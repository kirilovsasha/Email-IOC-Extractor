"""Local offline update manifest check (no network)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from reliquary import __version__
from reliquary.core.paths import app_dir


def _parse_ver(text: str) -> tuple[int, ...]:
    parts = [int(p) for p in re.split(r"[^\d]+", text) if p.isdigit()]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:4])


def detect_runtime_channel() -> str:
    """Return ``standard`` (QR available) or ``no_qr`` (offline capability probe)."""
    try:
        from reliquary.core.qr_scan import qr_decoder_available

        if qr_decoder_available():
            return "standard"
    except (ImportError, AttributeError):
        pass
    return "no_qr"


def check_update_manifest(path: str | Path | None = None) -> str | None:
    """Return a short RU status message if ``update.json`` exists next to the app.

    Manifest shape::
        {
          "latest": "2.16.0",
          "sha256": "optional hex of EmailIOCExtractor.exe",
          "notes": "optional"
        }

    Legacy ``channel`` keys (lite/full) are ignored.
    Never contacts the network — an admin drops the file beside the EXE.
    """
    target = Path(path) if path else app_dir() / "update.json"
    if not target.is_file():
        return None
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "update.json: повреждён / неверный JSON"
    latest = str(data.get("latest") or data.get("version") or "").strip()
    if not latest:
        return None
    notes = str(data.get("notes") or "").strip()
    expected_sha = str(data.get("sha256") or data.get("sha256_lite") or "").strip().lower()

    lines: list[str] = []
    if _parse_ver(latest) > _parse_ver(__version__):
        msg = f"Доступно обновление: {__version__} → {latest}"
        if notes:
            msg += f" — {notes[:80]}"
        lines.append(msg)
    else:
        lines.append(f"Актуально относительно манифеста {latest}")

    if expected_sha and len(expected_sha) == 64:
        root = app_dir()
        exe = root / "EmailIOCExtractor.exe"
        if exe.is_file():
            import hashlib

            h = hashlib.sha256()
            try:
                with exe.open("rb") as fh:
                    for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                        h.update(chunk)
                digest = h.hexdigest()
                if digest == expected_sha:
                    lines.append("SHA256 манифеста совпадает с EXE")
                else:
                    lines.append("⚠ SHA256 манифеста НЕ совпадает с EXE")
            except OSError as exc:
                lines.append(f"⚠ SHA256 манифеста: ошибка чтения EXE ({exc})")
        else:
            lines.append("SHA256 в манифесте задан (EXE рядом не найден для сверки)")

    return " · ".join(lines)
