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
    """Return ``lite`` / ``full`` / ``partial`` from installed optional deps (offline)."""
    rar_mod = False
    try:
        import rarfile  # noqa: F401

        rar_mod = True
    except ImportError:
        pass
    qr_ok = False
    try:
        from reliquary.core.qr_scan import qr_decoder_available

        qr_ok = qr_decoder_available()
    except (ImportError, AttributeError):
        qr_ok = False
    unrar_ok = False
    if rar_mod:
        try:
            from reliquary.core.self_check import _unrar_tool_available

            unrar_ok, _ = _unrar_tool_available()
        except (ImportError, AttributeError, TypeError):
            unrar_ok = False
    if rar_mod and qr_ok and unrar_ok:
        return "full"
    if not rar_mod and not qr_ok:
        return "lite"
    return "partial"


def check_update_manifest(path: str | Path | None = None) -> str | None:
    """Return a short RU status message if ``update.json`` exists next to the app.

    Manifest shape::
        {
          "latest": "2.14.1",
          "channel": "lite"|"full",
          "sha256": "optional hex of EmailIOCExtractor.exe",
          "notes": "optional"
        }

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
    channel = str(data.get("channel") or data.get("edition") or "").strip().lower()
    chan_ru = {"lite": "Lite", "full": "Full", "partial": "частичная"}.get(channel, channel)
    notes = str(data.get("notes") or "").strip()
    expected_sha = str(data.get("sha256") or data.get("sha256_lite") or "").strip().lower()

    lines: list[str] = []
    if _parse_ver(latest) > _parse_ver(__version__):
        msg = f"Доступно обновление: {__version__} → {latest}"
        if chan_ru:
            msg += f" ({chan_ru})"
        if notes:
            msg += f" — {notes[:80]}"
        lines.append(msg)
    else:
        msg = f"Актуально относительно манифеста {latest}"
        if chan_ru:
            msg += f" · канал {chan_ru}"
        lines.append(msg)

    if channel in {"lite", "full"}:
        runtime = detect_runtime_channel()
        if channel == "full" and runtime != "full":
            lines.append(
                f"⚠ Манифест Full, фактически {runtime} "
                "(нет rarfile/pyzbar/UnRAR — см. self-check)"
            )
        elif channel == "lite" and runtime == "full":
            lines.append("Манифест Lite, фактически Full-сборка (rar+QR+UnRAR)")
        elif channel == "lite" and runtime == "partial":
            lines.append("⚠ Манифест Lite, фактически частичная сборка")

    if expected_sha and len(expected_sha) == 64:
        root = app_dir()
        exe = root / "EmailIOCExtractor.exe"
        if not exe.is_file():
            exe = root / "EmailIOCExtractor-Full.exe"
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
