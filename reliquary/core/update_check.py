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


def check_update_manifest(path: str | Path | None = None) -> str | None:
    """Return a short status message if ``update.json`` exists next to the app.

    Manifest shape::
        {"latest": "2.7.0", "notes": "optional"}

    Never contacts the network — an admin drops the file beside the EXE.
    """
    target = Path(path) if path else app_dir() / "update.json"
    if not target.is_file():
        return None
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "update.json: invalid"
    latest = str(data.get("latest") or data.get("version") or "").strip()
    if not latest:
        return None
    if _parse_ver(latest) > _parse_ver(__version__):
        notes = str(data.get("notes") or "").strip()
        msg = f"update available: {__version__} → {latest}"
        if notes:
            msg += f" ({notes[:80]})"
        return msg
    return f"up to date vs manifest {latest}"
