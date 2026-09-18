"""Persist analyst UI preferences next to the exe."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reliquary.core.paths import app_dir, ensure_user_lists

_PREFS_NAME = "ui_prefs.json"
_DEFAULTS: dict[str, Any] = {
    "last_dir": "",
    "copy_format": "type|value",
    "export_choice": "CSV",
    "ticket_short": False,
    "ui_scale": 1.0,
    "hide_rewriter": True,
    "hide_allowlisted": True,
    "hide_private": False,
    "only_denylisted": False,
    "actionable_only": False,
}


def prefs_path() -> Path:
    ensure_user_lists()
    return app_dir() / _PREFS_NAME


def load_prefs() -> dict[str, Any]:
    path = prefs_path()
    data = dict(_DEFAULTS)
    if not path.is_file():
        return data
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return data
    if isinstance(raw, dict):
        for key, default in _DEFAULTS.items():
            if key in raw:
                data[key] = raw[key]
            elif key not in data:
                data[key] = default
    return data


def save_prefs(updates: dict[str, Any]) -> None:
    data = load_prefs()
    data.update(updates)
    path = prefs_path()
    try:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass
