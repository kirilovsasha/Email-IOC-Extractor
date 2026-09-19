"""Persist analyst UI preferences next to the exe."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reliquary.core.paths import app_dir

_PREFS_NAME = "ui_prefs.json"
_DEFAULTS: dict[str, Any] = {
    "last_dir": "",
    "last_export_dir": "",
    "copy_format": "type|value",
    "export_choice": "JSON",
    "ui_scale": 1.0,
    "window_geometry": "1320x820",
    "hide_rewriter": True,
    "hide_allowlisted": True,
    "hide_private": True,
    "actionable_only": True,
    "cat_network": True,
    "cat_hashes": True,
    "cat_host": True,
    "cat_crypto": False,  # email mode: hide crypto unless enabled / full_ioc_types
    "full_ioc_types": False,
    "folder_warn_threshold": 80,
    "max_workers": 0,  # 0 = auto (min(4, cpu))
    "skip_broken": True,
    "allowlist_path": "",  # empty = use allowlist_extra.txt next to app if present
    "verdict_path": "",  # empty = use verdict_extra.json next to app if present
    "handoff_template_path": "",  # empty = use handoff_extra.txt if present
    "brands_path": "",  # empty = use brands.txt next to app / profile if present
    "profile_dir": "",  # empty = use org_profile/ next to app if present
    "appearance_mode": "dark",  # dark|light
    "ioc_density": "normal",  # compact|normal|comfortable
}


def prefs_path() -> Path:
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
        for key, val in raw.items():
            if key not in data:
                data[key] = val
    return data


def save_prefs(updates: dict[str, Any]) -> bool:
    data = load_prefs()
    data.update(updates)
    path = prefs_path()
    try:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return True
    except OSError:
        return False
