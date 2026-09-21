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
    "last_inbox_dir": "",  # last folder used for inbox calibration
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
    "high_contrast": False,
    # Компактный режим: скрыть левую панель исходника, фокус на вердикте
    "verdict_compact": False,
    # Local command/script run after successful export; receives export path as argv
    "post_export_hook": "",
    # If true, allow hook executables outside the app directory (still blocked patterns apply)
    "post_export_hook_allow_external": False,
    # Corporate lock: ignore prefs/CLI hook entirely
    "disable_post_export_hook": False,
    # Pass schema_version:2 JSON sidecar as 2nd argv to the hook
    "post_export_hook_json_sidecar": True,
    # Batch tree: last sort column / reverse
    "batch_sort_column": "score",
    "batch_sort_reverse": True,
}

_APPEARANCE_OK = frozenset({"dark", "light", "system"})
_DENSITY_OK = frozenset({"compact", "normal", "comfortable"})
_COPY_OK = frozenset({"type|value", "value", "csv", "defanged", "defanged|type"})
_EXPORT_OK = frozenset(
    {
        "JSON",
        "CSV",
        "Batch CSV",
        "Тикет",
        "Handoff",  # legacy prefs
        "Кампания",
        "ECS",
        "CEF",
        "STIX",
        "MISP",
        "OpenCTI",
        "Campaign pack",
    }
)

def prefs_path() -> Path:
    return app_dir() / _PREFS_NAME


def _coerce_value(key: str, value: Any, default: Any) -> Any:
    """Coerce a prefs value toward the type of ``default``; fall back on failure."""
    if key == "appearance_mode":
        s = str(value or default).strip().lower()
        return s if s in _APPEARANCE_OK else default
    if key == "ioc_density":
        s = str(value or default).strip().lower()
        return s if s in _DENSITY_OK else default
    if key == "copy_format":
        s = str(value or default).strip()
        return s if s in _COPY_OK else default
    if key == "export_choice":
        s = str(value or default).strip()
        if s == "Handoff":
            s = "Тикет"
        return s if s in _EXPORT_OK else default
    if key == "ui_scale":
        try:
            scale = float(value)
        except (TypeError, ValueError):
            return default
        return max(0.75, min(2.0, scale))
    if key in ("folder_warn_threshold", "max_workers"):
        try:
            n = int(value)
        except (TypeError, ValueError):
            return default
        return max(0, n)
    if isinstance(default, bool):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)) and value in (0, 1):
            return bool(value)
        if isinstance(value, str):
            low = value.strip().lower()
            if low in ("1", "true", "yes", "on"):
                return True
            if low in ("0", "false", "no", "off", ""):
                return False
        return default
    if isinstance(default, str):
        return "" if value is None else str(value)
    if isinstance(default, int) and not isinstance(default, bool):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
    if isinstance(default, float):
        try:
            return float(value)
        except (TypeError, ValueError):
            return default
    return value


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
                data[key] = _coerce_value(key, raw[key], default)
        for key, val in raw.items():
            if key not in data:
                data[key] = val
    return data


def save_prefs(updates: dict[str, Any]) -> bool:
    data = load_prefs()
    for key, val in updates.items():
        if key in _DEFAULTS:
            data[key] = _coerce_value(key, val, _DEFAULTS[key])
        else:
            data[key] = val
    path = prefs_path()
    try:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return True
    except OSError:
        return False
