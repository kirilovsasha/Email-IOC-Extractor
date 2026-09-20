"""Visual theme for Email IOC Extractor — readable analyst layout."""

from __future__ import annotations

from typing import Any

from reliquary.core import filter_state as _filter_state

# Re-export for GUI consumers (single source of truth: filter_state.IOC_GROUPS).
IOC_GROUPS = _filter_state.IOC_GROUPS

COLORS_DARK = {
    "bg": "#0a0e12",
    "surface": "#121820",
    "surface_alt": "#1a222c",
    "border": "#2c3848",
    "text": "#e6edf3",
    "muted": "#8b9aab",
    "accent": "#3d9a8b",
    "accent_dim": "#2a6b60",
    "warn": "#d4a017",
    "danger": "#c94c4c",
    "ok": "#5a9e6f",
    "info": "#5b8fb9",
    "hash": "#9b7ed9",
    "host": "#e08a4c",
    "crypto": "#d4a017",
    "value": "#f0f4f8",
    "row_alt": "#151c24",
}

COLORS_LIGHT = {
    "bg": "#f4f6f8",
    "surface": "#ffffff",
    "surface_alt": "#e8eef3",
    "border": "#c5d0db",
    "text": "#1a2330",
    "muted": "#5a6a7a",
    "accent": "#2a7a6c",
    "accent_dim": "#1f5c52",
    "warn": "#b8860b",
    "danger": "#b33a3a",
    "ok": "#3d7a52",
    "info": "#3d6f94",
    "hash": "#6b4ea3",
    "host": "#c46a28",
    "crypto": "#b8860b",
    "value": "#0d1218",
    "row_alt": "#eef2f6",
}

# Active palette (mutated by apply_appearance)
COLORS = dict(COLORS_DARK)
_HIGH_CONTRAST = False

COLORS_HC_DARK = {
    **COLORS_DARK,
    "bg": "#000000",
    "surface": "#0a0a0a",
    "text": "#ffffff",
    "muted": "#c0c0c0",
    "accent": "#00e0c0",
    "border": "#ffffff",
}
COLORS_HC_LIGHT = {
    **COLORS_LIGHT,
    "bg": "#ffffff",
    "surface": "#ffffff",
    "text": "#000000",
    "muted": "#333333",
    "accent": "#005a4a",
    "border": "#000000",
}


def set_high_contrast(enabled: bool) -> None:
    global _HIGH_CONTRAST
    _HIGH_CONTRAST = bool(enabled)


def apply_appearance(mode: str = "dark") -> None:
    """Switch COLORS dict and CustomTkinter appearance mode."""
    light = str(mode).lower() == "light"
    if _HIGH_CONTRAST:
        palette = COLORS_HC_LIGHT if light else COLORS_HC_DARK
    else:
        palette = COLORS_LIGHT if light else COLORS_DARK
    COLORS.clear()
    COLORS.update(palette)
    try:
        import customtkinter as ctk

        ctk.set_appearance_mode("Light" if light else "Dark")
    except Exception:  # noqa: BLE001
        pass


# Typography (pt). Sized for 100% scale; Ctrl+/- still available.
FONT = {
    "tip": 10,
    "dense": 11,
    "caption": 12,
    "body": 13,
    "mono": 13,
    "table": 11,
    "label": 13,
    "panel": 14,
    "section": 15,
    "title": 16,
    "hero": 18,
}

FONT_UI = "Segoe UI"
FONT_MONO = "Consolas"

IOC_TYPE_COLORS = {
    "ipv4": "#6ea8d6",
    "ipv6": "#8ec0ea",
    "ip_port": "#4ec3d8",
    "domain": "#3d9a8b",
    "url": "#5ed0b8",
    "email": "#8fd4a8",
    "md5": "#9b7ed9",
    "sha1": "#b794f0",
    "sha256": "#d4b3ff",
    "cve": "#e05a5a",
    "filename": "#e08a4c",
    "filepath": "#e0b05c",
    "unc": "#d4925a",
    "registry": "#c9846a",
    "mutex": "#c4b07a",
    "bitcoin": "#f0c14e",
    "monero": "#f27a3d",
    "messenger": "#e6c15a",
    "command_line": "#c94c4c",
}

SEVERITY_COLORS = {
    "critical": COLORS["danger"],
    "high": COLORS["danger"],
    "medium": COLORS["warn"],
    "low": COLORS["info"],
    "info": COLORS["muted"],
}

SEVERITY_LABELS_RU = {
    "critical": "критично",
    "high": "высоко",
    "medium": "средне",
    "low": "низко",
    "info": "инфо",
}

VERDICT_COLORS = {
    "malicious": COLORS["danger"],
    "suspicious": COLORS["warn"],
    "unknown": COLORS["info"],
    "benign": COLORS["ok"],
}

BTN_H = 32
CHIP_H = 28
CHIP_H_COMPACT = 24

BTN_PRIMARY = dict(height=BTN_H, fg_color=COLORS["accent"], hover_color=COLORS["accent_dim"])
BTN_SECONDARY = dict(
    height=BTN_H,
    fg_color=COLORS["surface_alt"],
    hover_color=COLORS["border"],
    border_width=1,
    border_color=COLORS["border"],
)


def ioc_density_metrics(density: str = "normal") -> tuple[int, int]:
    """Return (font_pt, row_px) for IOC table density pref."""
    key = (density or "normal").lower()
    if key == "compact":
        return 10, 20
    if key == "comfortable":
        return 12, 28
    return 11, 24


def apply_global_fonts() -> None:
    """Use Segoe UI as CustomTkinter default instead of bundled Roboto."""
    try:
        import customtkinter as ctk

        theme = ctk.ThemeManager.theme
        font = dict(theme.get("CTkFont") or {})
        font["family"] = FONT_UI
        font["size"] = FONT["body"]
        theme["CTkFont"] = font
    except Exception:  # noqa: BLE001
        pass


def ctk_font(size_key: str = "body", *, weight: str = "normal") -> Any:
    import customtkinter as ctk

    return ctk.CTkFont(family=FONT_UI, size=FONT[size_key], weight=weight)


def ctk_mono(size_key: str = "mono") -> Any:
    import customtkinter as ctk

    return ctk.CTkFont(family=FONT_MONO, size=FONT[size_key])


def tk_ui(size_key: str = "body", *, bold: bool = False, scale: float = 1.0) -> tuple:
    size = max(10, int(round(FONT[size_key] * scale)))
    if bold:
        return (FONT_UI, size, "bold")
    return (FONT_UI, size)


def tk_mono(size_key: str = "mono", *, bold: bool = False, scale: float = 1.0) -> tuple:
    size = max(10, int(round(FONT[size_key] * scale)))
    if bold:
        return (FONT_MONO, size, "bold")
    return (FONT_MONO, size)
