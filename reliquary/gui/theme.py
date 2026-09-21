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
    "seg_selected": "#3d9a8b",
    "on_accent": "#ffffff",
    "warn": "#d4a017",
    "danger": "#c94c4c",
    "danger_hover": "#a33c3c",
    "ok": "#5a9e6f",
    "info": "#5b8fb9",
    "hash": "#9b7ed9",
    "host": "#e08a4c",
    "crypto": "#d4a017",
    "value": "#f0f4f8",
    "row_alt": "#151c24",
}

COLORS_LIGHT = {
    "bg": "#eef1f4",
    "surface": "#ffffff",
    "surface_alt": "#e2e8ee",
    "border": "#b0bec9",
    "text": "#121a24",
    "muted": "#3d4f5f",
    "accent": "#1f6b5e",
    "accent_dim": "#174f46",
    # Pale teal so shared segmented text_color stays dark and readable
    "seg_selected": "#c5e4dc",
    "on_accent": "#ffffff",
    "warn": "#9a6b00",
    "danger": "#a83232",
    "danger_hover": "#8a2828",
    "ok": "#2f6b45",
    "info": "#2f5f84",
    "hash": "#5a3f96",
    "host": "#a85a20",
    "crypto": "#9a6b00",
    "value": "#0a0e14",
    "row_alt": "#e8eef3",
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
    "accent_dim": "#00a090",
    "seg_selected": "#00e0c0",
    "on_accent": "#000000",
    "border": "#ffffff",
}
COLORS_HC_LIGHT = {
    **COLORS_LIGHT,
    "bg": "#ffffff",
    "surface": "#ffffff",
    "text": "#000000",
    "muted": "#222222",
    "accent": "#005a4a",
    "accent_dim": "#003d34",
    "seg_selected": "#a8d5cc",
    "on_accent": "#ffffff",
    "border": "#000000",
}


def set_high_contrast(enabled: bool) -> None:
    global _HIGH_CONTRAST
    _HIGH_CONTRAST = bool(enabled)


def _sync_derived_palettes() -> None:
    """Keep severity/verdict/button dicts in sync with active COLORS."""
    SEVERITY_COLORS.update(
        {
            "critical": COLORS["danger"],
            "high": COLORS["danger"],
            "medium": COLORS["warn"],
            "low": COLORS["info"],
            "info": COLORS["muted"],
        }
    )
    VERDICT_COLORS.update(
        {
            "malicious": COLORS["danger"],
            "suspicious": COLORS["warn"],
            "unknown": COLORS["info"],
            "benign": COLORS["ok"],
        }
    )
    BTN_PRIMARY["fg_color"] = COLORS["accent"]
    BTN_PRIMARY["hover_color"] = COLORS["accent_dim"]
    BTN_PRIMARY["text_color"] = COLORS["on_accent"]
    BTN_SECONDARY["fg_color"] = COLORS["surface_alt"]
    BTN_SECONDARY["hover_color"] = COLORS["border"]
    BTN_SECONDARY["border_color"] = COLORS["border"]
    BTN_SECONDARY["text_color"] = COLORS["text"]


def palette_remap(old: dict[str, str], new: dict[str, str]) -> dict[str, str]:
    """Map old hex → new hex for live widget restyle (keys lowercased)."""
    remap: dict[str, str] = {}
    for key, old_hex in old.items():
        new_hex = new.get(key)
        if not new_hex or old_hex == new_hex:
            continue
        remap[str(old_hex).strip().lower()] = new_hex
    # CustomTkinter defaults (not in our palette) → readable body text
    for default in ("#dce4ee", "#dce4ee"):
        remap[default] = new.get("text", "#121a24")
    return remap


_CTK_COLOR_ATTRS = (
    "fg_color",
    "bg_color",
    "text_color",
    "border_color",
    "hover_color",
    "button_color",
    "button_hover_color",
    "dropdown_fg_color",
    "dropdown_hover_color",
    "dropdown_text_color",
    "progress_color",
    "checkmark_color",
    "text_color_disabled",
    "placeholder_text_color",
    "selected_color",
    "selected_hover_color",
    "unselected_color",
    "unselected_hover_color",
)


def _flat_hex(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    return str(value or "").strip().lower()


def _relative_luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    if len(h) != 6:
        return 0.5
    try:
        r, g, b = (int(h[i : i + 2], 16) / 255.0 for i in (0, 2, 4))
    except ValueError:
        return 0.5
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _filled_fg_hexes() -> set[str]:
    """Backgrounds that need on_accent (light) label text."""
    keys = ("accent", "accent_dim", "danger", "danger_hover", "ok", "warn", "info")
    return {_flat_hex(COLORS[k]) for k in keys if k in COLORS}


def _remap_color_value(value: Any, remap: dict[str, str]) -> Any | None:
    """Return remapped color (str/tuple) or None if unchanged / not applicable."""
    if value is None or value == "transparent":
        return None
    if isinstance(value, (list, tuple)):
        mapped = []
        changed = False
        for item in value:
            nxt = _remap_color_value(item, remap)
            if nxt is None:
                mapped.append(item)
            else:
                mapped.append(nxt)
                changed = True
        return type(value)(mapped) if changed else None
    if isinstance(value, str):
        return remap.get(value.strip().lower())
    return None


def fix_control_contrast(widget: Any) -> None:
    """Force readable text on buttons/menus after palette or CTK defaults drift."""
    name = type(widget).__name__
    try:
        if name == "CTkButton":
            fg = _flat_hex(widget.cget("fg_color"))
            if fg in _filled_fg_hexes() or (fg.startswith("#") and _relative_luminance(fg) < 0.42):
                widget.configure(text_color=COLORS["on_accent"])
            else:
                widget.configure(text_color=COLORS["text"])
        elif name == "CTkSegmentedButton":
            widget.configure(
                fg_color=COLORS["surface_alt"],
                selected_color=COLORS["seg_selected"],
                selected_hover_color=COLORS["accent"]
                if _relative_luminance(COLORS["seg_selected"]) > 0.55
                else COLORS["accent_dim"],
                unselected_color=COLORS["surface_alt"],
                unselected_hover_color=COLORS["border"],
                text_color=COLORS["text"],
            )
        elif name == "CTkOptionMenu":
            widget.configure(
                fg_color=COLORS["surface"],
                button_color=COLORS["surface_alt"],
                button_hover_color=COLORS["accent_dim"],
                dropdown_fg_color=COLORS["surface"],
                text_color=COLORS["text"],
                dropdown_text_color=COLORS["text"],
            )
        elif name in ("CTkLabel", "CTkCheckBox", "CTkRadioButton", "CTkSwitch"):
            if _flat_hex(widget.cget("text_color")) == "#dce4ee":
                widget.configure(text_color=COLORS["text"])
        elif name in ("CTkEntry", "CTkTextbox"):
            widget.configure(text_color=COLORS["text"])
            try:
                widget.configure(fg_color=COLORS["surface_alt"])
            except Exception:  # noqa: BLE001
                pass
            try:
                widget.configure(border_color=COLORS["border"])
            except Exception:  # noqa: BLE001
                pass
            try:
                widget.configure(placeholder_text_color=COLORS["muted"])
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        pass
    try:
        children = widget.winfo_children()
    except Exception:  # noqa: BLE001
        return
    for child in children:
        fix_control_contrast(child)


def restyle_widget_tree(widget: Any, remap: dict[str, str]) -> None:
    """Recursively recolor CustomTkinter widgets, then fix control contrast."""

    def _remap_tree(node: Any) -> None:
        if not remap:
            return
        for attr in _CTK_COLOR_ATTRS:
            try:
                current = node.cget(attr)
            except Exception:  # noqa: BLE001
                continue
            mapped = _remap_color_value(current, remap)
            if mapped is None:
                continue
            try:
                node.configure(**{attr: mapped})
            except Exception:  # noqa: BLE001
                pass
        try:
            kids = node.winfo_children()
        except Exception:  # noqa: BLE001
            return
        for child in kids:
            _remap_tree(child)

    _remap_tree(widget)
    fix_control_contrast(widget)


def apply_appearance(mode: str = "dark") -> dict[str, str]:
    """Switch COLORS + CTK appearance. Returns old→new hex remap for live restyle."""
    mode_l = str(mode).lower()
    light = mode_l == "light"
    if _HIGH_CONTRAST:
        palette = COLORS_HC_LIGHT if light else COLORS_HC_DARK
    else:
        palette = COLORS_LIGHT if light else COLORS_DARK
    old = dict(COLORS)
    COLORS.clear()
    COLORS.update(palette)
    _sync_derived_palettes()
    try:
        import customtkinter as ctk

        if mode_l == "system":
            ctk.set_appearance_mode("System")
        else:
            ctk.set_appearance_mode("Light" if light else "Dark")
    except Exception:  # noqa: BLE001
        pass
    return palette_remap(old, COLORS)


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
    "hero": 22,
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

BTN_PRIMARY = dict(
    height=BTN_H,
    fg_color=COLORS["accent"],
    hover_color=COLORS["accent_dim"],
    text_color=COLORS["on_accent"],
)
BTN_SECONDARY = dict(
    height=BTN_H,
    fg_color=COLORS["surface_alt"],
    hover_color=COLORS["border"],
    border_width=1,
    border_color=COLORS["border"],
    text_color=COLORS["text"],
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
