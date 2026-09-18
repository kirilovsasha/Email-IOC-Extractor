"""Visual theme for IOC Extractor GUI — dense SOC-analyst layout.

Typography hierarchy (pt):
  content / IOC  — largest (primary work surface)
  UI chrome      — smaller (header, toolbar, filters)
  meta / status  — smallest
"""

from __future__ import annotations

import customtkinter as ctk

COLORS = {
    "bg": "#0c1014",
    "surface": "#151b22",
    "surface_alt": "#1c2430",
    "border": "#2a3544",
    "text": "#e8eef4",
    "muted": "#8494a7",
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
}

# —— Font scale (keep chrome quieter than IOC content) ——
FONT_UI = "Segoe UI"
FONT_MONO = "Consolas"

# Content (IOC table / result panes) — primary reading surface
FONT_IOC = 14
FONT_IOC_ROW_H = 28
FONT_CONTENT = 13
FONT_SECTION = 13

# Chrome (header / toolbar / filters) — secondary
FONT_BRAND = 15
FONT_UI_LABEL = 11
FONT_UI_BODY = 12
FONT_META = 10
FONT_STATUS = 10
FONT_TIP = 9

# Summary badge — between chrome and content
FONT_SUMMARY = 16
FONT_BADGE = 12

IOC_TYPE_COLORS = {
    "ipv4": COLORS["info"],
    "ipv6": COLORS["info"],
    "ip_port": COLORS["info"],
    "domain": COLORS["accent"],
    "url": COLORS["accent"],
    "email": COLORS["accent"],
    "md5": COLORS["hash"],
    "sha1": COLORS["hash"],
    "sha256": COLORS["hash"],
    "cve": COLORS["danger"],
    "filename": COLORS["host"],
    "filepath": COLORS["host"],
    "unc": COLORS["host"],
    "registry": COLORS["host"],
    "mutex": COLORS["host"],
    "bitcoin": COLORS["crypto"],
    "monero": COLORS["crypto"],
    "messenger": COLORS["warn"],
    "command_line": COLORS["danger"],
}

IOC_GROUPS = (
    ("Сеть", ("ipv4", "ipv6", "ip_port", "domain", "url", "email", "messenger")),
    ("Хеши и CVE", ("md5", "sha1", "sha256", "cve")),
    ("Хост", ("filename", "filepath", "unc", "registry", "mutex", "command_line")),
    ("Крипто", ("bitcoin", "monero")),
)

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

# Compact chrome buttons (shorter than content row height)
BTN_H = 28


def ui_font(*, size: int = FONT_UI_BODY, weight: str = "normal") -> ctk.CTkFont:
    return ctk.CTkFont(family=FONT_UI, size=size, weight=weight)


def chrome_font() -> ctk.CTkFont:
    """Toolbar / filter control text — quieter than IOC content."""
    return ui_font(size=FONT_UI_LABEL)


def btn_primary(**extra: object) -> dict:
    """Primary action button kwargs (create after CTk root exists)."""
    return {
        "height": BTN_H,
        "font": chrome_font(),
        "fg_color": COLORS["accent"],
        "hover_color": COLORS["accent_dim"],
        **extra,
    }


def btn_secondary(**extra: object) -> dict:
    """Secondary chrome button kwargs (create after CTk root exists)."""
    return {
        "height": BTN_H,
        "font": chrome_font(),
        "fg_color": COLORS["surface_alt"],
        "hover_color": COLORS["border"],
        "border_width": 1,
        "border_color": COLORS["border"],
        **extra,
    }
