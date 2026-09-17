"""Visual theme for Reliquary — SOC console, not a generic dashboard."""

COLORS = {
    "bg": "#0f1419",
    "surface": "#1a222c",
    "surface_alt": "#232d3a",
    "border": "#2e3a4a",
    "text": "#e7ecf1",
    "muted": "#8b9aab",
    "accent": "#3d9a8b",  # teal
    "accent_dim": "#2a6b60",
    "warn": "#d4a017",
    "danger": "#c94c4c",
    "ok": "#5a9e6f",
    "info": "#5b8fb9",
}

VERDICT_COLORS = {
    "benign": COLORS["ok"],
    "suspicious": COLORS["warn"],
    "malicious": COLORS["danger"],
    "unknown": COLORS["info"],
}

VERDICT_LABELS_RU = {
    "benign": "БЕЗОПАСНО",
    "suspicious": "ПОДОЗРИТЕЛЬНО",
    "malicious": "ВРЕДОНОСНО",
    "unknown": "НЕОДНОЗНАЧНО",
}
