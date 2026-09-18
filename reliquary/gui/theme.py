"""Visual theme for IOC Extractor GUI — dense SOC-analyst layout."""

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

# Shared button sizes for denser chrome
BTN_H = 32
BTN_PRIMARY = dict(height=BTN_H, fg_color=COLORS["accent"], hover_color=COLORS["accent_dim"])
BTN_SECONDARY = dict(
    height=BTN_H,
    fg_color=COLORS["surface_alt"],
    hover_color=COLORS["border"],
    border_width=1,
    border_color=COLORS["border"],
)
