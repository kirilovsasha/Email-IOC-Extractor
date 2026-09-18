"""Visual theme for IOC Extractor GUI."""

COLORS = {
    "bg": "#0f1419",
    "surface": "#1a222c",
    "surface_alt": "#232d3a",
    "border": "#2e3a4a",
    "text": "#e7ecf1",
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
}

# Colors for IOC type badges in result panes.
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
