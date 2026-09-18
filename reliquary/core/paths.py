"""Resolve application and resource directories for source and frozen (PyInstaller) runs."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

_DEFAULT_ALLOWLIST = """# IOC Extractor allowlist — one domain or IPv4 per line.
# Matched IOCs get tag "allowlisted" (can be hidden in GUI).
# Wildcards: *.corp.local  |  prefix*  |  *suffix
# Comments after entry: evil.example  # INC-12345
# Lines starting with # are ignored.

# company.local
# 10.0.0.1
"""

_DEFAULT_DENYLIST = """# IOC Extractor denylist — known-bad domains/IPs (optional).
# Matched IOCs get tag "denylisted".
# Wildcards and trailing comments (# ticket) supported.

# evil.example  # INC-0001
"""

_DEFAULT_VERDICT = """# IOC Extractor verdict thresholds (email triage only).
# Edit weights / thresholds for your SOC. Lines starting with # ignored.
# Format: key=integer

threshold_malicious=60
threshold_suspicious=30
threshold_unknown=10

weight_header_critical=35
weight_header_high=25
weight_header_medium=12
weight_header_low=4

weight_attachment_flag=20
weight_attachment_soft=8
weight_url_rewrite=5
weight_url_raw_ip=18
weight_suspicious_tld=10
weight_urgency=15
weight_links_and_attachments=10
"""


def app_dir() -> Path:
    """Directory next to the .exe (frozen) or project root (dev)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def resource_dir() -> Path:
    """Bundled read-only resources (_MEIPASS when frozen)."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    return Path(__file__).resolve().parents[2]


def config_path(name: str) -> Path:
    return app_dir() / name


def file_mtime_iso(path: Path) -> str:
    try:
        ts = path.stat().st_mtime
    except OSError:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def ensure_user_lists() -> Path:
    """Create allowlist.txt / denylist.txt / verdict.ini next to the app if missing.

    Prefers bundled copies from the PyInstaller archive; otherwise writes stubs.
    Returns the app directory.
    """
    root = app_dir()
    defaults = {
        "allowlist.txt": _DEFAULT_ALLOWLIST,
        "denylist.txt": _DEFAULT_DENYLIST,
        "verdict.ini": _DEFAULT_VERDICT,
    }
    for name, stub in defaults.items():
        dest = root / name
        if dest.is_file():
            continue
        bundled = resource_dir() / name
        try:
            if bundled.is_file() and bundled.resolve() != dest.resolve():
                dest.write_text(bundled.read_text(encoding="utf-8"), encoding="utf-8")
            else:
                dest.write_text(stub, encoding="utf-8")
        except OSError:
            pass
    return root
