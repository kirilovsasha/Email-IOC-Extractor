"""Resolve application and resource directories for source and frozen (PyInstaller) runs."""

from __future__ import annotations

import sys
from pathlib import Path

_DEFAULT_ALLOWLIST = """# IOC Extractor allowlist — one domain or IPv4 per line.
# Matched IOCs get tag "allowlisted" (can be hidden in GUI).
# Lines starting with # are ignored.

# company.local
# 10.0.0.1
"""

_DEFAULT_DENYLIST = """# IOC Extractor denylist — known-bad domains/IPs (optional).
# Matched IOCs get tag "denylisted".

# evil.example
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


def ensure_user_lists() -> Path:
    """Create allowlist.txt / denylist.txt next to the app if missing.

    Prefers bundled copies from the PyInstaller archive; otherwise writes stubs.
    Returns the app directory.
    """
    root = app_dir()
    defaults = {
        "allowlist.txt": _DEFAULT_ALLOWLIST,
        "denylist.txt": _DEFAULT_DENYLIST,
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
