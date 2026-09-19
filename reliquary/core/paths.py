"""Resolve application directories for source and frozen (PyInstaller) runs."""

from __future__ import annotations

import sys
from pathlib import Path


def app_dir() -> Path:
    """Directory next to the .exe (frozen) or project root (dev)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]
