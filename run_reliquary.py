#!/usr/bin/env python3
"""Entry point for Reliquary GUI and PyInstaller."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path


def _log_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "reliquary_error.log"
    return Path(__file__).resolve().parent / "reliquary_error.log"


def main() -> None:
    try:
        from reliquary.gui.app import run

        run()
    except Exception:
        log = _log_path()
        try:
            log.write_text(traceback.format_exc(), encoding="utf-8")
        except OSError:
            pass
        raise


if __name__ == "__main__":
    main()
