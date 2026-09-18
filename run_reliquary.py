#!/usr/bin/env python3
"""Entry point for IOC Extractor GUI and PyInstaller."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path


def _log_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "ioc_extractor_error.log"
    return Path(__file__).resolve().parent / "ioc_extractor_error.log"


def _show_fatal(message: str) -> None:
    """Show a message box when possible (frozen GUI has no console)."""
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("IOC Extractor", message)
        root.destroy()
    except Exception:
        try:
            sys.stderr.write(message + "\n")
        except Exception:
            pass


def main() -> None:
    try:
        from reliquary.core.paths import ensure_user_lists
        from reliquary.gui.app import run

        ensure_user_lists()
        run()
    except Exception:
        tb = traceback.format_exc()
        log = _log_path()
        try:
            log.write_text(tb, encoding="utf-8")
        except OSError:
            pass
        _show_fatal(
            "Не удалось запустить IOC Extractor.\n\n"
            f"Подробности: {log}\n\n"
            f"{tb[-1500:]}"
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
