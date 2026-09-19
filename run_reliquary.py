#!/usr/bin/env python3
"""Entry point for Email IOC Extractor GUI and PyInstaller."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path


def _log_path() -> Path:
    name = "email_ioc_extractor_error.log"
    try:
        from reliquary import __log_name__

        name = __log_name__
    except Exception:
        pass
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / name
    return Path(__file__).resolve().parent / name


def _show_fatal(message: str) -> None:
    """Show a message box when possible (frozen GUI has no console)."""
    try:
        import tkinter as tk
        from tkinter import messagebox

        name = "Email IOC Extractor"
        try:
            from reliquary import __app_name__

            name = __app_name__
        except Exception:
            pass

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(name, message)
        root.destroy()
    except Exception:
        try:
            sys.stderr.write(message + "\n")
        except Exception:
            pass


def main() -> None:
    try:
        from reliquary.gui.app import run

        run()
    except Exception:
        tb = traceback.format_exc()
        log = _log_path()
        try:
            log.write_text(tb, encoding="utf-8")
        except OSError:
            pass
        name = "Email IOC Extractor"
        try:
            from reliquary import __app_name__

            name = __app_name__
        except Exception:
            pass
        _show_fatal(
            f"Не удалось запустить {name}.\n\n"
            f"Подробности: {log}\n\n"
            f"{tb[-1500:]}"
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
