"""Append runtime errors to the product log next to the exe/project."""

from __future__ import annotations

import traceback
from datetime import datetime, timezone
from pathlib import Path

from reliquary import __log_name__
from reliquary.core.paths import app_dir


def error_log_path() -> Path:
    return app_dir() / __log_name__


def append_error_log(message: str, *, exc: BaseException | None = None) -> Path | None:
    """Append a timestamped note (and optional traceback). Returns log path or None."""
    path = error_log_path()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    parts = [f"[{stamp}] {message.strip()}"]
    if exc is not None:
        parts.append("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    block = "\n".join(parts).rstrip() + "\n\n"
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(block)
        return path
    except OSError:
        return None
