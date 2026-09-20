"""Append runtime errors to the product log next to the exe/project."""

from __future__ import annotations

import traceback
from datetime import datetime, timezone
from pathlib import Path

from reliquary import __log_name__
from reliquary.core.paths import app_dir

# Soft rotate when the log grows past this size (keep a single .1 backup).
_MAX_LOG_BYTES = 2_000_000


def error_log_path() -> Path:
    return app_dir() / __log_name__


def _maybe_rotate(path: Path) -> None:
    try:
        if not path.is_file() or path.stat().st_size < _MAX_LOG_BYTES:
            return
        bak = path.with_suffix(path.suffix + ".1")
        if bak.exists():
            bak.unlink()
        path.replace(bak)
    except OSError:
        pass


def append_error_log(message: str, *, exc: BaseException | None = None) -> Path | None:
    """Append a timestamped note (and optional traceback). Returns log path or None."""
    path = error_log_path()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    parts = [f"[{stamp}] {message.strip()}"]
    if exc is not None:
        parts.append("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    block = "\n".join(parts).rstrip() + "\n\n"
    try:
        _maybe_rotate(path)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(block)
        return path
    except OSError:
        return None
