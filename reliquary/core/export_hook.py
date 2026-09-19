"""Optional local post-export hook (offline subprocess)."""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from reliquary.core.error_log import append_error_log


def run_post_export_hook(
    hook: str | Path | list[str] | None,
    export_path: str | Path,
    *,
    timeout: float = 30.0,
) -> str | None:
    """Run ``hook`` with the exported file path as the last argument.

    ``hook`` may be an executable path, a shell-like command string, or an argv list.
    Returns a short status message, or ``None`` if hook is empty.
    Failures are logged and returned as a warning string (never raised).
    """
    if hook is None:
        return None
    if isinstance(hook, list):
        parts = [str(p) for p in hook if str(p).strip()]
    else:
        raw = str(hook).strip()
        if not raw:
            return None
        try:
            parts = shlex.split(raw, posix=False)
        except ValueError:
            parts = [raw]
    if not parts:
        return None
    out = Path(export_path)
    cmd = parts + [str(out)]
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except OSError as exc:
        append_error_log("post_export_hook failed", exc=exc)
        return f"hook error: {exc}"
    except subprocess.TimeoutExpired:
        append_error_log("post_export_hook timeout")
        return "hook timeout"
    if completed.returncode != 0:
        err = (completed.stderr or completed.stdout or "").strip()[:200]
        append_error_log(f"post_export_hook exit={completed.returncode} {err}")
        return f"hook exit {completed.returncode}"
    return f"hook ok → {out.name}"
