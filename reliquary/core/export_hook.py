"""Optional local post-export hook (offline subprocess)."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

from reliquary.core.error_log import append_error_log
from reliquary.core.paths import app_dir

# Tokens that strongly suggest downloaders / remote execution (process-local offline
# cannot block native child network I/O — refuse these hooks instead).
_BLOCKED_PATTERN = re.compile(
    r"(?i)\b("
    r"curl|wget|bitsadmin|certutil|Invoke-WebRequest|Invoke-RestMethod|"
    r"iwr\b|irm\b|Start-BitsTransfer|ftp\.exe|"
    r"powershell|pwsh|cmd\.exe|cmd\s+/c|msiexec|"
    r"https?://|ftp://"
    r")\b"
)
_INTERPRETER_NAMES = frozenset(
    {"python", "python.exe", "pythonw.exe", "python3", "python3.exe", "py", "py.exe"}
)


def _env_hooks_disabled() -> bool:
    return os.environ.get("RELIQUARY_DISABLE_EXPORT_HOOK", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _under_app(path: Path) -> bool:
    try:
        path.expanduser().resolve().relative_to(app_dir().resolve())
        return True
    except (ValueError, OSError):
        return False


def _parse_hook_parts(hook: str | Path | list[str] | None) -> list[str]:
    if hook is None:
        return []
    if isinstance(hook, list):
        return [str(p) for p in hook if str(p).strip()]
    raw = str(hook).strip()
    if not raw:
        return []
    try:
        return shlex.split(raw, posix=False)
    except ValueError:
        return [raw]


def validate_post_export_hook(
    hook: str | Path | list[str] | None,
    *,
    allow_external: bool = False,
) -> str | None:
    """Return an error message if the hook must not run, else ``None``."""
    parts = _parse_hook_parts(hook)
    if not parts:
        return "empty hook"
    joined = " ".join(parts)
    if _BLOCKED_PATTERN.search(joined):
        return "hook blocked: looks like a downloader/shell remote helper"
    if allow_external:
        return None
    first = Path(parts[0])
    local = app_dir() / parts[0]
    if _under_app(first) or local.is_file():
        return None
    # python + script.py where script lives next to the app
    name = first.name.lower()
    if name in _INTERPRETER_NAMES or name.startswith("python"):
        if len(parts) >= 2 and (_under_app(Path(parts[1])) or (app_dir() / parts[1]).is_file()):
            return None
    return (
        "hook blocked: executable outside app dir "
        "(set post_export_hook_allow_external or place script next to the exe)"
    )


def run_post_export_hook(
    hook: str | Path | list[str] | None,
    export_path: str | Path,
    *,
    timeout: float = 30.0,
    allow_external: bool | None = None,
    disabled: bool | None = None,
) -> str | None:
    """Run ``hook`` with the exported file path as the last argument.

    ``hook`` may be an executable path, a shell-like command string, or an argv list.
    Returns a short status message, or ``None`` if hook is empty.
    Failures are logged and returned as a warning string (never raised).
    """
    if disabled is None:
        disabled = _env_hooks_disabled()
    if disabled:
        return "hook disabled"

    parts = _parse_hook_parts(hook)
    if not parts:
        return None

    if allow_external is None:
        try:
            from reliquary.core.prefs import load_prefs

            prefs = load_prefs()
            if bool(prefs.get("disable_post_export_hook")):
                return "hook disabled"
            allow_external = bool(prefs.get("post_export_hook_allow_external"))
        except Exception:  # noqa: BLE001
            allow_external = False

    err = validate_post_export_hook(parts, allow_external=bool(allow_external))
    if err:
        append_error_log(f"post_export_hook refused: {err}")
        return err

    # Prefer app-local relative scripts
    if not Path(parts[0]).is_absolute() and not Path(parts[0]).exists():
        local = app_dir() / parts[0]
        if local.is_file():
            parts = [str(local)] + parts[1:]
    elif (
        len(parts) >= 2
        and not Path(parts[1]).is_absolute()
        and not Path(parts[1]).exists()
    ):
        local_script = app_dir() / parts[1]
        if local_script.is_file():
            parts = [parts[0], str(local_script)] + parts[2:]

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
        err_out = (completed.stderr or completed.stdout or "").strip()[:200]
        append_error_log(f"post_export_hook exit={completed.returncode} {err_out}")
        return f"hook exit {completed.returncode}"
    return f"hook ok → {out.name}"
