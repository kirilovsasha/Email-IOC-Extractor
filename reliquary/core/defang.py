"""Defang / refang helpers for safe paste into tickets."""

from __future__ import annotations

import re

_URL_SCHEME = re.compile(r"(?i)\bhttps?://")
_DOT_IN_HOST = re.compile(
    r"(?i)(?<=://)([^/\s<>\"']+)|(?<=@)([a-z0-9.\-]+\.[a-z]{2,})"
)


def defang_value(value: str) -> str:
    """Make indicators safer to paste (hxxp, [.] )."""
    out = _URL_SCHEME.sub(lambda m: m.group(0).replace("http", "hxxp", 1), value)
    # Dot-defang host-looking segments and bare domains/IPs
    out = out.replace(".", "[.]")
    # Undo accidental defang inside already-bracketed sequences
    out = out.replace("[[.]]", "[.]")
    return out


def defang_ioc_line(ioc_type: str, value: str, *, with_type: bool = True) -> str:
    fang = defang_value(value)
    if with_type:
        return f"{ioc_type}|{fang}"
    return fang
