"""Defang / refang helpers for safe paste into tickets and parse-time normalize."""

from __future__ import annotations

import re

_URL_SCHEME = re.compile(r"(?i)\bhttps?://")

_REFANG_REPLACEMENTS = (
    ("hxxps[://]", "https://"),
    ("hxxp[://]", "http://"),
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("https[://]", "https://"),
    ("http[://]", "http://"),
    ("[://]", "://"),
    ("[:]", ":"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    ("{dot}", "."),
    ("[@]", "@"),
    ("[at]", "@"),
    ("(at)", "@"),
    ("{at}", "@"),
    ("hxxp[:]//", "http://"),
    ("hxxps[:]//", "https://"),
    ("\\.", "."),
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


def refang(text: str) -> str:
    """Normalize common SOC defanging so extractors still match."""
    out = text
    for old, new in _REFANG_REPLACEMENTS:
        out = out.replace(old, new)
        out = out.replace(old.upper(), new)
        if old.lower() != old:
            continue
        out = re.sub(re.escape(old), new, out, flags=re.IGNORECASE)
    out = re.sub(
        r"(?i)\b([a-z0-9\-]+)\s+dot\s+([a-z0-9\-]+)\s+dot\s+([a-z]{2,24})\b",
        r"\1.\2.\3",
        out,
    )
    out = re.sub(
        r"(?i)\b([a-z0-9\-]+)\s+dot\s+([a-z]{2,24})\b",
        r"\1.\2",
        out,
    )
    return out


# Back-compat alias used historically in ioc_extractor
defang = refang
