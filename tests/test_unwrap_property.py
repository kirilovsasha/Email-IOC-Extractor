"""Property-ish unwrap fuzz (no hypothesis dependency)."""

from __future__ import annotations

import pytest

from reliquary.core.url_rewrite import unwrap_url

_TARGETS = [
    "https://evil.example.com/a",
    "https://phish.top/login",
    "http://203.0.113.50/x",
]


def _wrap_safelinks(inner: str) -> str:
    from urllib.parse import quote

    return (
        "https://nam.safelinks.protection.outlook.com/?url="
        + quote(inner, safe="")
        + "&data=01"
    )


def _wrap_proxysg(inner: str) -> str:
    return f"http://sg.company.local:8080/*,1,/{inner}"


@pytest.mark.parametrize("target", _TARGETS)
@pytest.mark.parametrize("depth", [1, 2])
def test_unwrap_nested_property(target: str, depth: int) -> None:
    url = target
    if depth >= 1:
        url = _wrap_proxysg(url)
    if depth >= 2:
        url = _wrap_safelinks(url)
    result = unwrap_url(url)
    assert result.changed
    assert target.split("/")[2] in result.unwrapped or target in result.unwrapped
    assert len(result.chain) >= depth
