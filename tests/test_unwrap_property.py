"""Property-ish unwrap fuzz (no hypothesis dependency)."""

from __future__ import annotations

from urllib.parse import quote

import pytest

from reliquary.core.url_rewrite import unwrap_url

_TARGETS = [
    "https://evil.example.com/a",
    "https://phish.top/login",
    "http://203.0.113.50/x",
    "https://login.bank-secure.example/path?q=1",
]


def _wrap_safelinks(inner: str, *, host: str = "nam.safelinks.protection.outlook.com") -> str:
    return f"https://{host}/?url=" + quote(inner, safe="") + "&data=01"


def _wrap_proxysg(inner: str) -> str:
    return f"http://sg.company.local:8080/*,1,/{inner}"


def _wrap_mailru(inner: str) -> str:
    return "https://click.mail.ru/redir?url=" + quote(inner, safe="")


def _wrap_yandex(inner: str) -> str:
    return "https://away.yandex.ru/redirect?url=" + quote(inner, safe="")


def _wrap_vk(inner: str) -> str:
    return "https://vk.com/away.php?to=" + quote(inner, safe="")


def _wrap_bitrix(inner: str) -> str:
    return "https://company.bitrix24.ru/bitrix/redirect.php?url=" + quote(inner, safe="")


def _wrap_amocrm(inner: str) -> str:
    return "https://www.amocrm.ru/redirect?url=" + quote(inner, safe="")


def _wrap_gosuslugi(inner: str) -> str:
    return "https://www.gosuslugi.ru/redirect?url=" + quote(inner, safe="")


_WRAPPERS = {
    "safelinks": _wrap_safelinks,
    "safelinks_eu": lambda u: _wrap_safelinks(u, host="eur01.safelinks.protection.outlook.com"),
    "proxysg": _wrap_proxysg,
    "mailru": _wrap_mailru,
    "yandex": _wrap_yandex,
    "vk": _wrap_vk,
    "bitrix": _wrap_bitrix,
    "amocrm": _wrap_amocrm,
    "gosuslugi": _wrap_gosuslugi,
}


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


@pytest.mark.parametrize("target", _TARGETS[:3])
@pytest.mark.parametrize("wrapper", sorted(_WRAPPERS))
def test_unwrap_ru_and_safelinks_hosts(target: str, wrapper: str) -> None:
    wrapped = _WRAPPERS[wrapper](target)
    result = unwrap_url(wrapped)
    assert result.changed, f"{wrapper} failed to unwrap {wrapped!r}"
    host = target.split("/")[2]
    assert host in result.unwrapped or target in result.unwrapped
    assert result.rewriter != "none"
    assert result.chain


@pytest.mark.parametrize("target", _TARGETS[:2])
def test_unwrap_safelinks_over_ru_chain(target: str) -> None:
    """Nested SafeLinks → Mail.ru → target must recover the final host."""
    inner = _wrap_mailru(target)
    outer = _wrap_safelinks(inner)
    result = unwrap_url(outer, max_hops=5)
    assert result.changed
    assert target.split("/")[2] in result.unwrapped
    assert len(result.chain) >= 2
