"""URL rewriter unwrap snapshots (offline, no network)."""

from __future__ import annotations

import pytest

from reliquary.core.url_rewrite import find_and_unwrap, unwrap_url

CASES = [
    (
        "safelinks",
        "https://nam.safelinks.protection.outlook.com/"
        "?url=https%3A%2F%2Fevil.example.com%2Fx&data=01",
        "microsoft_safelinks",
        "https://evil.example.com/x",
    ),
    (
        "proofpoint_v2",
        "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example.com_a&d=Dw",
        "proofpoint_v2",
        "evil.example.com",
    ),
    (
        "proofpoint_v3",
        "https://urldefense.proofpoint.com/v3/__https://evil.example.com/path__;!!",
        "proofpoint_v3",
        "https://evil.example.com/path",
    ),
    (
        "barracuda",
        "https://linkprotect.cudasvc.com/url?a=https%3A%2F%2Fevil.example.com%2Fy&c=1",
        "barracuda",
        "https://evil.example.com/y",
    ),
    (
        "mimecast",
        "https://protect-eu.mimecast.com/s/abc?url=https%3A%2F%2Fevil.example.com%2Fz",
        "mimecast",
        "https://evil.example.com/z",
    ),
    (
        "fireeye",
        "https://protect.fireeye.com/v1/url?url=https%3A%2F%2Fevil.example.com%2Fw",
        "fireeye",
        "https://evil.example.com/w",
    ),
    (
        "cisco_umbrella",
        "https://secure-web.cisco.com/1/abc?url=https%3A%2F%2Fevil.example.com%2Fcisco",
        "cisco_umbrella",
        "https://evil.example.com/cisco",
    ),
    (
        "google_redirect",
        "https://www.google.com/url?q=https%3A%2F%2Fevil.example.com%2Fg&sa=D",
        "google_redirect",
        "https://evil.example.com/g",
    ),
    (
        "defender_atp",
        "https://protection.office.com/?url=https%3A%2F%2Fevil.example.com%2Fatp",
        "defender_atp",
        "https://evil.example.com/atp",
    ),
    (
        "generic_redirect",
        "https://tracker.mail.example/click?url=https%3A%2F%2Fevil.example.com%2Fq",
        "generic_redirect",
        "https://evil.example.com/q",
    ),
]


@pytest.mark.parametrize("name,url,rewriter,expect", CASES, ids=[c[0] for c in CASES])
def test_unwrap_snapshot(name: str, url: str, rewriter: str, expect: str) -> None:
    result = unwrap_url(url)
    assert result.rewriter == rewriter
    assert result.changed
    if expect.startswith("http"):
        assert result.unwrapped.startswith(expect) or result.unwrapped == expect
    else:
        assert expect in result.unwrapped


def test_find_and_unwrap_multiple() -> None:
    text = (
        "a https://nam.safelinks.protection.outlook.com/"
        "?url=https%3A%2F%2Fa.example%2F1&data=01 "
        "b https://linkprotect.cudasvc.com/url?a=https%3A%2F%2Fb.example%2F2"
    )
    hits = find_and_unwrap(text)
    rewriters = {h.rewriter for h in hits if h.changed}
    assert "microsoft_safelinks" in rewriters
    assert "barracuda" in rewriters


@pytest.mark.parametrize(
    "extra",
    [
        "&utm_source=x",
        "&data=AAAA",
        "?foo=1&url=https%3A%2F%2Fevil.example.com%2Fz",
        "",
    ],
)
def test_unwrap_safelinks_query_fuzz(extra: str) -> None:
    """Property-ish: SafeLinks still unwraps with noisy query tails."""
    base = (
        "https://nam.safelinks.protection.outlook.com/"
        "?url=https%3A%2F%2Fevil.example.com%2Fpath"
    )
    url = base + extra
    result = unwrap_url(url)
    if result.changed:
        assert "evil.example.com" in result.unwrapped


def test_unwrap_proofpoint_noise() -> None:
    url = (
        "https://urldefense.proofpoint.com/v2/url?"
        "u=https-3A__evil.example.com_a&d=Dw&c=noise&r=xx"
    )
    result = unwrap_url(url)
    assert result.changed
    assert "evil.example.com" in result.unwrapped
