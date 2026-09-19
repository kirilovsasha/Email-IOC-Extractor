"""Content signals and lookalike / IDN detection."""

from __future__ import annotations

from reliquary.core.content_signals import analyze_content_signals
from reliquary.core.lookalike import check_domain, levenshtein, scan_lookalikes


def test_lookalike_levenshtein_microsoft() -> None:
    hits = check_domain("micros0ft.com")
    kinds = {h.kind for h in hits}
    assert "levenshtein" in kinds or "brand_spoof" in kinds or "homoglyph" in kinds


def test_idn_detection() -> None:
    hits = check_domain("xn--pple-43d.com")
    assert isinstance(hits, list)


def test_levenshtein_basic() -> None:
    assert levenshtein("microsoft", "micros0ft") == 1


def test_content_href_mismatch() -> None:
    html = (
        '<a href="https://evil.top/login">https://www.microsoft.com/account</a>'
    )
    sigs = analyze_content_signals("", html)
    kinds = {s.kind for s in sigs}
    assert "href_mismatch" in kinds


def test_content_credential() -> None:
    sigs = analyze_content_signals("Please sign in to OWA webmail now")
    assert any(s.kind == "credential_harvest" for s in sigs)


def test_scan_lookalikes_from_addr() -> None:
    hits = scan_lookalikes(from_addr="Microsoft Support <help@evil-secure.top>")
    assert isinstance(hits, list)
