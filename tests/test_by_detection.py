"""Belarus (РБ) detection: display-spoof, ЕРИП BEC, by_gov profile, unwrap."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from reliquary.core.content_signals import analyze_content_signals
from reliquary.core.lookalike import check_display_name_spoof, scan_lookalikes
from reliquary.core.org_profile import load_org_profile
from reliquary.core.pipeline import analyze_file
from reliquary.core.url_rewrite import unwrap_url

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
CORPUS = SAMPLES / "corpus"
PRESETS = Path(__file__).resolve().parents[1] / "org_profile.example"


def test_by_display_spoof_belarusbank() -> None:
    hits = check_display_name_spoof('"Беларусбанк" <notify@bank-secure.top>')
    assert hits and hits[0].kind == "display_spoof"
    assert hits[0].brand == "belarusbank.by"
    r = analyze_file(CORPUS / "suspicious_display_spoof_belarusbank.eml")
    assert r.verdict is not None
    assert r.verdict.level.value in {"suspicious", "malicious"}
    assert r.verdict.score >= 30


def test_by_display_spoof_mns() -> None:
    hits = check_display_name_spoof('"МНС РБ" <cabinet@nalog-portal.top>')
    assert hits and hits[0].kind == "display_spoof"
    assert hits[0].brand == "nalog.gov.by"
    r = analyze_file(CORPUS / "suspicious_display_spoof_mns_by.eml")
    assert r.verdict is not None
    assert r.verdict.score >= 30


def test_by_display_legit_portal_no_spoof() -> None:
    hits = check_display_name_spoof('"Портал госуслуг РБ" <noreply@portal.gov.by>')
    assert not hits
    r = analyze_file(CORPUS / "benign_portal_gov_by.eml")
    assert r.verdict is not None
    assert r.verdict.level.value == "benign"


def test_by_bec_erip_signal() -> None:
    text = (
        "Срочно оплатите сегодня через ЕРИП на новые реквизиты "
        "УНП 190123456, р/с BY12UNBS3012. Пишите только в Telegram."
    )
    sigs = analyze_content_signals(text)
    assert any(s.kind == "bec_payment" for s in sigs)
    r = analyze_file(CORPUS / "suspicious_bec_by_erip.eml")
    assert r.verdict is not None
    assert r.verdict.level.value in {"suspicious", "malicious"}
    assert "bec_payment" in (r.content_signals or []) or any(
        "BEC" in x or "реквизит" in x.lower() or "ерип" in x.lower()
        for x in (r.verdict.reasons or [])
    )


def test_by_gov_redirect_unwrap() -> None:
    target = "https://evil.example/phish"
    wrapped = "https://portal.gov.by/redirect?url=" + quote(target, safe="")
    result = unwrap_url(wrapped)
    assert result.changed
    assert "evil.example" in result.unwrapped


def test_by_gov_org_profile() -> None:
    profile = load_org_profile(PRESETS / "by_gov")
    assert profile is not None
    assert profile.brands_path is not None
    assert Path(profile.brands_path).is_file()
    brands = Path(profile.brands_path).read_text(encoding="utf-8")
    assert "belarusbank.by" in brands
    assert "nalog.gov.by" in brands


def test_by_brand_in_defaults() -> None:
    hits = scan_lookalikes(from_addr="Приорбанк <x@evil.top>")
    assert any(h.kind == "display_spoof" and h.brand == "priorbank.by" for h in hits)
