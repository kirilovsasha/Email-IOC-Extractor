"""v2.8: BEC, nested unwrap, MISP/OpenCTI, campaign, labels, schema v2."""

from __future__ import annotations

import json
from pathlib import Path

from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.campaign import export_campaign_handoff, summarize_campaigns
from reliquary.core.content_signals import analyze_content_signals
from reliquary.core.labels import parse_verdict_level, verdict_label_ru
from reliquary.core.models import SCHEMA_VERSION
from reliquary.core.pipeline import analyze_file
from reliquary.core.url_rewrite import unwrap_url
from reliquary.gui.export_actions import run_export

CORPUS = Path(__file__).resolve().parents[1] / "samples" / "corpus"


def test_schema_version_is_2() -> None:
    assert SCHEMA_VERSION == 2
    result = analyze_file(CORPUS / "benign_hr_notice.eml")
    payload = result.to_dict()
    assert payload["schema_version"] == 2
    assert "unwrap_chains" in payload


def test_nested_unwrap_chain() -> None:
    url = (
        "https://nam.safelinks.protection.outlook.com/"
        "?url=http%3A%2F%2Fsg.company.local%3A8080%2F*%2C1%2C%2F"
        "https%3A%2F%2Fevil.example.com%2Fx"
    )
    r = unwrap_url(url)
    assert r.changed
    assert "microsoft_safelinks" in r.chain
    assert "proxysg" in r.chain
    assert r.unwrapped.startswith("https://evil.example.com")


def test_bec_content_signal() -> None:
    signals = analyze_content_signals(
        "Срочно смените реквизиты и пишите только в Telegram @x",
        "",
    )
    kinds = {s.kind for s in signals}
    assert "bec_payment" in kinds


def test_href_mismatch_after_unwrap() -> None:
    html = (
        '<a href="https://nam.safelinks.protection.outlook.com/'
        '?url=https%3A%2F%2Fevil.top%2Fx">microsoft.com</a>'
    )
    signals = analyze_content_signals("", html)
    assert any(s.kind == "href_mismatch" for s in signals)


def test_iso_lnk_onenote_flags() -> None:
    iso = inspect_bytes("disk.iso", b"\x00" * 64)
    assert "iso_image" in iso.risk_flags
    lnk = inspect_bytes("run.lnk", b"\x00" * 64)
    assert "shortcut_lnk" in lnk.risk_flags
    one = inspect_bytes("notes.one", b"\x00" * 64)
    assert "onenote_attachment" in one.risk_flags


def test_verdict_labels_ru() -> None:
    assert verdict_label_ru("malicious") == "вредоносный"
    assert parse_verdict_level("подозрительный").value == "suspicious"  # type: ignore[union-attr]
    assert parse_verdict_level("benign").value == "benign"  # type: ignore[union-attr]


def test_campaign_summary_and_export(tmp_path: Path) -> None:
    a = analyze_file(CORPUS / "campaign_a1.eml")
    b = analyze_file(CORPUS / "campaign_a2.eml")
    summaries = summarize_campaigns([a, b])
    assert summaries
    assert summaries[0].file_count >= 2
    out = export_campaign_handoff([a, b], tmp_path / "c.txt")
    text = out.read_text(encoding="utf-8")
    assert "Кампания" in text or "кампани" in text.lower()


def test_misp_opencti_exports(tmp_path: Path) -> None:
    result = analyze_file(CORPUS / "malicious_exe_ip_url.eml")
    # SIEM/TIP formats stay available via run_export / CLI, not GUI menu
    misp = run_export("misp", result, tmp_path / "m.csv")
    assert "ip-dst" in misp.read_text(encoding="utf-8-sig") or "url" in misp.read_text(
        encoding="utf-8-sig"
    )
    octi = run_export("opencti", result, tmp_path / "o.json")
    payload = json.loads(octi.read_text(encoding="utf-8"))
    assert payload["type"] == "opencti-bundle-lite"
    assert payload["x_reliquary_schema"] == 2


def test_bec_corpus_case() -> None:
    r = analyze_file(CORPUS / "suspicious_bec_ru_payment.eml")
    assert r.verdict is not None
    assert r.verdict.level.value in ("suspicious", "malicious")
    assert "bec_payment" in (r.content_signals or []) or any(
        "BEC" in x or "реквизит" in x.lower() or "Telegram" in x for x in r.verdict.reasons
    )
