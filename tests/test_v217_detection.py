"""v2.17 detection — wrap-lure, ARC/reply-chain, campaign, attachments, HTML, PST, caps."""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from pathlib import Path

from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.calibration import segment_for
from reliquary.core.content_signals import analyze_content_signals
from reliquary.core.feedback import FeedbackEvent, append_feedback, suggest_threshold_overrides
from reliquary.core.formats import expand_input_paths, is_supported
from reliquary.core.lookalike import normalize_homoglyph
from reliquary.core.office_extract import detect_office_dde
from reliquary.core.pipeline import analyze_file, apply_campaign_divergence, campaign_divergence_keys
from reliquary.core.pst_ingest import expand_pst_to_emls, looks_like_pst, pst_library_available
from reliquary.core.verdict import VerdictConfig
from reliquary.core.models import AnalysisResult, MailIdentity, Verdict, VerdictLevel

CORPUS = Path(__file__).resolve().parents[1] / "samples" / "corpus"
ROOT = Path(__file__).resolve().parents[1]


def test_wrap_lure_raises_floor() -> None:
    cfg = VerdictConfig()
    assert cfg.weight_wrap_lure == 12
    for name in (
        "suspicious_mailru_wrap.eml",
        "suspicious_vk_away.eml",
        "suspicious_password_safelinks.eml",
    ):
        r = analyze_file(CORPUS / name)
        assert r.verdict is not None
        assert r.verdict.level.value == "suspicious"
        assert r.verdict.score >= 30
        assert "wrap_lure" in (r.content_signals or []) or any(
            "wrap" in (c.reason or "").lower() for c in r.verdict.breakdown
        )


def test_return_path_mismatch_toward_suspicious() -> None:
    cfg = VerdictConfig()
    assert cfg.weight_return_path_mismatch == 10
    r = analyze_file(CORPUS / "suspicious_return_path_mismatch.eml")
    assert r.verdict is not None
    assert r.verdict.level.value == "suspicious"
    assert any("Return-Path" in (c.reason or "") for c in r.verdict.breakdown)


def test_fp_softfail_legit_brand_stays_low() -> None:
    r = analyze_file(CORPUS / "fp_softfail_legit_brand.eml")
    assert r.verdict is not None
    assert r.verdict.level.value in ("unknown", "benign")
    assert r.verdict.score < 30
    assert not any("SPF softfail/fail + lookalike" in (c.reason or "") for c in r.verdict.breakdown)


def test_arc_fail_weight() -> None:
    cfg = VerdictConfig()
    assert cfg.weight_arc_fail == 12
    r = analyze_file(CORPUS / "suspicious_arc_auth_fail.eml")
    assert r.verdict is not None
    assert r.verdict.level.value in ("suspicious", "malicious")
    assert any(
        h.name in ("ARC", "ARC result") and "fail" in (h.value or "").lower() for h in r.headers
    )
    assert any("ARC" in (c.reason or "") for c in r.verdict.breakdown)


def test_reply_chain_anomaly() -> None:
    cfg = VerdictConfig()
    assert cfg.weight_reply_chain_anomaly == 14
    r = analyze_file(CORPUS / "suspicious_reply_chain_spoof.eml")
    assert r.verdict is not None
    assert r.verdict.level.value == "malicious"
    assert any("Reply-chain" in (h.name or "") for h in r.headers)
    assert any("Reply-chain" in (c.reason or "") for c in r.verdict.breakdown)


def test_campaign_divergence_signal() -> None:
    a = AnalysisResult(
        source_path="a.eml",
        source_kind="email",
        sender="one@alpha.example",
        subject="Same campaign subject XYZ",
        mail_identity=MailIdentity(
            from_header="one@alpha.example",
            subject="Same campaign subject XYZ",
            message_id="<same-camp@shared.local>",
        ),
        verdict=Verdict(level=VerdictLevel.SUSPICIOUS, score=40, summary="x", reasons=["r"]),
    )
    b = AnalysisResult(
        source_path="b.eml",
        source_kind="email",
        sender="two@beta.example",
        subject="Same campaign subject XYZ",
        mail_identity=MailIdentity(
            from_header="two@beta.example",
            subject="Same campaign subject XYZ",
            message_id="<same-camp@shared.local>",
        ),
        verdict=Verdict(level=VerdictLevel.SUSPICIOUS, score=40, summary="x", reasons=["r"]),
    )
    keys = campaign_divergence_keys([a, b])
    assert keys
    apply_campaign_divergence([a, b])
    assert "campaign_divergence" in (a.content_signals or [])
    assert "campaign_divergence" in (b.content_signals or [])


def test_office_dde_flag() -> None:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "xl/sharedStrings.xml",
            '<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            "<si><t>DDEAUTO mseexcel|cmd|/c calc</t></si></sst>",
        )
    raw = buf.getvalue()
    assert detect_office_dde(raw) is True
    info = inspect_bytes("q3.xlsx", raw)
    assert "office_dde" in info.risk_flags
    r = analyze_file(CORPUS / "suspicious_office_dde.eml")
    assert any("office_dde" in (a.risk_flags or []) for a in r.attachments)


def test_ole_package_and_pdf_openaction_uri() -> None:
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64 + b"Ole10Native" + b"\x00Package\x00"
    info = inspect_bytes("payload.doc", ole)
    assert "ole_package" in info.risk_flags
    pdf = (
        b"%PDF-1.4\n/OpenAction\n/URI (https://evil.top/x)\ntrailer\n%%EOF\n"
    )
    info2 = inspect_bytes("x.pdf", pdf)
    assert "pdf_openaction_uri" in info2.risk_flags
    r = analyze_file(CORPUS / "suspicious_pdf_openaction_uri.eml")
    assert any("pdf_openaction_uri" in (a.risk_flags or []) for a in r.attachments)


def test_onenote_embedded_file() -> None:
    raw = b"ONEDOC" + b"\x00" * 32 + b"FileData" + b"embeddedFile" + b"\x00" * 16
    info = inspect_bytes("note.one", raw)
    assert "onenote_attachment" in info.risk_flags
    assert "onenote_embedded_file" in info.risk_flags


def test_cid_phishing_and_form_action() -> None:
    html = (
        '<html><body><img src="cid:x"/><a href="https://evil.top/l"> </a></body></html>'
    )
    kinds = {s.kind for s in analyze_content_signals("", html)}
    assert "cid_phishing" in kinds
    html2 = '<html><body><form action="http://198.51.100.9/x"><input type="text"/></form></body></html>'
    kinds2 = {s.kind for s in analyze_content_signals("", html2)}
    assert "form_action_suspicious" in kinds2
    # hidden style variants
    html3 = '<div style="position:absolute;left:-9999px">hidden lure password</div>'
    kinds3 = {s.kind for s in analyze_content_signals("", html3)}
    assert "hidden_text" in kinds3 or "hidden_style" in kinds3
    r = analyze_file(CORPUS / "suspicious_cid_phishing.eml")
    assert "cid_phishing" in (r.content_signals or [])
    r2 = analyze_file(CORPUS / "suspicious_form_action_ip.eml")
    assert "form_action_suspicious" in (r2.content_signals or []) or any(
        "form" in (c.reason or "").lower() for c in (r2.verdict.breakdown if r2.verdict else [])
    )


def test_homoglyph_uppercase_and_kz() -> None:
    assert normalize_homoglyph("КАSPI") == "kaspi" or "a" in normalize_homoglyph("а")
    assert normalize_homoglyph("а") == "a"
    assert normalize_homoglyph("Р") == "p"
    r = analyze_file(CORPUS / "malicious_homoglyph_kaspi.eml")
    assert r.verdict is not None
    assert r.verdict.level.value in ("suspicious", "malicious")


def test_yara_pack_v2_rules() -> None:
    text = (ROOT / "yara_rules" / "default.yar").read_text(encoding="utf-8")
    for name in (
        "remote_template",
        "html_polyglot",
        "office_dde",
        "ole10native",
        "pdf_openaction",
    ):
        assert f"rule {name}" in text


def test_cap_display_spoof_default() -> None:
    cfg = VerdictConfig()
    assert cfg.cap_display_spoof == 28
    assert cfg.weight_display_spoof <= cfg.cap_display_spoof


def test_feedback_threshold_overrides(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("reliquary.core.feedback.app_dir", lambda: tmp_path)
    for i in range(3):
        append_feedback(
            FeedbackEvent(
                kind="fp",
                expected_level="benign",
                observed_level="suspicious",
                score=40,
                source_path=f"fp{i}.eml",
                segment="display_spoof",
            )
        )
    thr = suggest_threshold_overrides()
    assert thr
    assert "threshold_suspicious" in thr or "cap_display_spoof" in thr


def test_pst_magic_and_missing_lib(tmp_path: Path) -> None:
    pst = tmp_path / "mail.pst"
    pst.write_bytes(b"!BDN" + b"\x00" * 64)
    assert looks_like_pst(pst)
    assert is_supported(pst)
    emls, _dest, notes = expand_pst_to_emls(pst)
    if not pst_library_available():
        assert emls == []
        assert any("недоступен" in n or "pypff" in n.lower() or "libratom" in n.lower() for n in notes)
    # expand_input_paths must not crash
    expanded = expand_input_paths([pst])
    assert isinstance(expanded, list)


def test_new_weights_defaults_v217() -> None:
    cfg = VerdictConfig()
    assert cfg.weight_wrap_lure == 12
    assert cfg.weight_return_path_mismatch == 10
    assert cfg.weight_arc_fail == 12
    assert cfg.weight_reply_chain_anomaly == 14
    assert cfg.weight_campaign_divergence == 10
    assert cfg.weight_office_dde == 18
    assert cfg.weight_ole_package == 16
    assert cfg.weight_pdf_openaction_uri == 14
    assert cfg.weight_cid_phishing == 12
    assert cfg.weight_form_action_suspicious == 14


def test_schema_has_v217_weights() -> None:
    schema = json.loads((ROOT / "docs" / "verdict_extra.schema.json").read_text(encoding="utf-8"))
    props = schema["properties"]
    for key in (
        "weight_wrap_lure",
        "weight_return_path_mismatch",
        "weight_arc_fail",
        "weight_reply_chain_anomaly",
        "weight_campaign_divergence",
        "weight_office_dde",
        "weight_ole_package",
        "weight_pdf_openaction_uri",
        "weight_cid_phishing",
        "weight_form_action_suspicious",
        "cap_display_spoof",
    ):
        assert key in props


def test_calibration_segments_v217() -> None:
    r = analyze_file(CORPUS / "suspicious_password_safelinks.eml")
    assert segment_for(r) in ("wrap_lure", "safelinks", "phishing_content", "rewrite")
    r2 = analyze_file(CORPUS / "suspicious_cid_phishing.eml")
    assert segment_for(r2) == "cid_phishing"
    r3 = analyze_file(CORPUS / "suspicious_office_dde.eml")
    assert segment_for(r3) == "office_dde"
