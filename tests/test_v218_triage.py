"""v2.18 triage signals and GUI helpers (no Tk display)."""

from __future__ import annotations

import zipfile
from io import BytesIO

from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.content_signals import analyze_content_signals
from reliquary.core.feedback import format_feedback_ack
from reliquary.core.models import AnalysisResult, FileTriageRow, ScoreContribution
from reliquary.core.pipeline import analyze_text
from reliquary.core.pst_ingest import compose_eml
from reliquary.core.verdict import VerdictConfig
from reliquary.core.verdict_scoring import _ics_has_attach, _score_mitigations
from reliquary.gui.result_panels import campaign_banner_text


def _eml(headers: dict[str, str], body: str, *, content_type: str = "text/plain; charset=utf-8") -> str:
    lines = [f"{key}: {value}" for key, value in headers.items()]
    lines.append("MIME-Version: 1.0")
    lines.append(f"Content-Type: {content_type}")
    lines.append("")
    lines.append(body)
    return "\n".join(lines)


def test_clickfix_and_fake_auth_and_image_only() -> None:
    kinds = {
        s.kind
        for s in analyze_content_signals("Нажмите Win+R и выполните команду powershell -enc QQ==", "")
    }
    assert "clickfix" in kinds

    fake = {
        s.kind
        for s in analyze_content_signals(
            "",
            "<p>Проверка: spf=pass dkim=pass</p><a href='https://evil.example'>войти</a>",
        )
    }
    assert "fake_auth_results" in fake

    html = (
        "<html><body><img src='https://cdn.example/inv.png'/>"
        "<a href='https://evil.example/pay'>ok</a></body></html>"
    )
    image = {s.kind for s in analyze_content_signals("", html)}
    assert "image_only_body" in image

    header_only = analyze_content_signals(
        "Authentication-Results: mx; spf=pass\n\nОбычный текст письма без фишинга.",
        "",
    )
    assert "fake_auth_results" not in {s.kind for s in header_only}


def test_password_plus_office_encrypted() -> None:
    kinds = {
        s.kind
        for s in analyze_content_signals(
            "Пароль архива: 1234",
            "",
            has_office_encrypted=True,
        )
    }
    assert "archive_password_match" in kinds


def test_excel_xlm_flag() -> None:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("xl/macrosheets/sheet1.xml", "<xml/>")
        zf.writestr("[Content_Types].xml", "<Types/>")
    info = inspect_bytes("invoice.xlsm", buf.getvalue())
    assert "office_xlm" in info.risk_flags


def test_msgid_surfaces_and_resent_from() -> None:
    raw = _eml(
        {
            "From": "Ivan <ivan@company.example>",
            "To": "user@company.example",
            "Subject": "Документ",
            "Message-ID": "<abc@other.example>",
            "Resent-From": "Other <other@relay.example>",
        },
        "Смотрите вложение.",
    )
    result = analyze_text(raw, label="msgid.eml")
    assert result.verdict is not None
    assert any(h.name == "Message-ID domain" for h in result.headers)
    assert any(h.name == "Resent-From domain" for h in result.headers)
    reasons = [c.reason for c in result.verdict.breakdown]
    assert any("Message-ID" in r for r in reasons)
    assert any("Resent-From" in r for r in reasons)


def test_calendar_attach_skips_mitigation() -> None:
    ics = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:sync\nATTACH:file://share/a.exe\nEND:VEVENT\nEND:VCALENDAR\n"
    result = AnalysisResult(source_kind="email", source_path="cal.eml", subject="Meeting")
    result.raw_text_preview = ics
    assert _ics_has_attach(result, ics)
    cfg = VerdictConfig()
    _score, parts = _score_mitigations(result, cfg)
    assert not any("Календар" in (c.reason or "") for c in parts)


def test_pst_compose_includes_attachment() -> None:
    raw = compose_eml(
        "From: a@example\nSubject: hi\n",
        b"body",
        [("invoice.xlsm", b"PK\x03\x04xlsm")],
    )
    assert b"invoice.xlsm" in raw
    assert b"Content-Disposition: attachment" in raw


def test_campaign_banner() -> None:
    result = AnalysisResult(source_kind="batch", source_path="a.eml")
    result.file_rows = [
        FileTriageRow(
            path="a.eml",
            kind="email",
            sender="one@alpha.example",
            campaign_key="k",
            campaign_peers=["b.eml"],
        ),
        FileTriageRow(
            path="b.eml",
            kind="email",
            sender="two@beta.example",
            campaign_key="k",
            campaign_peers=["a.eml"],
        ),
    ]
    text = campaign_banner_text(result)
    assert "разошлись" in text
    assert "alpha.example" in text


def test_feedback_ack_mentions_weight_without_applying() -> None:
    text = format_feedback_ack(
        "fn",
        "clickfix",
        [ScoreContribution("content", 16, "ClickFix / Win+R")],
    )
    assert "+16" in text
    assert "weight_clickfix" in text
    assert "не изменены" in text


def test_new_weights_v218() -> None:
    cfg = VerdictConfig()
    assert cfg.weight_clickfix == 16
    assert cfg.weight_image_only_body == 14
    assert cfg.weight_fake_auth_results == 12
    assert cfg.weight_office_xlm == 22
    assert cfg.weight_resent_from_mismatch == 12
