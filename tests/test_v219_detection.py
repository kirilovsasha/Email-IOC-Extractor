"""v2.19 detection: live VBA, lure composites, reply-domain mitigation, org domains."""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from pathlib import Path

from reliquary.core.analysis_options import AnalysisOptions
from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.calibration import segment_for
from reliquary.core.models import AnalysisResult, AttachmentInfo, Ioc, IocType, MailIdentity
from reliquary.core.office_extract import detect_office_vba_live
from reliquary.core.org_profile import load_org_profile
from reliquary.core.pipeline import analyze_text
from reliquary.core.verdict import VerdictConfig, render_verdict

ROOT = Path(__file__).resolve().parents[1]


def _eml(headers: dict[str, str], body: str, *, content_type: str = "text/plain; charset=utf-8") -> str:
    lines = [f"{key}: {value}" for key, value in headers.items()]
    lines.append("MIME-Version: 1.0")
    lines.append(f"Content-Type: {content_type}")
    lines.append("")
    lines.append(body)
    return "\n".join(lines)


def _xlsm(member: str, payload: bytes) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(member, payload)
        zf.writestr("[Content_Types].xml", b"<Types/>")
    return buf.getvalue()


def _att(filename: str, flags: list[str]) -> AttachmentInfo:
    return AttachmentInfo(
        filename=filename,
        size=32,
        mime_guess="application/octet-stream",
        md5="",
        sha1="",
        sha256="",
        risk_flags=flags,
    )


def test_vba_live_markers_and_inert_project() -> None:
    live = _xlsm(
        "word/vbaProject.bin",
        b'Attribute VB_Name = "M"\r\nSub AutoOpen()\r\nURLDownloadToFile\r\nEnd Sub\r\n',
    )
    info = inspect_bytes("invoice.docm", live)
    assert "ooxml_vba" in info.risk_flags
    assert "office_vba_live" in info.risk_flags
    assert detect_office_vba_live(live) is True

    shell = _xlsm("xl/vbaProject.bin", b'Sub Workbook_Open()\r\nShell("cmd.exe")\r\nEnd Sub\r\n')
    assert "office_vba_live" in inspect_bytes("book.xlsm", shell).risk_flags

    benign_create = _xlsm(
        "word/vbaProject.bin",
        b'CreateObject("Scripting.Dictionary")\r\n',
    )
    quiet = inspect_bytes("template.docm", benign_create)
    assert "ooxml_vba" in quiet.risk_flags
    assert "office_vba_live" not in quiet.risk_flags

    prose = _xlsm("word/document.xml", b"<t>please AutoOpen powershell</t>")
    assert "office_vba_live" not in inspect_bytes("note.docx", prose).risk_flags


def test_image_only_link_reaches_suspicious() -> None:
    html = (
        "<html><body><img src='https://cdn.example/inv.png'/>"
        "<a href='https://evil.example/pay'>ok</a></body></html>"
    )
    raw = _eml(
        {
            "From": "Billing <bill@vendor.example>",
            "To": "user@company.example",
            "Subject": "Invoice",
            "Message-ID": "<img1@vendor.example>",
        },
        html,
        content_type="text/html; charset=utf-8",
    )
    result = analyze_text(raw, label="image-only.eml")
    assert result.verdict is not None
    assert "image_only_body" in (result.content_signals or [])
    assert "image_only_link" in (result.content_signals or [])
    assert result.verdict.score >= 30
    assert result.verdict.level.value == "suspicious"
    assert any("внешняя http-ссылка" in (c.reason or "") for c in result.verdict.breakdown)


def test_macro_password_and_html_form_composites() -> None:
    macro = AnalysisResult(
        source_path="macro.eml",
        source_kind="email",
        subject="файл",
        sender="a@b.example",
        raw_text_preview="Пароль архива: 4481",
        attachments=[_att("sheet.xlsm", ["office_xlm", "ooxml_vba"])],
        mail_identity=MailIdentity(from_header="A <a@b.example>"),
    )
    verdict = render_verdict(macro)
    assert verdict is not None
    assert "macro_password" in (macro.content_signals or [])
    assert verdict.score >= 30
    assert any("пароль в теле" in (c.reason or "") for c in verdict.breakdown)

    html = (
        "<html><body><form action='http://203.0.113.9/login'>"
        "<input type='text'/></form></body></html>"
    )
    attached = inspect_bytes("login.html", html.encode())
    assert "html_form_action" in attached.risk_flags
    form = AnalysisResult(
        source_path="form.eml",
        source_kind="email",
        subject="вход",
        sender="a@b.example",
        raw_text_preview="откройте вложение",
        attachments=[attached],
        mail_identity=MailIdentity(from_header="A <a@b.example>"),
    )
    form_verdict = render_verdict(form)
    assert form_verdict is not None
    assert "html_form_lure" in (form.content_signals or [])
    assert form_verdict.score >= 30
    assert segment_for(form) == "html_form_lure"


def test_thread_and_calendar_skip_foreign_reply() -> None:
    foreign = _eml(
        {
            "From": "Alice <alice@company.example>",
            "Reply-To": "other@gmail.com",
            "To": "bob@company.example",
            "Subject": "Re: бюджет",
            "Message-ID": "<m2@company.example>",
            "In-Reply-To": "<m1@company.example>",
            "References": "<m1@company.example>",
        },
        "Согласен.\nС уважением,\nAlice",
    )
    result = analyze_text(foreign, label="foreign-reply.eml")
    assert result.verdict is not None
    assert not any("существующем треде" in (c.reason or "") for c in result.verdict.breakdown)

    calendar = _eml(
        {
            "From": "Alice <alice@company.example>",
            "Reply-To": "other@gmail.com",
            "To": "bob@company.example",
            "Subject": "Приглашение",
            "Message-ID": "<cal@company.example>",
        },
        "BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:sync\nEND:VEVENT\nEND:VCALENDAR\n",
    )
    cal = analyze_text(calendar, label="cal-reply.eml")
    assert cal.verdict is not None
    assert not any("Календарное приглашение" in (c.reason or "") for c in cal.verdict.breakdown)

    payment = _eml(
        {
            "From": "CFO <cfo@company.example>",
            "To": "pay@company.example",
            "Subject": "Re: оплата",
            "Message-ID": "<p2@company.example>",
            "In-Reply-To": "<p1@company.example>",
            "References": "<p1@company.example>",
        },
        "Срочно смените реквизиты и сделайте перевод на счёт сегодня.",
    )
    pay = analyze_text(payment, label="pay-thread.eml")
    assert pay.verdict is not None
    assert not any("существующем треде" in (c.reason or "") for c in pay.verdict.breakdown)


def test_org_domains_are_protected_brands(tmp_path: Path) -> None:
    domains = tmp_path / "org_domains.txt"
    domains.write_text("# own\ncontoso.com\n", encoding="utf-8")
    spoof = AnalysisResult(
        source_path="spoof.eml",
        source_kind="email",
        subject="доступ",
        sender="Contoso Security <boss@gmail.com>",
        raw_text_preview="Портал https://contoso-secure.com/login",
        iocs=[Ioc(value="contoso-secure.com", ioc_type=IocType.DOMAIN)],
        mail_identity=MailIdentity(from_header="Contoso Security <boss@gmail.com>"),
    )
    verdict = render_verdict(spoof, org_domains_path=domains)
    assert verdict is not None
    assert "org_domain" in (spoof.content_signals or [])
    assert any("свой домен" in (c.reason or "").lower() for c in verdict.breakdown)
    assert segment_for(spoof) == "org_domain"

    legit = AnalysisResult(
        source_path="legit.eml",
        source_kind="email",
        subject="ок",
        sender="Contoso <a@contoso.com>",
        raw_text_preview="Внутренняя рассылка contoso.com",
        mail_identity=MailIdentity(from_header="Contoso <a@contoso.com>"),
    )
    render_verdict(legit, org_domains_path=domains)
    assert "org_domain" not in (legit.content_signals or [])

    (tmp_path / "brands.txt").write_text("other.example\n", encoding="utf-8")
    profile = load_org_profile(tmp_path)
    assert profile is not None
    assert profile.org_domains_path == domains
    opts = AnalysisOptions().with_profile(profile)
    assert opts.org_domains_path == domains


def test_v219_weights_in_schema() -> None:
    cfg = VerdictConfig()
    assert cfg.weight_office_vba_live == 22
    assert cfg.weight_image_only_link == 16
    assert cfg.weight_macro_password == 12
    assert cfg.weight_html_form_lure == 16
    schema = json.loads((ROOT / "docs" / "verdict_extra.schema.json").read_text(encoding="utf-8"))
    example = json.loads((ROOT / "verdict_extra.example.json").read_text(encoding="utf-8"))
    for key in (
        "weight_office_vba_live",
        "weight_image_only_link",
        "weight_macro_password",
        "weight_html_form_lure",
    ):
        assert key in schema["properties"]
        assert key in example
