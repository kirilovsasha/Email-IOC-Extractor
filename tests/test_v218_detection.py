"""Detection depth: headers, URI schemes, lure files, RTF/PDF/OOXML, BEC tokens."""

from __future__ import annotations

import zipfile
from io import BytesIO

from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.content_signals import analyze_content_signals
from reliquary.core.models import AnalysisResult, AttachmentInfo
from reliquary.core.office_extract import detect_office_external_data
from reliquary.core.pipeline import analyze_text
from reliquary.core.verdict import VerdictConfig
from reliquary.core.verdict_config import normalize_suspicious_tlds
from reliquary.core.verdict_scoring import _score_content


def _eml(headers: dict[str, str], body: str, *, content_type: str = "text/plain; charset=utf-8") -> str:
    lines = [f"{key}: {value}" for key, value in headers.items()]
    lines.append("MIME-Version: 1.0")
    lines.append(f"Content-Type: {content_type}")
    lines.append("")
    lines.append(body)
    return "\n".join(lines)


def test_sender_mismatch_without_dmarc() -> None:
    raw = _eml(
        {
            "From": "Director <dir@company.example>",
            "Sender": "ext@gmail.com",
            "To": "user@company.example",
            "Subject": "Срочно",
            "Message-ID": "<s1@company.example>",
        },
        "Нужно обсудить.",
    )
    result = analyze_text(raw, label="sender.eml")
    assert result.verdict is not None
    assert any(
        h.name == "Sender mismatch" and h.severity.value == "high" for h in result.headers
    )
    assert any("Sender ≠ From" in (c.reason or "") for c in result.verdict.breakdown)


def test_sender_mismatch_skipped_on_dmarc_pass() -> None:
    raw = _eml(
        {
            "From": "Director <dir@company.example>",
            "Sender": "ext@gmail.com",
            "To": "user@company.example",
            "Subject": "Дайджест",
            "Message-ID": "<s2@company.example>",
            "Authentication-Results": "mx.example; spf=pass; dkim=pass; dmarc=pass",
        },
        "Обычное письмо.",
    )
    result = analyze_text(raw, label="sender-pass.eml")
    assert result.verdict is not None
    assert any(
        h.name == "Sender mismatch" and h.severity.value == "info" for h in result.headers
    )
    assert not any("Sender ≠ From" in (c.reason or "") for c in result.verdict.breakdown)


def test_orphan_reply_and_mailer_brand() -> None:
    orphan = _eml(
        {
            "From": "Ann <ann@vendor.example>",
            "To": "user@company.example",
            "Subject": "Re: счёт",
            "Message-ID": "<o1@vendor.example>",
        },
        "Продолжение.",
    )
    result = analyze_text(orphan, label="orphan.eml")
    assert result.verdict is not None
    assert any(h.name == "Orphan reply" for h in result.headers)
    assert any("In-Reply-To" in (c.reason or "") for c in result.verdict.breakdown)

    spoof = _eml(
        {
            "From": '"Microsoft" <phish@evil.example>',
            "To": "user@company.example",
            "Subject": "Mailbox",
            "Message-ID": "<m1@evil.example>",
            "X-Mailer": "PHPMailer 6.8.0",
        },
        "Verify.",
    )
    result2 = analyze_text(spoof, label="mailer.eml")
    assert result2.verdict is not None
    assert any(h.name == "Display-name spoof" for h in result2.headers)
    assert any(h.name == "Mailer brand mismatch" for h in result2.headers)
    assert any("X-Mailer" in (c.reason or "") or "почтов" in (c.reason or "").lower() for c in result2.verdict.breakdown)


def test_dangerous_scheme_userinfo_and_tlds() -> None:
    kinds = {
        s.kind
        for s in analyze_content_signals(
            "",
            '<html><body><a href="search-ms:query=invoice">x</a>'
            '<form action="javascript:alert(1)"></form></body></html>',
        )
    }
    assert "dangerous_scheme" in kinds
    kinds2 = {s.kind for s in analyze_content_signals("open https://sberbank.ru@evil.tld/login", "")}
    assert "url_userinfo" in kinds2
    kinds3 = {
        s.kind
        for s in analyze_content_signals(
            "",
            '<form action="http://login.click/x"><input type="text"/></form>',
        )
    }
    assert "form_action_suspicious" in kinds3
    assert ".click" in normalize_suspicious_tlds(["click", ".sbs"])


def test_payment_tokens_and_callback() -> None:
    quiet = {s.kind for s in analyze_content_signals("IBAN GB29NWBK60161331926819", "")}
    assert "payment_tokens" not in quiet
    changed = {
        s.kind
        for s in analyze_content_signals(
            "Новые реквизиты IBAN GB29NWBK60161331926819",
            "",
        )
    }
    assert "payment_tokens" in changed
    callback = {s.kind for s in analyze_content_signals("Не отвечайте на письмо, перезвоните.", "")}
    assert "bec_callback" in callback


def test_freemail_bec_and_password_lure_file() -> None:
    raw = _eml(
        {
            "From": "CFO <cfo@gmail.com>",
            "To": "user@company.example",
            "Subject": "Оплата",
            "Message-ID": "<b1@gmail.com>",
        },
        "Смените реквизиты и сделайте перевод сегодня.",
    )
    result = analyze_text(raw, label="freemail.eml")
    assert "freemail_bec" in (result.content_signals or [])
    assert result.verdict is not None
    assert any("freemail" in (c.reason or "") for c in result.verdict.breakdown)

    att = AttachmentInfo(
        filename="doc.html",
        size=10,
        mime_guess="text/html",
        md5="a",
        sha1="b",
        sha256="c",
        risk_flags=["html_attachment"],
    )
    scored = AnalysisResult(
        source_path="pw.eml",
        source_kind="email",
        subject="архив",
        raw_text_preview="Пароль архива: secret",
        attachments=[att],
    )
    _points, parts = _score_content(scored, VerdictConfig())
    assert any("HTML" in (p.reason or "") or "ярлык" in (p.reason or "") for p in parts)


def test_lure_shortcut_rtf_pdf_and_iso_script() -> None:
    url = inspect_bytes(
        "invoice.url",
        b"[InternetShortcut]\r\nURL=https://evil.example/pay\r\n",
    )
    assert "lure_shortcut" in url.risk_flags
    assert "lure_shortcut_target" in url.risk_flags
    iqy = inspect_bytes("q.iqy", b"WEB\n1\nhttps://evil.example/sheet\n")
    assert "lure_shortcut_target" in iqy.risk_flags

    rtf = inspect_bytes("note.rtf", b"{\\rtf1 \\objupdate Equation.3 \\objdata aabb}")
    assert "rtf_exploit" in rtf.risk_flags
    assert "rtf_equation" in rtf.risk_flags

    pdf = inspect_bytes("a.pdf", b"%PDF-1.4\n/Launch /Win << /F (cmd.exe) >>\n")
    assert "pdf_launch" in pdf.risk_flags
    assert "pdf_javascript" not in pdf.risk_flags
    pdf2 = inspect_bytes("b.pdf", b"%PDF-1.4\n/SubmitForm /GoToR (https://evil.example/x.pdf)\n")
    assert "pdf_submitform" in pdf2.risk_flags
    assert "pdf_gotor" in pdf2.risk_flags

    iso = inspect_bytes("disk.iso", b"CD001" + b"\x00" * 16 + b"payload.js")
    assert "iso_contains_script" in iso.risk_flags

    lnk = b"L\x00\x00\x00" + b"\x00" * 0x48 + b"C:\\Windows\\System32\\certutil.exe -urlcache"
    assert "lnk_dangerous" in inspect_bytes("run.lnk", lnk).risk_flags


def test_office_encrypted_and_external_data() -> None:
    enc = BytesIO()
    with zipfile.ZipFile(enc, "w") as zf:
        zf.writestr("EncryptionInfo", b"agile")
        zf.writestr("EncryptedPackage", b"\x00" * 32)
    info = inspect_bytes("secret.docx", enc.getvalue())
    assert "office_encrypted" in info.risk_flags

    book = BytesIO()
    with zipfile.ZipFile(book, "w") as zf:
        zf.writestr(
            "xl/connections.xml",
            '<?xml version="1.0"?><connections><connection source="https://evil.example/c"/></connections>',
        )
        zf.writestr(
            "xl/worksheets/sheet1.xml",
            '<worksheet><f>WEBSERVICE("https://evil.example/x")</f></worksheet>',
        )
    raw = book.getvalue()
    assert detect_office_external_data(raw) is True
    info2 = inspect_bytes("book.xlsx", raw)
    assert "office_external_data" in info2.risk_flags


def test_calendar_ics_link_skips_mitigation() -> None:
    linked = _eml(
        {
            "From": "calendar@contoso.com",
            "To": "user@company.example",
            "Subject": "Meeting: review",
            "Message-ID": "<cal1@contoso.com>",
            "Authentication-Results": "mx.example; spf=pass; dkim=pass; dmarc=pass",
        },
        "BEGIN:VCALENDAR\nDESCRIPTION:https://evil.example/phish\nEND:VCALENDAR\n",
    )
    result = analyze_text(linked, label="cal-link.eml")
    assert result.verdict is not None
    assert not any("Календарное приглашение" in (c.reason or "") for c in result.verdict.breakdown)

    plain = _eml(
        {
            "From": "calendar@contoso.com",
            "To": "user@company.example",
            "Subject": "Meeting: review",
            "Message-ID": "<cal2@contoso.com>",
            "Authentication-Results": "mx.example; spf=pass; dkim=pass; dmarc=pass",
        },
        "You are invited to Q3 planning tomorrow at 10:00. No links.",
    )
    result2 = analyze_text(plain, label="cal-plain.eml")
    assert result2.verdict is not None
    # The words alone are not a calendar part.
    assert not any("Календарное приглашение" in (c.reason or "") for c in result2.verdict.breakdown)
