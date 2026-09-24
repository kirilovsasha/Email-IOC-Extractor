"""Sixth-pass fixes: kinship, quiet signals, parse edges, IOC, allowlist, subject key."""

from __future__ import annotations

import email

from reliquary.core.allowlist import build_allowlist, domain_matches, tag_allowlist
from reliquary.core.content_signals import (
    BEC_RE,
    CREDENTIAL_RE,
    MESSENGER_LURE_RE,
    QR_LURE_RE,
    analyze_content_signals,
)
from reliquary.core.ioc_extractor import extract_iocs
from reliquary.core.lookalike import check_domain
from reliquary.core.models import Ioc, IocType
from reliquary.core.pipeline import (
    analyze_file,
    analyze_text,
    campaign_divergence_keys,
    campaign_key_for,
)
from reliquary.core.pst_ingest import compose_eml


def _two_hops() -> str:
    return (
        "Received: from mx1.example.org (mx1.example.org [203.0.113.1]) "
        "by mx.dest.test; Wed, 17 Sep 2025 10:00:00 +0000\n"
        "Received: from sender.example.net (sender.example.net [203.0.113.2]) "
        "by mx1.example.org; Wed, 17 Sep 2025 09:59:00 +0000\n"
    )


def _eml(headers: dict[str, str], body: str, *, content_type: str = "text/plain; charset=utf-8") -> str:
    lines = [f"{key}: {value}" for key, value in headers.items()]
    lines.append("MIME-Version: 1.0")
    lines.append(f"Content-Type: {content_type}")
    lines.append("")
    lines.append(body)
    return "\n".join(lines)


def _pass_mail(
    body: str,
    extra: dict[str, str] | None = None,
    *,
    content_type: str = "text/plain; charset=utf-8",
) -> str:
    headers = {
        "From": "News <news@company.example>",
        "To": "user@company.example",
        "Subject": "hello",
        "Message-ID": "<m@company.example>",
        "Authentication-Results": "mx.example; spf=pass; dkim=pass; dmarc=pass",
    }
    if extra:
        headers.update(extra)
    return _two_hops() + _eml(headers, body, content_type=content_type)


def _reasons(result) -> str:
    assert result.verdict is not None
    return " ".join(c.reason or "" for c in result.verdict.breakdown)


def _values(text: str, kind: str) -> list[str]:
    return [i.value for i in extract_iocs(text) if i.ioc_type.value == kind]


def test_dkim_subdomain_is_aligned_either_way() -> None:
    parent = _pass_mail(
        "обычный текст",
        {
            "Authentication-Results": (
                "mx.example; spf=pass; dkim=pass header.d=mail.company.example "
                "header.from=company.example; dmarc=pass"
            )
        },
    )
    result = analyze_text(parent, label="dkim-sub.eml")
    assert not any(h.name == "DKIM alignment" for h in result.headers)
    assert "DMARC+DKIM" in _reasons(result)
    assert result.verdict is not None
    assert result.verdict.score < 10

    child = _pass_mail(
        "обычный текст",
        {
            "From": "News <news@mail.company.example>",
            "Message-ID": "<m@mail.company.example>",
            "Authentication-Results": (
                "mx.example; spf=pass; dkim=pass header.d=company.example "
                "header.from=mail.company.example; dmarc=pass"
            ),
        },
    )
    quiet = analyze_text(child, label="dkim-parent.eml")
    assert not any(h.name == "DKIM alignment" for h in quiet.headers)
    assert quiet.verdict is not None
    assert quiet.verdict.score < 10

    foreign = _pass_mail(
        "обычный текст",
        {
            "Authentication-Results": (
                "mx.example; spf=pass; dkim=pass header.d=evil.example "
                "header.from=company.example; dmarc=pass"
            )
        },
    )
    bad = analyze_text(foreign, label="dkim-foreign.eml")
    assert any(h.name == "DKIM alignment" and h.severity.value == "high" for h in bad.headers)
    assert "DMARC+DKIM" not in _reasons(bad)

    signed = _pass_mail(
        "обычный текст",
        {"DKIM-Signature": "v=1; a=rsa-sha256; d=mail.company.example; s=sel1;"},
    )
    sig = analyze_text(signed, label="dkim-sig.eml")
    assert not any(h.name == "DKIM alignment" for h in sig.headers)

    signed_bad = _pass_mail(
        "обычный текст",
        {"DKIM-Signature": "v=1; a=rsa-sha256; d=evil.example; s=sel1;"},
    )
    sig_bad = analyze_text(signed_bad, label="dkim-sig-bad.eml")
    assert any("evil.example" in (h.value or "") for h in sig_bad.headers if h.name == "DKIM alignment")


def test_return_path_and_message_id_use_domain_kinship() -> None:
    raw = _pass_mail(
        "Подтвердите получение документов",
        {
            "Return-Path": "<bounce@bounce.company.example>",
            "Message-ID": "<abc@mx.company.example>",
        },
    )
    result = analyze_text(raw, label="kin.eml")
    assert not any(h.name == "Return-Path mismatch" for h in result.headers)
    assert not any(h.name == "Message-ID domain" for h in result.headers)
    assert "DMARC+DKIM" in _reasons(result)
    assert result.verdict is not None
    assert result.verdict.level.value == "benign"

    foreign = _pass_mail(
        "текст",
        {
            "Return-Path": "<bounce@evil.example>",
            "Message-ID": "<abc@other.example>",
        },
    )
    other = analyze_text(foreign, label="kin-foreign.eml")
    assert any(h.name == "Return-Path mismatch" for h in other.headers)
    assert any(h.name == "Message-ID domain" for h in other.headers)


def test_visible_css_is_not_hidden_text() -> None:
    long = "Это обычный видимый абзац письма для клиента компании."
    for style in ("color:#ffffff", "opacity:0.85", "font-size:0.9em"):
        html = f'<div style="{style}">{long}</div>'
        result = analyze_text(
            _pass_mail(html, content_type="text/html; charset=utf-8"),
            label="css.eml",
        )
        assert "hidden_text" not in (result.content_signals or []), style
        assert "DMARC+DKIM" in _reasons(result), style

    hidden = analyze_content_signals("", f'<div style="opacity:0">{long}</div>')
    assert any(s.kind == "hidden_text" for s in hidden)
    style_block = (
        "<style>p { display:none }</style><p>Видимый текст письма без скрытого абзаца.</p>"
    )
    styled = analyze_text(
        _pass_mail(style_block, content_type="text/html; charset=utf-8"),
        label="style.eml",
    )
    assert "hidden_style" in (styled.content_signals or [])
    assert "hidden_text" not in (styled.content_signals or [])
    assert "DMARC+DKIM" in _reasons(styled)


def test_bare_rekvizity_does_not_cancel_pass() -> None:
    assert BEC_RE.search("Направляем реквизиты организации для договора") is None
    quiet = analyze_text(
        _pass_mail("Направляем реквизиты организации для договора"),
        label="rekv.eml",
    )
    assert "bec_payment" not in (quiet.content_signals or [])
    assert "DMARC+DKIM" in _reasons(quiet)
    assert quiet.verdict is not None
    assert quiet.verdict.level.value == "benign"

    hostile = analyze_text(
        _pass_mail("Смените реквизиты и оплатите сегодня только в Telegram"),
        label="rekv-bad.eml",
    )
    assert "bec_payment" in (hostile.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(hostile)
    assert hostile.verdict is not None
    assert hostile.verdict.level.value == "suspicious"


def test_lure_markers_need_their_existing_context() -> None:
    assert QR_LURE_RE.search("Отсканируйте паспорт на входе") is None
    assert QR_LURE_RE.search("Сканируйте QR-код")
    assert MESSENGER_LURE_RE.search("публикуем в Telegram") is None
    assert MESSENGER_LURE_RE.search("пишите в Telegram")
    assert CREDENTIAL_RE.search("Вход в офис со двора") is None
    assert CREDENTIAL_RE.search("Password policy was updated") is None
    assert CREDENTIAL_RE.search("enter your password")

    for body, kind in (
        ("Отсканируйте паспорт на входе в здание.", "qr_lure"),
        ("публикуем в Telegram новости отдела.", "messenger_lure"),
        ("Вход в офис со двора, второй подъезд.", "credential_harvest"),
        ("Password policy was updated last week.", "credential_harvest"),
    ):
        result = analyze_text(_pass_mail(body), label="lure.eml")
        assert kind not in (result.content_signals or []), body
        assert "DMARC+DKIM" in _reasons(result), body

    kept = analyze_text(_pass_mail("Сканируйте QR-код для пропуска."), label="qr.eml")
    assert "qr_lure" in (kept.content_signals or [])
    mess = analyze_text(_pass_mail("пишите в Telegram по этому вопросу."), label="tg.eml")
    assert "messenger_lure" in (mess.content_signals or [])


def test_form_action_zone_is_the_host() -> None:
    html = '<form action="https://files.company.example/q3.zip/download"><input></form>'
    quiet = analyze_text(
        _pass_mail(html, content_type="text/html; charset=utf-8"),
        label="form.eml",
    )
    assert "form_action_suspicious" not in (quiet.content_signals or [])
    assert "DMARC+DKIM" in _reasons(quiet)
    hosts = {i.value for i in quiet.iocs if i.ioc_type.value == "domain"}
    assert "files.company.example" in hosts
    assert "q3.zip" not in hosts

    bad = analyze_text(
        _pass_mail(
            '<form action="https://login.evil.zip/auth"><input></form>',
            content_type="text/html; charset=utf-8",
        ),
        label="form-bad.eml",
    )
    assert "form_action_suspicious" in (bad.content_signals or [])


def test_bare_idn_does_not_block_pass_homoglyph_still_does() -> None:
    hits = {h.kind for h in check_domain("xn--pple-43d.com")}
    assert "homoglyph" in hits

    raw = _pass_mail(
        "Перейдите на почта.рф",
        {
            "From": "Иван <ivan@почта.рф>",
            "Message-ID": "<abc@xn--80a1acny.xn--p1ai>",
        },
    )
    result = analyze_text(raw, label="idn.eml")
    assert not any(h.name == "Message-ID domain" for h in result.headers)
    assert "DMARC+DKIM" in _reasons(result)
    assert result.verdict is not None
    assert result.verdict.score < 10
    emails = {i.value for i in result.iocs if i.ioc_type.value == "email"}
    domains = {i.value for i in result.iocs if i.ioc_type.value == "domain"}
    assert "ivan@почта.рф" in emails
    assert "почта.рф" in domains

    spoof = _pass_mail(
        "hello",
        {
            "From": "Apple <a@xn--pple-43d.com>",
            "Message-ID": "<m@xn--pple-43d.com>",
        },
    )
    blocked = analyze_text(spoof, label="homo.eml")
    assert "DMARC+DKIM" not in _reasons(blocked)
    assert any("Homoglyph" in (c.reason or "") for c in blocked.verdict.breakdown)


def test_unicode_address_and_domain_use_idna() -> None:
    assert "user@почта.рф" in _values("user@почта.рф", "email")
    assert "почта.рф" in _values("смотрите почта.рф", "domain")
    assert "почта.рф" in _values("https://почта.рф/login", "domain")
    assert _values("Иван Петров написал письмо", "domain") == []


def test_pst_compose_keeps_folded_and_repeated_headers() -> None:
    headers = (
        "Received: from mx.dest.test\n"
        " by mx2.dest.test\n"
        "Received: from mx.origin.test\n"
        " by mx.dest.test\n"
        "Authentication-Results: mx.example;\n"
        " spf=pass\n"
        " dkim=pass\n"
        " dmarc=pass\n"
        "DKIM-Signature: v=1; d=company.example;\n"
        " s=one\n"
        "DKIM-Signature: v=1; d=evil.example;\n"
        " s=two\n"
        "From: News <news@company.example>\n"
        "To: user@company.example\n"
        "Subject: hello\n"
        "Message-ID: <m@company.example>\n"
    )
    raw = compose_eml(headers, b"", [("note.bin", b"abc")], plain=b"body", html_body=b"<p>body</p>")
    msg = email.message_from_bytes(raw)
    received = msg.get_all("Received") or []
    assert len(received) == 2
    assert any("mx.origin.test" in item for item in received)
    auth = " ".join(msg.get_all("Authentication-Results") or [])
    assert "spf=pass" in auth and "dkim=pass" in auth and "dmarc=pass" in auth
    signatures = msg.get_all("DKIM-Signature") or []
    assert len(signatures) == 2
    assert any("evil.example" in item for item in signatures)

    fail_headers = headers.replace(" spf=pass", " spf=fail")
    failed = compose_eml(
        fail_headers, b"", [("note.bin", b"abc")], plain=b"body", html_body=b"<p>body</p>"
    )
    failed_msg = email.message_from_bytes(failed)
    assert "spf=fail" in " ".join(failed_msg.get_all("Authentication-Results") or [])


def test_declared_latin1_uses_cyrillic_comparison(tmp_path) -> None:
    phrase = "Смените реквизиты и оплатите сегодня только в Telegram"
    body = phrase.encode("cp1251")
    for charset in ("iso-8859-1", "windows-1252"):
        raw = (
            "From: News <news@company.example>\n"
            "To: user@company.example\n"
            "Subject: pay\n"
            "Message-ID: <m@company.example>\n"
            "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\n"
            "MIME-Version: 1.0\n"
            f"Content-Type: text/plain; charset={charset}\n"
            "\n"
        ).encode("ascii") + body
        path = tmp_path / f"{charset}.eml"
        path.write_bytes(_two_hops().encode("ascii") + raw)
        result = analyze_file(path)
        assert "bec_payment" in (result.content_signals or []), charset
        assert result.verdict is not None
        assert result.verdict.level.value == "suspicious", charset

    bare = (
        "From: News <news@company.example>\n"
        "To: user@company.example\n"
        "Subject: pay\n"
        "Message-ID: <m@company.example>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain\n"
        "\n"
    ).encode("ascii") + body
    path = tmp_path / "nocharset.eml"
    path.write_bytes(bare)
    plain = analyze_file(path)
    assert "реквизит" in (plain.raw_text_preview or "").lower() or "Смените" in (
        plain.raw_text_preview or ""
    )


def test_nameless_pdf_is_inspected(tmp_path) -> None:
    pdf = b"%PDF-1.4\n1 0 obj\n<< /URI (https://pdf-link.example/a) >>\nendobj\n%%EOF\n"
    raw = (
        "From: a@company.example\n"
        "To: user@company.example\n"
        "Subject: invoice\n"
        "Message-ID: <pdf@company.example>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=BOUND\n"
        "\n"
        "--BOUND\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "see attached\n"
        "--BOUND\n"
        "Content-Type: application/pdf\n"
        "Content-Disposition: inline\n"
        "\n"
    ).encode("ascii") + pdf + b"\n--BOUND--\n"
    path = tmp_path / "pdf.eml"
    path.write_bytes(raw)
    result = analyze_file(path)
    assert result.attachments
    assert any("pdf_uri_action" in (a.risk_flags or []) for a in result.attachments)
    assert "/URI" in _reasons(result)


def test_rfc822_headers_are_appended_to_the_body() -> None:
    raw = (
        "From: mailer@company.example\n"
        "To: user@company.example\n"
        "Subject: fwd\n"
        "Message-ID: <outer@company.example>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=BOUND\n"
        "\n"
        "--BOUND\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "begin\n"
        "--BOUND\n"
        "Content-Type: text/rfc822-headers\n"
        "\n"
        "From: Boss <boss@evil.example>\n"
        "Subject: https://evil.example/pay\n"
        "--BOUND--\n"
    )
    result = analyze_text(raw, label="rfc822.eml")
    emails = {i.value for i in result.iocs if i.ioc_type.value == "email"}
    urls = {i.value for i in result.iocs if i.ioc_type.value == "url"}
    assert "boss@evil.example" in emails
    assert any("evil.example/pay" in url for url in urls)


def test_user_microsoft_hosts_are_not_allowlisted() -> None:
    domains, ips = build_allowlist()
    hidden = ("onedrive.live.com", "storage.live.com", "sway.office.com")
    for host in hidden:
        assert not domain_matches(host, domains), host
    for host in ("login.live.com", "outlook.office.com", "live.com", "office.com"):
        assert domain_matches(host, domains), host
    iocs = [
        Ioc("https://onedrive.live.com/edit", IocType.URL),
        Ioc("login.live.com", IocType.DOMAIN),
        Ioc("2001:db8::1", IocType.IPV6),
        Ioc("203.0.113.5", IocType.IPV4),
    ]
    tag_allowlist(iocs, domains, {"2001:db8::1", "203.0.113.5"})
    assert "allowlisted" not in iocs[0].tags
    assert "allowlisted" in iocs[1].tags
    assert "allowlisted" in iocs[2].tags
    assert "allowlisted" in iocs[3].tags


def test_campaign_subject_key_strips_reply_prefix() -> None:
    def mail(subject: str, sender: str) -> str:
        return (
            f"From: {sender}\n"
            "To: user@company.example\n"
            f"Subject: {subject}\n"
            "Message-ID: <unique@company.example>\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "body\n"
        )

    plain = analyze_text(mail("Invoice Q3", "a@one.example"), label="s1.eml")
    replied = analyze_text(mail("Re: Invoice Q3", "b@two.example"), label="s2.eml")
    forwarded = analyze_text(mail("Fw: Invoice Q3", "c@three.example"), label="s3.eml")
    ru = analyze_text(mail("Отв: Invoice Q3", "d@four.example"), label="s4.eml")
    fwd_ru = analyze_text(mail("Пересл: Invoice Q3", "e@five.example"), label="s5.eml")
    assert campaign_key_for(plain) == "subj:invoice q3"
    assert campaign_key_for(replied) == campaign_key_for(plain)
    assert campaign_key_for(forwarded) == campaign_key_for(plain)
    assert campaign_key_for(ru) == campaign_key_for(plain)
    assert campaign_key_for(fwd_ru) == campaign_key_for(plain)
    assert campaign_key_for(plain) in campaign_divergence_keys([plain, replied])
