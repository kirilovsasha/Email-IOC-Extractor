"""Tenth-pass fixes: quieter phrases, encodings, allowlist, subject key."""

from __future__ import annotations

from reliquary.core.allowlist import build_allowlist, domain_matches, tag_allowlist
from reliquary.core.attachment_inspector import decode_payload_text
from reliquary.core.content_signals import (
    BEC_RE,
    CREDENTIAL_RE,
    DANGEROUS_SCHEME_RE,
    HIDDEN_STYLE_RE,
)
from reliquary.core.ioc_extractor import extract_iocs
from reliquary.core.lookalike import check_display_name_spoof, check_domain
from reliquary.core.models import Ioc, IocType
from reliquary.core.pipeline import (
    analyze_file,
    analyze_text,
    campaign_divergence_keys,
    campaign_key_for,
)


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


def _benign(body: str, extra: dict[str, str] | None = None, *, content_type: str = "text/plain; charset=utf-8"):
    result = analyze_text(_pass_mail(body, extra, content_type=content_type), label="q.eml")
    assert "DMARC+DKIM" in _reasons(result)
    assert result.verdict is not None
    assert result.verdict.level.value == "benign", (body, result.verdict.score, _reasons(result))
    return result


def test_bare_ceo_urgent_and_ordinary_payment_talk_stay_quiet() -> None:
    quiet = (
        "CEO urgent: the all-hands is at 3",
        "Оплата сегодня отменена",
        "Оплата сегодня прошла успешно",
        "wire transfer of the payment plan",
        "updated payment instructions are in the handbook",
        "изменить платежный день",
    )
    for phrase in quiet:
        assert BEC_RE.search(phrase) is None, phrase
        result = _benign(phrase)
        assert "bec_payment" not in (result.content_signals or []), phrase

    kept = (
        "wire transfer of funds",
        "CEO urgent wire transfer",
        "оплатите сегодня",
        "updated payment instructions",
        "изменить платёжные реквизиты",
    )
    for phrase in kept:
        assert BEC_RE.search(phrase), phrase

    assert BEC_RE.search("wire transfer of the files") is None
    assert BEC_RE.search("Оплата сегодня не требуется") is None
    assert BEC_RE.search("Оплата сегодня уже получена") is None
    hostile = analyze_text(_pass_mail("оплатите сегодня"), label="pay.eml")
    assert "bec_payment" in (hostile.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(hostile)


def test_urgent_oplatite_and_oplata_are_bec() -> None:
    phrases = ("Срочно оплатите этот счет", "срочно оплата счета")
    reference = analyze_text(_pass_mail("оплатите сегодня"), label="today.eml")
    assert reference.verdict is not None
    for phrase in phrases:
        assert BEC_RE.search(phrase), phrase
        result = analyze_text(_pass_mail(phrase), label="urgent.eml")
        assert "bec_payment" in (result.content_signals or []), phrase
        assert "DMARC+DKIM" not in _reasons(result), phrase
        assert result.verdict is not None
        assert result.verdict.level.value == reference.verdict.level.value, phrase
        assert result.verdict.score == reference.verdict.score, phrase


def test_verify_account_tail_and_password_policy_are_not_harvest() -> None:
    quiet = (
        "Please verify account status on the invoice",
        "Please verify account balance",
        "Please verify account details",
        "Please update your password policy",
        "Please verify account number on the invoice",
        "Please change the password policy",
    )
    for phrase in quiet:
        assert CREDENTIAL_RE.search(phrase) is None, phrase
        result = _benign(phrase)
        assert "credential_harvest" not in (result.content_signals or []), phrase

    assert CREDENTIAL_RE.search("Please enter your password")
    assert CREDENTIAL_RE.search("update your password")
    assert CREDENTIAL_RE.search("Please update your password policy") is None
    kept = analyze_text(_pass_mail("Please enter your password"), label="cred.eml")
    assert "credential_harvest" in (kept.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(kept)
    assert kept.verdict is not None
    assert kept.verdict.level.value == "unknown"
    assert kept.verdict.score == 14


def test_file_colon_prose_is_not_a_scheme_file_url_is() -> None:
    assert DANGEROUS_SCHEME_RE.search("See the file: notes.txt for the agenda") is None
    assert DANGEROUS_SCHEME_RE.search("search-ms:query=invoice")
    assert DANGEROUS_SCHEME_RE.search("file://files.example/invoice.html")
    quiet = _benign("See the file: notes.txt for the agenda")
    assert "dangerous_scheme" not in (quiet.content_signals or [])

    urls = [
        i.value
        for i in extract_iocs("Open file://files.example/invoice.html and hxxp://evil.example/a")
        if i.ioc_type.value == "url"
    ]
    assert any(value.startswith("file://files.example/") for value in urls)
    assert any("evil.example" in value for value in urls)

    scheme = analyze_text(_pass_mail("search-ms:query=invoice"), label="ms.eml")
    assert "dangerous_scheme" in (scheme.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(scheme)
    filed = analyze_text(_pass_mail("Open file://files.example/invoice.html"), label="file.eml")
    assert "dangerous_scheme" in (filed.content_signals or [])
    assert any(
        i.value.startswith("file://files.example/")
        for i in filed.iocs
        if i.ioc_type.value == "url"
    )


def test_product_names_are_not_display_spoof() -> None:
    quiet = (
        "Microsoft Office <it@company.example>",
        "Microsoft Excel <it@company.example>",
        "Microsoft Outlook <it@company.example>",
        "Google Chrome <bot@company.example>",
        "Яндекс Браузер <news@company.example>",
        "Сбер Бизнес <shop@company.example>",
        "Microsoft Teams <it@company.example>",
        "Google Docs <bot@company.example>",
    )
    for header in quiet:
        assert check_display_name_spoof(header) == [], header
        result = _benign("график", {"From": header})
        assert result.verdict is not None

    for header in (
        "Microsoft <evil@evil.example>",
        "ЦБ <evil@evil.example>",
        "Outlook <evil@evil.example>",
    ):
        spoof = check_display_name_spoof(header)
        assert spoof and spoof[0].kind == "display_spoof", header


def test_multi_label_zone_compares_the_label() -> None:
    assert any(h.kind == "levenshtein" for h in check_domain("microsft.co.uk"))
    assert any(h.kind == "levenshtein" for h in check_domain("microsft.com"))
    assert any(h.kind == "levenshtein" for h in check_domain("microsft.de"))
    uk = check_domain("xn--pple-43d.co.uk")
    assert any(h.kind == "homoglyph" for h in uk)
    com = check_domain("xn--pple-43d.com")
    assert any(h.kind == "homoglyph" for h in com)
    assert not any(h.kind == "homoglyph" for h in check_domain("microsft.com"))


def test_vendor_country_zone_and_longer_label_are_not_brand_spoof() -> None:
    domains, _ips = build_allowlist()
    quiet = (
        "google.de",
        "yandex.com",
        "yandex.by",
        "amazon.de",
        "googletagmanager.com",
        "google-analytics.com",
        "githubassets.com",
    )
    for host in quiet:
        hits = check_domain(host)
        assert not any(h.kind == "brand_spoof" for h in hits), (host, [h.kind for h in hits])
        assert not domain_matches(host, domains), host
        result = _benign(f"https://{host}/status")
        assert result.verdict is not None

    assert any(h.kind == "levenshtein" for h in check_domain("microsft.com"))
    assert any(h.kind == "brand_spoof" for h in check_domain("microsoft-login.top"))
    assert any(h.kind == "brand_spoof" for h in check_domain("microsoft.top"))
    blocked = analyze_text(_pass_mail("https://microsft.com/status"), label="typo.eml")
    assert "DMARC+DKIM" not in _reasons(blocked)
    foreign = analyze_text(_pass_mail("https://microsoft-login.top/status"), label="suffix.eml")
    assert "DMARC+DKIM" not in _reasons(foreign)


def test_zero_fraction_and_either_overflow_order_are_hidden() -> None:
    long = "Это обычный видимый абзац письма для клиента компании и отдела."
    visible = (
        "font-size:0.85px",
        "opacity:0.85",
        "font-size:0.9em",
        "opacity:0.01",
        "height:0.5;overflow:hidden",
    )
    for style in visible:
        assert HIDDEN_STYLE_RE.search(style) is None, style
        html = f'<div style="{style}">{long}</div>'
        result = _benign(html, content_type="text/html; charset=utf-8")
        assert "hidden_text" not in (result.content_signals or []), style

    hidden_styles = (
        "font-size:0.0px",
        "opacity:0.0",
        "font-size:0",
        "height:0;overflow:hidden",
        "overflow:hidden;height:0",
    )
    for style in hidden_styles:
        assert HIDDEN_STYLE_RE.search(style), style
        html = f'<div style="{style}">{long}</div>'
        result = analyze_text(
            _pass_mail(html, content_type="text/html; charset=utf-8"),
            label="hide.eml",
        )
        assert "hidden_text" in (result.content_signals or []), style
        assert "DMARC+DKIM" not in _reasons(result), style


def test_koi8_u_and_mac_cyrillic_stay_in_the_cyrillic_comparison(tmp_path) -> None:
    phrase = "Смените реквизиты и оплатите сегодня только в Telegram"
    cp = phrase.encode("cp1251")
    koi_u = phrase.encode("koi8-u")
    mac = phrase.encode("mac-cyrillic")
    assert decode_payload_text(koi_u, "koi8-u") == phrase
    assert decode_payload_text(mac, "mac-cyrillic") == phrase
    assert "реквизит" in decode_payload_text(cp, "koi8-u")
    assert "реквизит" in decode_payload_text(cp, "mac-cyrillic")

    def mail(body: bytes, charset: str) -> bytes:
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
        return _two_hops().encode("ascii") + raw

    cases = (
        ("koi8-u", cp),
        ("mac-cyrillic", cp),
        ("koi8-u", koi_u),
        ("mac-cyrillic", mac),
    )
    for charset, body in cases:
        path = tmp_path / f"{charset.replace('-', '_')}-{len(body)}.eml"
        path.write_bytes(mail(body, charset))
        result = analyze_file(path)
        assert "bec_payment" in (result.content_signals or []), charset
        assert result.verdict is not None
        assert result.verdict.level.value == "suspicious", (charset, result.verdict.score)


def test_csv_text_and_amp_html_join_the_body() -> None:
    page = "Смените реквизиты\nhttps://evil.example/pay\n"
    html_page = f"<html><body>{page}</body></html>\n"

    def mixed(parts: list[str]) -> str:
        raw = (
            "From: News <news@company.example>\n"
            "To: user@company.example\n"
            "Subject: pay\n"
            "Message-ID: <m@company.example>\n"
            "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\n"
            "MIME-Version: 1.0\n"
            "Content-Type: multipart/mixed; boundary=BOUND\n"
            "\n"
            "--BOUND\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "см. вложение\n"
            + "".join(parts)
            + "--BOUND--\n"
        )
        return _two_hops() + raw

    def named(filename: str, ctype: str, payload: str) -> str:
        return (
            "--BOUND\n"
            f"Content-Type: {ctype}\n"
            f'Content-Disposition: attachment; filename="{filename}"\n'
            "\n"
            f"{payload}"
        )

    def unnamed(ctype: str, payload: str) -> str:
        return f"--BOUND\nContent-Type: {ctype}\n\n{payload}"

    plain = analyze_text(
        mixed([named("a.txt", "text/plain; charset=utf-8", page)]),
        label="txt.eml",
    )
    csv = analyze_text(
        mixed([named("a.csv", "text/csv; charset=utf-8", page)]),
        label="csv.eml",
    )
    html = analyze_text(
        mixed([unnamed("text/html; charset=utf-8", html_page)]),
        label="html.eml",
    )
    amp = analyze_text(
        mixed([unnamed("text/x-amp-html; charset=utf-8", html_page)]),
        label="amp.eml",
    )
    assert plain.verdict is not None and html.verdict is not None
    for result, name, reference in (
        (csv, "a.csv", plain),
        (amp, "text/x-amp-html", html),
    ):
        assert result.verdict is not None
        assert "bec_payment" in (result.content_signals or []), name
        assert any("evil.example/pay" in i.value for i in result.iocs if i.ioc_type.value == "url"), name
        assert result.verdict.level.value == reference.verdict.level.value, name
        assert result.verdict.score == reference.verdict.score, name
    assert any(a.filename == "a.csv" for a in csv.attachments)


def test_to_and_cc_reach_the_ioc_table() -> None:
    result = analyze_text(
        _pass_mail(
            "hello",
            {
                "To": "Evil <evil@evil.example>",
                "Cc": "Other <other@elsewhere.example>",
            },
        ),
        label="cc.eml",
    )
    emails = {i.value for i in result.iocs if i.ioc_type.value == "email"}
    domains = {i.value for i in result.iocs if i.ioc_type.value == "domain"}
    assert "news@company.example" in emails
    assert "evil@evil.example" in emails
    assert "other@elsewhere.example" in emails
    assert "evil.example" in domains
    assert "elsewhere.example" in domains
    assert "company.example" in domains


def test_chat_onenote_and_datastudio_stay_visible() -> None:
    domains, ips = build_allowlist()
    hidden = (
        "chat.google.com",
        "datastudio.google.com",
        "onenote.office.com",
        "onenote.microsoft.com",
        "whiteboard.office.com",
    )
    for host in hidden:
        assert not domain_matches(host, domains), host
    for host in ("mail.google.com", "accounts.google.com", "outlook.office.com"):
        assert domain_matches(host, domains), host

    iocs = [Ioc(f"https://{host}/a", IocType.URL) for host in hidden]
    iocs.append(Ioc("https://evil.example/a", IocType.URL))
    iocs.append(Ioc("https://mail.google.com/mail", IocType.URL))
    iocs.append(Ioc("https://accounts.google.com/signin", IocType.URL))
    iocs.append(Ioc("https://outlook.office.com/mail", IocType.URL))
    tag_allowlist(iocs, domains, ips)
    for ioc in iocs[: len(hidden) + 1]:
        assert "allowlisted" not in ioc.tags, ioc.value
    for ioc in iocs[len(hidden) + 1 :]:
        assert "allowlisted" in ioc.tags, ioc.value


def test_gateway_mark_before_re_is_an_orphan_reply() -> None:
    def mail(subject: str, *, reply: bool) -> str:
        extra = {"Subject": subject}
        if reply:
            extra["In-Reply-To"] = "<root@company.example>"
        return _pass_mail("body", extra)

    for subject in (
        "Re: Invoice",
        "Re[2]: Invoice",
        "[EXTERNAL] Re: Invoice",
        "[EXT] Re: Invoice",
        "External: Re: Invoice",
    ):
        orphan = analyze_text(mail(subject, reply=False), label="orphan.eml")
        assert any(h.name == "Orphan reply" for h in orphan.headers), subject
        assert "DMARC+DKIM" not in _reasons(orphan), subject
        assert orphan.verdict is not None
        assert orphan.verdict.level.value == "unknown", subject
        assert orphan.verdict.score == 12, subject


def test_short_gateway_and_numbered_forward_share_the_subject_key() -> None:
    plain = analyze_text(_pass_mail("body", {"Subject": "Invoice Q3"}), label="s0.eml")
    assert campaign_key_for(plain) == "subj:invoice q3"
    keyed = [plain]
    for subject in (
        "[EXT] Invoice Q3",
        "[External Email] Invoice Q3",
        "[Внешняя почта] Invoice Q3",
        "SPAM: Invoice Q3",
        "Fw[2]: Invoice Q3",
        "Fwd[2]: Invoice Q3",
    ):
        same = analyze_text(
            _pass_mail(
                "body",
                {"Subject": subject, "From": "Other <other@elsewhere.example>"},
            ),
            label="s1.eml",
        )
        assert campaign_key_for(same) == "subj:invoice q3", subject
        keyed.append(same)
    assert "subj:invoice q3" in campaign_divergence_keys(keyed)

    def thread_points(result) -> list[int]:
        return [
            c.points
            for c in result.verdict.breakdown
            if "существующем треде" in (c.reason or "")
        ]

    bare = analyze_text(
        _pass_mail(
            "body",
            {"Subject": "Re[2]: Invoice Q3", "In-Reply-To": "<root@company.example>"},
        ),
        label="t0.eml",
    )
    for subject in ("Fw[2]: Invoice Q3", "[EXT] Re: Invoice Q3", "Fwd[2]: Invoice Q3"):
        gated = analyze_text(
            _pass_mail(
                "body",
                {"Subject": subject, "In-Reply-To": "<root@company.example>"},
            ),
            label="t1.eml",
        )
        assert thread_points(gated) == thread_points(bare) == [-4], subject
