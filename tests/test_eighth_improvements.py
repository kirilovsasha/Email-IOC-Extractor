"""Eighth-pass fixes: quieter phrases, named plain text, allowlist, ARC, thread key."""

from __future__ import annotations

from reliquary.core.allowlist import build_allowlist, domain_matches, tag_allowlist
from reliquary.core.attachment_inspector import decode_payload_text
from reliquary.core.content_signals import (
    BEC_RE,
    CLICKFIX_RE,
    CLOUD_LURE_RE,
    CREDENTIAL_RE,
    HIDDEN_STYLE_RE,
    analyze_content_signals,
)
from reliquary.core.lookalike import check_display_name_spoof, check_domain
from reliquary.core.models import Ioc, IocType, MailIdentity
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


def test_english_bec_and_iban_fragment_need_a_payment_object() -> None:
    quiet = (
        "The new details will be sent tomorrow",
        "payment instructions are in the handbook",
        "wire transfer of knowledge",
        "change of banking hours",
        "bank transfer receipt from last month",
        "Room BY20 ABCD",
        "by20 code",
        "Оплата сегодня не требуется",
        "Реквизиты на карте проезда",
        "Срочный перевод документов",
    )
    for phrase in quiet:
        assert BEC_RE.search(phrase) is None, phrase
        result = _benign(phrase)
        assert "bec_payment" not in (result.content_signals or []), phrase

    kept = (
        "new bank details",
        "new payment details",
        "updated payment instructions",
        "CEO urgent wire transfer",
        "оплатите сегодня по новым реквизитам",
        "перевод на карту",
        "срочно переведите на карту",
        "реквизиты на карту",
        "Смените реквизиты",
    )
    for phrase in kept:
        assert BEC_RE.search(phrase), phrase

    assert BEC_RE.search("updated payment details") is None
    assert "bec_payment" not in (_benign("updated payment details").content_signals or [])
    assert BEC_RE.search("BY20NBRB30120000000000000000") is None
    tokens = analyze_text(
        _pass_mail("Смените реквизиты BY20NBRB30120000000000000000"),
        label="iban.eml",
    )
    assert "payment_tokens" in (tokens.content_signals or [])
    assert tokens.verdict is not None
    assert tokens.verdict.level.value == "suspicious"

    hostile = analyze_text(
        _pass_mail("Смените реквизиты и оплатите сегодня только в Telegram"),
        label="bec.eml",
    )
    assert "bec_payment" in (hostile.content_signals or [])
    assert hostile.verdict is not None
    assert hostile.verdict.level.value == "suspicious"


def test_bare_password_words_do_not_cancel_pass() -> None:
    quiet = (
        "The password for the guest wifi is on the board",
        "passwd file lives in /etc",
        "passcode for the door is 1234",
        "outlook web is slow today",
        "account verify step is optional",
        "подтвердите аккаунт в реестре гостей",
        "Password policy was updated",
    )
    for phrase in quiet:
        assert CREDENTIAL_RE.search(phrase) is None, phrase
        result = _benign(phrase)
        assert "credential_harvest" not in (result.content_signals or []), phrase

    assert CREDENTIAL_RE.search("Please enter your password")
    assert CREDENTIAL_RE.search("Password policy was updated") is None
    kept = analyze_text(_pass_mail("Please enter your password"), label="cred.eml")
    assert "credential_harvest" in (kept.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(kept)


def test_product_name_and_hyphen_are_not_display_spoof() -> None:
    quiet = (
        "Microsoft Teams <it@company.example>",
        "Google Calendar <bot@company.example>",
        "Яндекс Еда <news@company.example>",
        "Outlook notification <noreply@company.example>",
        "Альфа-тест <qa@company.example>",
        "Газпром нефть <press@gazprom-neft.ru>",
        "Сбер Маркет <shop@sbermarket.ru>",
        "Нацбанк <press@nbrb.by>",
        "Сбербанк <news@sberbank.ru>",
    )
    for header in quiet:
        assert check_display_name_spoof(header) == [], header
        result = _benign("график", {"From": header})
        assert result.verdict is not None

    spoof = check_display_name_spoof("ЦБ <evil@evil.example>")
    assert spoof and spoof[0].kind == "display_spoof"
    alfa = check_display_name_spoof("Альфа-Банк <evil@evil.example>")
    assert alfa and alfa[0].kind == "display_spoof"
    bare = check_display_name_spoof("Microsoft <evil@evil.example>")
    assert bare and bare[0].kind == "display_spoof"


def test_percent_unit_is_not_hidden_text() -> None:
    long = "Это обычный видимый абзац письма для клиента компании и отдела."
    for style in ("font-size:0%", "opacity:0%"):
        assert HIDDEN_STYLE_RE.search(style) is None, style
        html = f'<div style="{style}">{long}</div>'
        result = _benign(html, content_type="text/html; charset=utf-8")
        assert "hidden_text" not in (result.content_signals or []), style

    assert HIDDEN_STYLE_RE.search("font-size:0")
    assert HIDDEN_STYLE_RE.search("opacity:0")
    assert HIDDEN_STYLE_RE.search("opacity:0.85") is None
    hidden = analyze_content_signals("", f'<div style="font-size:0">{long}</div>')
    assert any(s.kind == "hidden_text" for s in hidden)


def test_bare_cloud_phrase_is_not_a_lure() -> None:
    for phrase in ("файл в облаке обновлён", "Документ в облаке для команды"):
        assert CLOUD_LURE_RE.search(phrase) is None, phrase
        result = _benign(phrase)
        assert "cloud_lure" not in (result.content_signals or []), phrase

    assert CLOUD_LURE_RE.search("https://drive.google.com/file/abc")
    assert CLOUD_LURE_RE.search("файл на яндекс диске")
    lure = analyze_text(_pass_mail("файл на яндекс диске"), label="cloud.eml")
    assert "cloud_lure" in (lure.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(lure)


def test_vendor_infrastructure_hosts_are_not_brand_spoof() -> None:
    domains, _ips = build_allowlist()
    quiet = (
        "storage.googleapis.com",
        "lh3.googleusercontent.com",
        "raw.githubusercontent.com",
        "cvws.icloud-content.com",
    )
    for host in quiet:
        hits = check_domain(host)
        assert not any(h.kind == "brand_spoof" for h in hits), host
        assert not domain_matches(host, domains), host
        result = _benign(f"https://{host}/object")
        assert result.verdict is not None

    assert any(h.kind == "levenshtein" for h in check_domain("microsft.com"))
    assert any(h.kind == "brand_spoof" for h in check_domain("microsoft-login.top"))
    blocked = analyze_text(_pass_mail("https://microsft.com/status"), label="typo.eml")
    assert "DMARC+DKIM" not in _reasons(blocked)


def test_bare_command_phrases_are_not_clickfix() -> None:
    for phrase in ("выполните команду в регламенте охраны", "нажмите win в лотерее отдела"):
        assert CLICKFIX_RE.search(phrase) is None, phrase
        result = _benign(phrase)
        assert "clickfix" not in (result.content_signals or []), phrase

    assert CLICKFIX_RE.search("Нажмите Win+R")
    assert CLICKFIX_RE.search("powershell -enc QQ==")
    kept = analyze_text(_pass_mail("Нажмите Win+R"), label="click.eml")
    assert "clickfix" in (kept.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(kept)


def test_declared_single_byte_cyrillic_is_compared(tmp_path) -> None:
    phrase = "Смените реквизиты и оплатите сегодня только в Telegram"
    koi = phrase.encode("koi8-r")
    cp = phrase.encode("cp1251")
    iso = phrase.encode("iso-8859-5")
    oem = phrase.encode("cp866")
    assert "реквизит" in decode_payload_text(koi, "windows-1251")
    assert "реквизит" in decode_payload_text(cp, "iso-8859-5")
    assert "реквизит" in decode_payload_text(cp, "cp866")
    assert decode_payload_text(iso, "iso-8859-5") == phrase
    assert decode_payload_text(oem, "cp866") == phrase

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
        ("windows-1251", koi),
        ("iso-8859-5", cp),
        ("cp866", cp),
        ("iso-8859-5", iso),
        ("cp866", oem),
    )
    for charset, body in cases:
        path = tmp_path / f"{charset}-{len(body)}.eml"
        path.write_bytes(mail(body, charset))
        result = analyze_file(path)
        assert "bec_payment" in (result.content_signals or []), charset
        assert result.verdict is not None
        assert result.verdict.level.value == "suspicious", (charset, result.verdict.score)


def test_named_text_plain_is_body_text() -> None:
    body = (
        "Смените реквизиты и оплатите сегодня только в Telegram\n"
        "https://evil.example/pay\n"
    )
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
        'Content-Disposition: inline; filename="body.txt"\n'
        "\n"
        f"{body}"
        "--BOUND--\n"
    )
    result = analyze_text(_two_hops() + raw, label="plain.eml")
    assert any(a.filename == "body.txt" and a.sha256 for a in result.attachments)
    assert "bec_payment" in (result.content_signals or [])
    assert any("evil.example/pay" in i.value for i in result.iocs if i.ioc_type.value == "url")
    assert result.verdict is not None
    assert result.verdict.level.value == "suspicious"


def test_user_document_hosts_and_github_release_stay_visible() -> None:
    domains, ips = build_allowlist()
    hidden = (
        "sheets.google.com",
        "slides.google.com",
        "keep.google.com",
        "groups.google.com",
        "drive.usercontent.google.com",
        "excel.office.com",
        "word.office.com",
        "powerpoint.office.com",
        "onedrive.office.com",
        "firebasestorage.googleapis.com",
        "photos.icloud.com",
        "onedrive.microsoft.com",
        "forms.microsoft.com",
        "sway.microsoft.com",
        "account.z13.web.core.windows.net",
    )
    for host in hidden:
        assert not domain_matches(host, domains), host
    for host in ("login.live.com", "outlook.office.com", "accounts.google.com"):
        assert domain_matches(host, domains), host

    release = "https://github.com/user/repo/releases/download/v1/invoice.exe"
    iocs = [Ioc(f"https://{host}/a", IocType.URL) for host in hidden]
    iocs.append(Ioc(release, IocType.URL))
    iocs.append(Ioc("https://evil.example/a", IocType.URL))
    iocs.append(Ioc("https://login.live.com/login", IocType.URL))
    iocs.append(Ioc("https://github.com/user/repo", IocType.URL))
    tag_allowlist(iocs, domains, ips)
    for ioc in iocs[: len(hidden) + 2]:
        assert "allowlisted" not in ioc.tags, ioc.value
    assert "allowlisted" in iocs[-2].tags
    assert "allowlisted" in iocs[-1].tags


def test_arc_seal_cv_fail_counts_as_arc_fail() -> None:
    quiet = analyze_text(
        _pass_mail(
            "обычный текст",
            {
                "ARC-Seal": "i=1; cv=pass",
                "ARC-Authentication-Results": "mx.example; spf=pass; dkim=pass; dmarc=pass",
            },
        ),
        label="arc-ok.eml",
    )
    assert quiet.verdict is not None
    assert quiet.verdict.level.value == "benign"
    assert not any(h.name == "ARC result" and h.value == "fail" for h in quiet.headers)

    failed = analyze_text(
        _pass_mail(
            "обычный текст",
            {
                "ARC-Seal": "i=1; cv=fail",
                "ARC-Authentication-Results": "mx.example; spf=pass; dkim=pass; dmarc=pass",
            },
        ),
        label="arc-cv.eml",
    )
    assert any(h.name == "ARC result" and h.value == "fail" for h in failed.headers)
    assert failed.verdict is not None
    assert failed.verdict.level.value == "suspicious"

    dkim = analyze_text(
        _pass_mail(
            "обычный текст",
            {
                "ARC-Authentication-Results": "mx.example; spf=pass; dkim=fail; dmarc=pass",
            },
        ),
        label="arc-dkim.eml",
    )
    assert dkim.verdict is not None
    assert dkim.verdict.level.value == "suspicious"
    assert failed.verdict.score == dkim.verdict.score


def test_gateway_prefix_and_thread_brackets_share_a_key() -> None:
    plain = analyze_text(_pass_mail("body", {"Subject": "Invoice Q3"}), label="s0.eml")
    assert campaign_key_for(plain) == "subj:invoice q3"
    keyed = [plain]
    for subject in (
        "[EXTERNAL] Invoice Q3",
        "[Внешнее] Invoice Q3",
        "ВНЕШНЯЯ ПОЧТА: Invoice Q3",
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
            {"Subject": "Re: Invoice Q3", "In-Reply-To": "<root@company.example>"},
        ),
        label="t0.eml",
    )
    gated = analyze_text(
        _pass_mail(
            "body",
            {"Subject": "[EXTERNAL] Re: Invoice Q3", "In-Reply-To": "<root@company.example>"},
        ),
        label="t1.eml",
    )
    assert thread_points(bare) == [-4]
    assert thread_points(gated) == [-4]

    with_brackets = MailIdentity(references="<root@company.example>")
    without = MailIdentity(in_reply_to="root@company.example")
    assert with_brackets.thread_root_id() == without.thread_root_id() == "root@company.example"
    left = analyze_text(
        _pass_mail("body", {"Subject": "Invoice Q3", "References": "<root@company.example>"}),
        label="r1.eml",
    )
    right = analyze_text(
        _pass_mail("body", {"Subject": "Other", "In-Reply-To": "root@company.example"}),
        label="r2.eml",
    )
    assert campaign_key_for(left) == campaign_key_for(right) == "thread:root@company.example"
