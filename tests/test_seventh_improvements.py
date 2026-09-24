"""Seventh-pass fixes: quieter verdict, nameless parts, IOC, allowlist, subject key."""

from __future__ import annotations

import zipfile
from io import BytesIO

from reliquary.core.allowlist import build_allowlist, domain_matches, tag_allowlist
from reliquary.core.attachment_inspector import decode_payload_text
from reliquary.core.content_signals import BEC_RE, CALLBACK_RE, CREDENTIAL_RE, analyze_content_signals
from reliquary.core.ioc_extractor import extract_iocs
from reliquary.core.lookalike import check_display_name_spoof, check_domain
from reliquary.core.models import Ioc, IocType
from reliquary.core.pipeline import analyze_file, analyze_text, campaign_key_for


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


def test_job_title_and_bare_unp_do_not_cancel_pass() -> None:
    quiet = (
        "Главбух отправила график отпусков",
        "Казначей на совещании",
        "Генеральный директор утвердил график",
        "Финансовый директор в отпуске",
        "Не звоните после 18:00",
        "УНП 100582333 указан в договоре",
        "Оплата через ЕРИП по желанию",
    )
    for phrase in quiet:
        assert BEC_RE.search(phrase) is None, phrase
        result = analyze_text(_pass_mail(phrase), label="bec.eml")
        assert "bec_payment" not in (result.content_signals or []), phrase
        assert "DMARC+DKIM" in _reasons(result), phrase
        assert result.verdict is not None
        assert result.verdict.level.value == "benign", phrase

    hostile = analyze_text(
        _pass_mail("Смените реквизиты и оплатите сегодня только в Telegram"),
        label="bec-bad.eml",
    )
    assert "bec_payment" in (hostile.content_signals or [])
    assert hostile.verdict is not None
    assert hostile.verdict.level.value == "suspicious"


def test_bare_callback_does_not_cancel_pass() -> None:
    assert CALLBACK_RE.search("Перезвоните мне завтра") is None
    assert CALLBACK_RE.search("Позвоните мне по номеру 123") is None
    assert CALLBACK_RE.search("call me back tomorrow") is None
    for phrase in ("Перезвоните мне завтра", "Позвоните мне по номеру 123"):
        result = analyze_text(_pass_mail(phrase), label="call.eml")
        assert "bec_callback" not in (result.content_signals or []), phrase
        assert "DMARC+DKIM" in _reasons(result), phrase
        assert result.verdict is not None
        assert result.verdict.level.value == "benign", phrase

    kept = analyze_text(
        _pass_mail("Не отвечайте на это письмо, перезвоните"),
        label="call-bad.eml",
    )
    assert "bec_callback" in (kept.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(kept)


def test_credential_words_and_login_host_do_not_cancel_pass() -> None:
    quiet = (
        "Войти в здание со двора",
        "Пароль от wifi",
        "Please login when you arrive",
        "sign in to the lobby",
        "webmail is down",
        "owa calendar was migrated",
        "See https://login.company.example/home",
    )
    for phrase in quiet:
        assert CREDENTIAL_RE.search(phrase) is None, phrase
        result = analyze_text(_pass_mail(phrase), label="cred.eml")
        assert "credential_harvest" not in (result.content_signals or []), phrase
        assert "DMARC+DKIM" in _reasons(result), phrase
        assert result.verdict is not None
        assert result.verdict.level.value == "benign", phrase

    assert CREDENTIAL_RE.search("enter your password")
    assert CREDENTIAL_RE.search("Please change your password")
    assert CREDENTIAL_RE.search("Смените пароль от почты")
    kept = analyze_text(_pass_mail("Please enter your password"), label="cred-bad.eml")
    assert "credential_harvest" in (kept.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(kept)


def test_auth_token_in_a_sentence_does_not_cancel_pass() -> None:
    quiet = analyze_text(
        _pass_mail("Отчёт готов. Для справки spf=pass на шлюзе."),
        label="spf.eml",
    )
    assert "fake_auth_results" not in (quiet.content_signals or [])
    assert "DMARC+DKIM" in _reasons(quiet)
    assert quiet.verdict is not None
    assert quiet.verdict.level.value == "benign"

    drawn = analyze_text(
        _pass_mail("Authentication-Results: mx; spf=pass\nОбычный текст."),
        label="spf-bad.eml",
    )
    assert "fake_auth_results" in (drawn.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(drawn)


def test_allowlisted_and_vendor_names_are_not_brand_spoof() -> None:
    quiet_hosts = (
        "amazonaws.com",
        "office365.com",
        "login.microsoftonline.com",
        "googlemail.com",
        "facebookmail.com",
        "mail.com",
    )
    for host in quiet_hosts:
        hits = check_domain(host)
        assert not any(h.kind == "brand_spoof" for h in hits), host
        assert not any(h.brand == "gmail.com" for h in hits), host
        result = analyze_text(_pass_mail(f"https://{host}/status"), label="brand.eml")
        assert "DMARC+DKIM" in _reasons(result), host
        assert result.verdict is not None
        assert result.verdict.level.value == "benign", (host, result.verdict.score, _reasons(result))

    assert any(h.kind == "levenshtein" for h in check_domain("microsft.com"))
    assert any(h.kind == "brand_spoof" for h in check_domain("microsoft-login.top"))
    blocked = analyze_text(_pass_mail("https://microsft.com/status"), label="typo.eml")
    assert "DMARC+DKIM" not in _reasons(blocked)
    foreign = analyze_text(_pass_mail("https://microsoft-login.top/status"), label="suffix.eml")
    assert "DMARC+DKIM" not in _reasons(foreign)


def test_nacbank_word_does_not_match_cb() -> None:
    own = check_display_name_spoof("Нацбанк <press@nbrb.by>")
    assert own == []
    kz = check_display_name_spoof("Нацбанк Казахстана <press@nationalbank.kz>")
    assert kz == []
    sber = check_display_name_spoof("Сбербанк <news@sberbank.ru>")
    assert sber == []
    spoof = check_display_name_spoof("ЦБ <evil@evil.example>")
    assert spoof and spoof[0].kind == "display_spoof"

    for header in (
        "Нацбанк <press@nbrb.by>",
        "Нацбанк Казахстана <press@nationalbank.kz>",
    ):
        result = analyze_text(
            _pass_mail("график", {"From": header, "Message-ID": "<m@nbrb.by>"}),
            label="bank.eml",
        )
        assert "DMARC+DKIM" in _reasons(result), header
        assert result.verdict is not None
        assert result.verdict.level.value == "benign", header


def test_bare_idn_adds_no_score_without_homoglyph() -> None:
    raw = (
        _two_hops()
        + _eml(
            {
                "From": "News <news@company.example>",
                "To": "user@company.example",
                "Subject": "hello",
                "Message-ID": "<m@company.example>",
            },
            "Перейдите на почта.рф",
        )
    )
    result = analyze_text(raw, label="idn.eml")
    assert "IDN" not in _reasons(result)
    assert result.verdict is not None
    assert result.verdict.score < 10
    assert not any(h.kind == "homoglyph" for h in check_domain("microsft.com"))
    assert any(h.kind == "levenshtein" for h in check_domain("microsft.com"))


def test_nameless_inline_zip_office_and_text_parts(tmp_path) -> None:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("invoice.exe", b"MZ")
    zip_bytes = buf.getvalue()
    office = BytesIO()
    with zipfile.ZipFile(office, "w") as zf:
        zf.writestr("word/document.xml", "<w:document/>")
        zf.writestr("invoice.exe", b"MZ")
    office_bytes = office.getvalue()

    def part(raw: bytes, ctype: str) -> None:
        body = (
            "From: a@company.example\n"
            "To: user@company.example\n"
            "Subject: invoice\n"
            "Message-ID: <zip@company.example>\n"
            "MIME-Version: 1.0\n"
            "Content-Type: multipart/mixed; boundary=BOUND\n"
            "\n"
            "--BOUND\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "see attached\n"
            "--BOUND\n"
            f"Content-Type: {ctype}\n"
            "Content-Disposition: inline\n"
            "\n"
        ).encode("ascii") + raw + b"\n--BOUND--\n"
        path = tmp_path / "part.eml"
        path.write_bytes(body)
        result = analyze_file(path)
        assert result.attachments, ctype
        assert any("archive_dangerous_member" in (a.risk_flags or []) for a in result.attachments), ctype
        assert result.verdict is not None
        assert result.verdict.level.value != "benign", ctype

    part(zip_bytes, "application/zip")
    part(office_bytes, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")

    enriched = analyze_text(
        _eml(
            {
                "From": "a@company.example",
                "To": "user@company.example",
                "Subject": "note",
                "Message-ID": "<e@company.example>",
            },
            "",
            content_type="multipart/mixed; boundary=BOUND",
        ).replace(
            "\n\n",
            "\n\n--BOUND\nContent-Type: text/plain; charset=utf-8\n\nhello\n"
            "--BOUND\nContent-Type: text/enriched\n\nhttps://enriched.example/a\n"
            "--BOUND\nContent-Type: text/rtf\n\nhttps://rtf-text.example/b\n"
            "--BOUND\nContent-Type: application/rtf\nContent-Disposition: inline\n\n"
            "{\\rtf1 https://rtf-app.example/c}\n--BOUND--\n",
            1,
        ),
        label="rtf.eml",
    )
    urls = {i.value for i in enriched.iocs if i.ioc_type.value == "url"}
    assert any("enriched.example/a" in url for url in urls)
    assert any("rtf-text.example/b" in url for url in urls)
    assert any("rtf-app.example/c" in url for url in urls)
    assert any(a.filename.endswith(".rtf") for a in enriched.attachments)


def test_koi8_and_broken_us_ascii_keep_cyrillic(tmp_path) -> None:
    phrase = "Смените реквизиты и оплатите сегодня только в Telegram"
    koi = phrase.encode("koi8-r")
    cp = phrase.encode("cp1251")
    assert "реквизит" in decode_payload_text(koi, "us-ascii")
    assert "реквизит" in decode_payload_text(koi, "koi8-r")
    assert "реквизит" in decode_payload_text(cp, "koi8-r")

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
        ("us-ascii", koi),
        ("koi8-r", koi),
        ("koi8-r", cp),
    )
    for charset, body in cases:
        path = tmp_path / f"{charset}.eml"
        path.write_bytes(mail(body, charset))
        result = analyze_file(path)
        assert "bec_payment" in (result.content_signals or []), charset
        assert result.verdict is not None
        assert result.verdict.level.value == "suspicious", (charset, result.verdict.score)


def test_cyrillic_local_part_is_an_email() -> None:
    assert "иван@почта.рф" in _values("иван@почта.рф", "email")
    assert "иван@почта.рф" in _values("Иван Петров <иван@почта.рф>", "email")
    assert "user@почта.рф" in _values("user@почта.рф", "email")


def test_resent_from_is_copied_into_header_iocs() -> None:
    raw = _pass_mail(
        "обычный текст",
        {"Resent-From": "Other <other@evil.example>"},
    )
    result = analyze_text(raw, label="resent.eml")
    emails = {i.value for i in result.iocs if i.ioc_type.value == "email"}
    assert "other@evil.example" in emails
    assert any(h.name == "Resent-From domain" for h in result.headers)


def test_forms_gist_and_icloud_share_stay_visible() -> None:
    domains, ips = build_allowlist()
    hidden = ("forms.office.com", "gist.github.com", "share.icloud.com")
    for host in hidden:
        assert not domain_matches(host, domains), host
    for host in (
        "outlook.office.com",
        "login.live.com",
        "photos.google.com",
        "colab.research.google.com",
    ):
        assert domain_matches(host, domains), host
    iocs = [
        Ioc("https://forms.office.com/r/abc", IocType.URL),
        Ioc("https://gist.github.com/user/1", IocType.URL),
        Ioc("https://share.icloud.com/a", IocType.URL),
        Ioc("https://evil.example/a", IocType.URL),
        Ioc("outlook.office.com", IocType.DOMAIN),
    ]
    tag_allowlist(iocs, domains, ips)
    assert "allowlisted" not in iocs[0].tags
    assert "allowlisted" not in iocs[1].tags
    assert "allowlisted" not in iocs[2].tags
    assert "allowlisted" not in iocs[3].tags
    assert "allowlisted" in iocs[4].tags


def test_reply_prefixes_share_the_subject_key_and_thread_credit() -> None:
    def mail(subject: str, *, reply: bool) -> str:
        extra = {"Subject": subject}
        if reply:
            extra["In-Reply-To"] = "<root@company.example>"
        return _pass_mail("body", extra)

    plain = analyze_text(mail("Invoice Q3", reply=False), label="s0.eml")
    assert campaign_key_for(plain) == "subj:invoice q3"
    for subject in (
        "Ответ: Invoice Q3",
        "Переслано: Invoice Q3",
        "Re[2]: Invoice Q3",
        "На: Invoice Q3",
    ):
        same = analyze_text(mail(subject, reply=False), label="s1.eml")
        assert campaign_key_for(same) == "subj:invoice q3", subject
        threaded = analyze_text(mail(subject, reply=True), label="s2.eml")
        plain_thread = analyze_text(mail("Invoice Q3", reply=True), label="s2b.eml")
        assert campaign_key_for(threaded) == campaign_key_for(plain_thread), subject
        assert "существующем треде" in _reasons(threaded), subject

    orphan = analyze_text(mail("Ответ: Invoice Q3", reply=False), label="s3.eml")
    assert any(h.name == "Orphan reply" for h in orphan.headers)
    assert "существующем треде" not in _reasons(orphan)
