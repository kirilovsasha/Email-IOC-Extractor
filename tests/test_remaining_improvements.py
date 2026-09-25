"""Fifth-pass fixes: ordinary finance mail, signals, headers, IOC, campaign key."""

from __future__ import annotations

from reliquary.core.allowlist import build_allowlist, domain_matches, tag_allowlist
from reliquary.core.content_signals import BEC_RE, analyze_content_signals
from reliquary.core.ioc_extractor import extract_iocs
from reliquary.core.models import (
    AnalysisResult,
    AttachmentInfo,
    Ioc,
    IocType,
    MailIdentity,
    Severity,
)
from reliquary.core.pipeline import analyze_text, campaign_divergence_keys, campaign_key_for
from reliquary.core.verdict import render_verdict
from reliquary.core.verdict_config import URGENCY_RE


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


def _pass_mail(body: str, extra: dict[str, str] | None = None, *, content_type: str = "text/plain; charset=utf-8") -> str:
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


def test_ordinary_finance_wording_does_not_cancel_pass() -> None:
    assert URGENCY_RE.search("направляем счёт-фактуру") is None
    assert URGENCY_RE.search("Расчётный счёт") is None
    assert URGENCY_RE.search("расчетный счет") is None
    assert BEC_RE.search("направляем счёт-фактуру") is None
    assert URGENCY_RE.search("срочно оплатите")

    for body in (
        "Направляем счёт-фактуру во вложении.",
        "Акт сверки за квартал.",
        "р/с 40702810900000001234",
        "Письмо от CFO.",
        "Расчётный счёт 40702810900000001234.",
    ):
        result = analyze_text(_pass_mail(body), label="finance.eml")
        assert "bec_payment" not in (result.content_signals or []), body
        assert "BEC" not in _reasons(result)
        assert "DMARC+DKIM" in _reasons(result)
        assert result.verdict is not None
        assert result.verdict.level.value == "benign", body
        assert result.verdict.score < 10

    hostile = analyze_text(
        _pass_mail("Смените реквизиты и оплатите сегодня только в Telegram."),
        label="bec.eml",
    )
    assert "bec_payment" in (hostile.content_signals or [])
    assert "DMARC+DKIM" not in _reasons(hostile)
    assert hostile.verdict is not None
    assert hostile.verdict.level.value == "suspicious"


def test_body_signals_are_kept_when_yara_is_already_listed() -> None:
    html = (
        '<a href="https://evil.example/login">https://bank.example/login</a>'
        "<p>Please sign in and update your password</p>"
        '<form><input type="password"></form>'
    )
    base = dict(
        source_path="yara.eml",
        source_kind="email",
        subject="status",
        score_text="Please sign in and update your password",
        score_html=html,
        mail_identity=MailIdentity(
            from_header="News <news@company.example>",
            spf="pass",
            dkim="pass",
            dmarc="pass",
        ),
    )
    quiet = AnalysisResult(**base)
    marked = AnalysisResult(**base, content_signals=["yara:BodyRule"])
    quiet_verdict = render_verdict(quiet)
    marked_verdict = render_verdict(marked)
    assert quiet_verdict is not None and marked_verdict is not None
    for result, verdict in ((quiet, quiet_verdict), (marked, marked_verdict)):
        kinds = result.content_signals or []
        assert "href_mismatch" in kinds
        assert "credential_harvest" in kinds
        reasons = " ".join(c.reason or "" for c in verdict.breakdown)
        assert "DMARC+DKIM" not in reasons
    assert "yara:BodyRule" in (marked.content_signals or [])
    assert quiet_verdict.score == marked_verdict.score
    assert quiet_verdict.level.value == "suspicious"


def test_password_attribute_is_not_a_credential_phrase() -> None:
    html = "<html><body>во вложении отчёт<form><input type=\"password\"></form></body></html>"
    kinds = {s.kind for s in analyze_content_signals("во вложении отчёт", html)}
    assert "credential_harvest" not in kinds
    assert "html_password_form" in kinds
    stuck = {
        s.kind
        for s in analyze_content_signals(
            'во вложении отчёт\n<form><input type="password"></form>',
            html,
        )
    }
    assert "credential_harvest" not in stuck

    visible = {s.kind for s in analyze_content_signals("enter your password", "")}
    assert "credential_harvest" in visible

    result = analyze_text(
        _pass_mail(html, content_type="text/html; charset=utf-8"),
        label="form.eml",
    )
    assert "credential_harvest" not in (result.content_signals or [])
    assert "html_password_form" in (result.content_signals or [])
    assert "учётных данных" not in _reasons(result)
    assert "полем password" in _reasons(result)
    assert "DMARC+DKIM" not in _reasons(result)
    assert result.verdict is not None
    assert result.verdict.level.value == "unknown"


def test_reply_to_subdomain_is_related() -> None:
    related = analyze_text(
        _pass_mail(
            "Обычный текст.",
            {"Reply-To": "Billing <billing@mail.company.example>"},
        ),
        label="reply-sub.eml",
    )
    assert not any(
        h.name == "Reply-To mismatch" and h.severity == Severity.HIGH for h in related.headers
    )
    assert "Reply-To отличается" not in _reasons(related)
    assert "DMARC+DKIM" in _reasons(related)
    assert related.verdict is not None and related.verdict.score < 25

    foreign = analyze_text(
        _pass_mail("Обычный текст.", {"Reply-To": "Billing <billing@other.test>"}),
        label="reply-foreign.eml",
    )
    assert any(
        h.name == "Reply-To mismatch" and h.severity == Severity.HIGH for h in foreign.headers
    )


def test_dkim_signature_d_is_alignment_when_auth_has_no_pair() -> None:
    raw = _pass_mail(
        "текст",
        {
            "DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed; d=evil.example; s=selector",
        },
    )
    result = analyze_text(raw, label="sig.eml")
    assert any(
        h.name == "DKIM alignment" and "evil.example" in (h.value or "") for h in result.headers
    )
    assert "DMARC+DKIM" not in _reasons(result)
    assert result.verdict is not None and result.verdict.score > 0

    aligned = analyze_text(
        _pass_mail(
            "текст",
            {"DKIM-Signature": "v=1; a=rsa-sha256; d=company.example; s=selector"},
        ),
        label="sig-ok.eml",
    )
    assert not any(h.name == "DKIM alignment" for h in aligned.headers)
    assert "DMARC+DKIM" in _reasons(aligned)

    subdomain = analyze_text(
        _pass_mail(
            "текст",
            {
                "From": "News <news@mail.company.example>",
                "DKIM-Signature": "v=1; a=rsa-sha256; d=company.example; s=selector",
            },
        ),
        label="sig-sub.eml",
    )
    assert not any(h.name == "DKIM alignment" for h in subdomain.headers)

    paired = analyze_text(
        _pass_mail(
            "текст",
            {
                "Authentication-Results": (
                    "mx.example; dkim=pass header.d=company.example "
                    "header.from=company.example; dmarc=pass"
                ),
                "DKIM-Signature": "v=1; a=rsa-sha256; d=evil.example; s=selector",
            },
        ),
        label="sig-paired.eml",
    )
    assert not any(h.name == "DKIM alignment" for h in paired.headers)


def test_single_received_gateway_is_not_internal_mx() -> None:
    single = _eml(
        {
            "Received": (
                "from mail.protection.outlook.com (mail.protection.outlook.com [1.2.3.4]) "
                "by mx.company.local; Wed, 17 Sep 2025 10:00:00 +0000"
            ),
            "From": "a@company.example",
            "To": "user@company.example",
            "Subject": "one",
            "Message-ID": "<one@company.example>",
            "Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass",
        },
        "текст",
    )
    result = analyze_text(single, label="gateway.eml")
    assert result.mail_identity is not None and result.mail_identity.received_hops == 1
    assert "доверенный MX" not in _reasons(result)
    assert "DMARC+DKIM" in _reasons(result)

    internal = _eml(
        {
            "Received": (
                "from mail.corp.local (mail.corp.local [10.0.0.5]) "
                "by mx.company.local; Wed, 17 Sep 2025 10:00:00 +0000"
            ),
            "From": "it@company.local",
            "To": "user@company.local",
            "Subject": "окно",
            "Message-ID": "<mx@company.local>",
            "Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass",
        },
        "Напоминание: завтра сервисное окно.",
    )
    assert "доверенный MX" in _reasons(analyze_text(internal, label="corp.eml"))


def test_return_path_sender_and_list_unsubscribe_reach_iocs() -> None:
    foreign = analyze_text(
        _pass_mail(
            "дайджест",
            {
                "Return-Path": "<bounces+tag@evil.example>",
                "Sender": "Mailer <bounces@lists.example>",
                "List-Unsubscribe": "<https://evil.example/click>",
                "Precedence": "bulk",
            },
        ),
        label="unsub.eml",
    )
    emails = {i.value for i in foreign.iocs if i.ioc_type.value == "email"}
    urls = {i.value for i in foreign.iocs if i.ioc_type.value == "url"}
    assert "bounces+tag@evil.example" in emails
    assert "bounces@lists.example" in emails
    assert "https://evil.example/click" in urls
    assert "Рассылка" not in _reasons(foreign)

    same = analyze_text(
        _pass_mail(
            "дайджест",
            {
                "List-Unsubscribe": "<https://news.company.example/unsub>",
                "List-Id": "<digest.company.example>",
                "Precedence": "bulk",
            },
        ),
        label="unsub-ok.eml",
    )
    assert "https://news.company.example/unsub" in {
        i.value for i in same.iocs if i.ioc_type.value == "url"
    }
    assert "Рассылка" in _reasons(same)


def test_named_entities_on_found_urls_share_one_key() -> None:
    text = (
        'href="https://evil.example/login?a=1&amp;b=2"\n'
        "https://evil.example/login?a=1&b=2"
    )
    urls = _values(text, "url")
    assert urls.count("https://evil.example/login?a=1&b=2") == 1
    assert not any("&amp;" in url for url in urls)
    assert "https://evil.com/a" in _values("https://evil&#46;com/a", "url")

    html = (
        '<a href="https://evil.example/login?a=1&amp;b=2">'
        "https://evil.example/login?a=1&amp;b=2</a>"
    )
    result = analyze_text(
        _pass_mail(html, content_type="text/html; charset=utf-8"),
        label="amp.eml",
    )
    found = [i.value for i in result.iocs if i.ioc_type.value == "url" and "evil.example/login" in i.value]
    assert found == ["https://evil.example/login?a=1&b=2"]


def test_ipv6_url_host_gets_raw_ip_weight() -> None:
    v6 = analyze_text(
        _pass_mail("статус http://[2606:4700:4700::1111]/status"),
        label="v6.eml",
    )
    v4 = analyze_text(
        _pass_mail("статус http://203.0.113.50/status"),
        label="v4.eml",
    )
    assert "сырой IP" in _reasons(v6)
    assert "сырой IP" in _reasons(v4)
    assert v6.verdict is not None and v4.verdict is not None
    assert v6.verdict.score == v4.verdict.score
    assert v6.verdict.score > 0


def test_href_mismatch_strips_only_www_prefix() -> None:
    mismatch = {
        s.kind
        for s in analyze_content_signals(
            "",
            '<a href="https://wbank.com">https://www.bank.com</a>',
        )
    }
    assert "href_mismatch" in mismatch
    webhook = {
        s.kind
        for s in analyze_content_signals(
            "",
            '<a href="https://ebhook.example.com">https://webhook.example.com</a>',
        )
    }
    assert "href_mismatch" in webhook
    same = {
        s.kind
        for s in analyze_content_signals(
            "",
            '<a href="https://www.bank.com/login">https://bank.com</a>',
        )
    }
    assert "href_mismatch" not in same


def test_google_user_hosts_and_path_style_s3_stay_visible() -> None:
    domains, ips = build_allowlist()
    hidden = [
        "drive.google.com",
        "docs.google.com",
        "sites.google.com",
        "script.google.com",
        "storage.cloud.google.com",
        "s3.amazonaws.com",
    ]
    for host in hidden:
        assert not domain_matches(host, domains), host
    for host in ("mail.google.com", "google.com", "fonts.gstatic.com", "fonts.googleapis.com"):
        assert domain_matches(host, domains), host

    iocs = [
        Ioc("https://s3.amazonaws.com/bucket/secret", IocType.URL),
        Ioc("https://drive.google.com/file/d/1", IocType.URL),
        Ioc("mail.google.com", IocType.DOMAIN),
    ]
    tag_allowlist(iocs, domains, ips)
    assert "allowlisted" not in iocs[0].tags
    assert "allowlisted" not in iocs[1].tags
    assert "allowlisted" in iocs[2].tags


def test_campaign_key_ignores_inline_and_cid_images() -> None:
    def mail(subject: str, filename: str, payload: str, sender: str) -> str:
        return (
            f"From: {sender}\n"
            "To: user@company.example\n"
            f"Subject: {subject}\n"
            f"Message-ID: <{payload}@company.example>\n"
            "MIME-Version: 1.0\n"
            "Content-Type: multipart/mixed; boundary=BOUND\n"
            "\n"
            "--BOUND\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "body\n"
            "--BOUND\n"
            f'Content-Type: image/png; name="{filename}"\n'
            f'Content-Disposition: inline; filename="{filename}"\n'
            "Content-ID: <logo@company.example>\n"
            "\n"
            f"{payload}\n"
            "--BOUND--\n"
        )

    left = analyze_text(mail("Alpha note", "cid-logo.png", "LOGO", "a@one.example"), label="a.eml")
    right = analyze_text(mail("Beta note", "cid-logo.png", "LOGO", "b@two.example"), label="b.eml")
    assert any("inline_image" in (a.risk_flags or []) for a in left.attachments)
    assert campaign_key_for(left).startswith("subj:")
    assert campaign_key_for(left) != campaign_key_for(right)
    assert campaign_key_for(left) not in campaign_divergence_keys([left, right])

    one = analyze_text(mail("Invoice Q3", "cid-logo.png", "PNG-ONE", "a@one.example"), label="c.eml")
    two = analyze_text(mail("Invoice Q3", "cid-logo.png", "PNG-TWO", "b@two.example"), label="d.eml")
    assert campaign_key_for(one) == "subj:invoice q3"
    assert campaign_key_for(one) == campaign_key_for(two)
    assert campaign_key_for(one) in campaign_divergence_keys([one, two])

    real = AttachmentInfo(
        filename="note.pdf",
        size=4,
        mime_guess="application/pdf",
        md5="m",
        sha1="s",
        sha256="a" * 64,
        risk_flags=[],
    )
    logo = AttachmentInfo(
        filename="cid-logo.png",
        size=4,
        mime_guess="image/png",
        md5="m2",
        sha1="s2",
        sha256="b" * 64,
        risk_flags=["inline_image"],
    )
    keyed = AnalysisResult(
        source_path="file.eml",
        source_kind="email",
        subject="other",
        attachments=[logo, real],
    )
    assert campaign_key_for(keyed) == "att:" + ("a" * 16)
