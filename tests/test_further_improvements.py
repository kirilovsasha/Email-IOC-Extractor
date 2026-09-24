"""Third-pass fixes: header IOCs, URL path domains, campaign key, score relief."""

from __future__ import annotations

from reliquary.core.ioc_extractor import extract_iocs
from reliquary.core.models import AttachmentInfo, MailIdentity
from reliquary.core.pipeline import (
    _lift_attachment_iocs,
    analyze_text,
    campaign_divergence_keys,
    campaign_key_for,
)


def _eml(headers: dict[str, str], body: str, *, content_type: str = "text/plain; charset=utf-8") -> str:
    lines = [f"{key}: {value}" for key, value in headers.items()]
    lines.append("MIME-Version: 1.0")
    lines.append(f"Content-Type: {content_type}")
    lines.append("")
    lines.append(body)
    return "\n".join(lines)


def _domains(text: str) -> set[str]:
    return {i.value for i in extract_iocs(text) if i.ioc_type.value == "domain"}


def _reasons(result) -> str:
    assert result.verdict is not None
    return " ".join(c.reason or "" for c in result.verdict.breakdown)


def test_subject_from_reply_to_land_in_iocs() -> None:
    raw = _eml(
        {
            "From": "Alice <alice@phish.example>",
            "Reply-To": "Bob <bob@reply.example>",
            "To": "user@company.example",
            "Subject": "See https://subject-only.example/a",
            "Message-ID": "<hdr@phish.example>",
        },
        "Тело без ссылок и без адресов.",
    )
    result = analyze_text(raw, label="headers-only.eml")
    values = {i.value for i in result.iocs}
    assert "https://subject-only.example/a" in values
    assert "subject-only.example" in values
    assert "alice@phish.example" in values
    assert "phish.example" in values
    assert "bob@reply.example" in values
    assert "reply.example" in values


def test_url_path_segment_is_not_a_domain_or_suspicious_zone() -> None:
    text = (
        "https://files.company.example/reports/q3.zip "
        "https://cdn.example/img/banner.mov "
        "https://login.evil.zip/auth"
    )
    domains = _domains(text)
    assert "q3.zip" not in domains
    assert "banner.mov" not in domains
    assert "files.company.example" in domains
    assert "cdn.example" in domains
    assert "login.evil.zip" in domains

    path_mail = _eml(
        {
            "From": "a@company.example",
            "To": "user@company.example",
            "Subject": "отчёт",
            "Message-ID": "<path@company.example>",
        },
        "Файл: https://files.company.example/reports/q3.zip и https://cdn.example/banner.mov",
    )
    path_result = analyze_text(path_mail, label="path-tld.eml")
    path_domains = {i.value for i in path_result.iocs if i.ioc_type.value == "domain"}
    assert "q3.zip" not in path_domains
    assert "banner.mov" not in path_domains
    assert "Подозрительная зона" not in _reasons(path_result)

    host_mail = _eml(
        {
            "From": "a@company.example",
            "To": "user@company.example",
            "Subject": "вход",
            "Message-ID": "<host@company.example>",
        },
        "https://login.evil.zip/auth",
    )
    host_result = analyze_text(host_mail, label="host-tld.eml")
    assert "login.evil.zip" in {
        i.value for i in host_result.iocs if i.ioc_type.value == "domain"
    }
    assert "login.evil.zip" in _reasons(host_result)
    assert "Подозрительная зона" in _reasons(host_result)


def test_campaign_key_skips_own_message_id_and_from_domain() -> None:
    assert MailIdentity(message_id="<solo@x>").thread_root_id() == ""

    def with_file(msgid: str, sender: str) -> str:
        return (
            f"From: {sender}\n"
            "To: user@company.example\n"
            "Subject: Same wave\n"
            f"Message-ID: {msgid}\n"
            "MIME-Version: 1.0\n"
            "Content-Type: multipart/mixed; boundary=BOUND\n"
            "\n"
            "--BOUND\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "body\n"
            "--BOUND\n"
            "Content-Type: application/octet-stream; name=\"note.bin\"\n"
            "Content-Disposition: attachment; filename=\"note.bin\"\n"
            "\n"
            "SAME-BYTES\n"
            "--BOUND--\n"
        )

    left = analyze_text(with_file("<a@x>", "one@evil.test"), label="a.eml")
    right = analyze_text(with_file("<b@y>", "two@other.test"), label="b.eml")
    key = campaign_key_for(left)
    assert key == campaign_key_for(right)
    assert key.startswith("att:")
    assert "from:" not in key
    assert "<a@x>" not in key
    assert left.mail_identity is not None and left.mail_identity.message_id

    def subject_only(msgid: str, sender: str) -> str:
        return _eml(
            {
                "From": sender,
                "To": "user@company.example",
                "Subject": "Same wave",
                "Message-ID": msgid,
            },
            "без вложения",
        )

    one = analyze_text(subject_only("<c@x>", "c@one.test"), label="c.eml")
    two = analyze_text(subject_only("<d@y>", "d@two.test"), label="d.eml")
    subj = campaign_key_for(one)
    assert subj == "subj:same wave"
    assert subj == campaign_key_for(two)
    assert subj in campaign_divergence_keys([one, two])

    threaded = _eml(
        {
            "From": "a@company.example",
            "To": "user@company.example",
            "Subject": "Re: Same wave",
            "Message-ID": "<me@company.example>",
            "References": "<root@company.example>",
        },
        "ответ",
    )
    threaded_result = analyze_text(threaded, label="thread.eml")
    assert campaign_key_for(threaded_result).startswith("thread:")
    assert "root@company.example" in campaign_key_for(threaded_result)


def test_calendar_relief_needs_a_calendar_part() -> None:
    words = _eml(
        {
            "From": "a@company.example",
            "To": "user@company.example",
            "Subject": "Приглашение на планёрку",
            "Message-ID": "<words@company.example>",
            "Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass",
        },
        "meeting request\nyou are invited\nзапрос на собрание\n",
    )
    word_result = analyze_text(words, label="words.eml")
    assert "Календарное приглашение" not in _reasons(word_result)

    ics = (
        "BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:sync\n"
        "END:VEVENT\nEND:VCALENDAR\n"
    )
    body = _eml(
        {
            "From": "calendar@company.example",
            "To": "user@company.example",
            "Subject": "sync",
            "Message-ID": "<bodycal@company.example>",
            "Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass",
        },
        ics,
    )
    assert "Календарное приглашение" in _reasons(analyze_text(body, label="body-cal.eml"))

    attached = (
        "From: calendar@company.example\n"
        "To: user@company.example\n"
        "Subject: sync\n"
        "Message-ID: <filecal@company.example>\n"
        "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=BOUND\n"
        "\n"
        "--BOUND\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "смотри вложение\n"
        "--BOUND\n"
        "Content-Type: text/calendar; name=\"meet.ics\"\n"
        "Content-Disposition: attachment; filename=\"meet.ics\"\n"
        "\n"
        f"{ics}"
        "--BOUND--\n"
    )
    assert "Календарное приглашение" in _reasons(analyze_text(attached, label="ics.eml"))


def test_internal_mx_uses_origin_hop() -> None:
    gateway = (
        "Received: from protection.outlook.com (protection.outlook.com [1.2.3.4]) "
        "by mx.company.local; Wed, 17 Sep 2025 10:00:00 +0000\n"
        "Received: from vps.attacker.example (vps.attacker.example [203.0.113.8]) "
        "by protection.outlook.com; Wed, 17 Sep 2025 09:59:00 +0000\n"
        "From: a@outside.example\n"
        "To: user@company.example\n"
        "Subject: via gateway\n"
        "Message-ID: <gw@outside.example>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        "\n"
        "текст\n"
    )
    via_gateway = analyze_text(gateway, label="gateway.eml")
    assert via_gateway.mail_identity is not None
    assert via_gateway.mail_identity.received_hops == 2
    assert "доверенный MX" not in _reasons(via_gateway)

    origin = (
        "Received: from vps.attacker.example (vps.attacker.example [203.0.113.8]) "
        "by mx.company.local; Wed, 17 Sep 2025 10:00:00 +0000\n"
        "Received: from mail.google.com (mail.google.com [142.250.0.1]) "
        "by vps.attacker.example; Wed, 17 Sep 2025 09:59:00 +0000\n"
        "From: a@company.example\n"
        "To: user@company.example\n"
        "Subject: from google\n"
        "Message-ID: <og@company.example>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        "\n"
        "текст\n"
    )
    assert "доверенный MX" in _reasons(analyze_text(origin, label="origin.eml"))

    single = _eml(
        {
            "Received": "from mail.google.com (mail.google.com [142.250.0.1]) by mx.company.local; Wed, 17 Sep 2025 10:00:00 +0000",
            "From": "a@company.example",
            "To": "user@company.example",
            "Subject": "one hop",
            "Message-ID": "<one@company.example>",
            "Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass",
        },
        "текст",
    )
    assert "доверенный MX" in _reasons(analyze_text(single, label="one-hop.eml"))


def test_permerror_temperror_and_any_dkim_mismatch() -> None:
    perm = _eml(
        {
            "From": "a@bank.example",
            "To": "user@company.example",
            "Subject": "auth",
            "Message-ID": "<perm@bank.example>",
            "Authentication-Results": (
                "mx; spf=pass; dkim=pass header.d=bank.example header.from=bank.example; dmarc=pass"
                " | mx; spf=permerror; dkim=pass header.d=bank.example header.from=bank.example; dmarc=pass"
            ),
        },
        "текст",
    )
    # Two physical headers, not one joined value.
    perm_raw = perm.replace(
        "Authentication-Results: mx; spf=pass; dkim=pass header.d=bank.example "
        "header.from=bank.example; dmarc=pass | mx; spf=permerror; "
        "dkim=pass header.d=bank.example header.from=bank.example; dmarc=pass",
        "Authentication-Results: mx; spf=pass; dkim=pass header.d=bank.example "
        "header.from=bank.example; dmarc=pass\n"
        "Authentication-Results: mx; spf=permerror; dkim=pass header.d=bank.example "
        "header.from=bank.example; dmarc=pass",
    )
    perm_result = analyze_text(perm_raw, label="perm.eml")
    assert perm_result.mail_identity is not None
    assert perm_result.mail_identity.spf == "permerror"
    assert any(h.name == "SPF result" and h.value == "permerror" for h in perm_result.headers)
    reasons = _reasons(perm_result)
    assert "SPF+DKIM+DMARC pass" not in reasons
    assert "DMARC+DKIM pass" not in reasons

    temp_raw = (
        "From: a@bank.example\n"
        "To: user@company.example\n"
        "Subject: auth\n"
        "Message-ID: <temp@bank.example>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        "Received-SPF: temperror\n"
        "\n"
        "текст\n"
    )
    temp_result = analyze_text(temp_raw, label="temp.eml")
    assert temp_result.mail_identity is not None
    assert temp_result.mail_identity.spf == "temperror"

    fail_raw = (
        "From: a@bank.example\n"
        "To: user@company.example\n"
        "Subject: auth\n"
        "Message-ID: <fail@bank.example>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "Authentication-Results: mx; spf=permerror\n"
        "Authentication-Results: mx; spf=fail\n"
        "\n"
        "текст\n"
    )
    fail_result = analyze_text(fail_raw, label="fail.eml")
    assert fail_result.mail_identity is not None
    assert fail_result.mail_identity.spf == "fail"

    align_raw = (
        "From: a@bank.example\n"
        "To: user@company.example\n"
        "Subject: auth\n"
        "Message-ID: <align@bank.example>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "Authentication-Results: mx; dkim=pass header.d=bank.example header.from=bank.example\n"
        "Authentication-Results: mx; dkim=pass header.d=evil.test\n"
        "\n"
        "текст\n"
    )
    align = analyze_text(align_raw, label="align.eml")
    assert any(
        h.name == "DKIM alignment" and "evil.test" in (h.value or "") and "bank.example" in (h.value or "")
        for h in align.headers
    )

    same_header = (
        "From: a@bank.example\n"
        "To: user@company.example\n"
        "Subject: auth\n"
        "Message-ID: <same@bank.example>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "Authentication-Results: mx; dkim=pass header.d=bank.example header.from=news.bank.example\n"
        "\n"
        "текст\n"
    )
    quiet = analyze_text(same_header, label="aligned.eml")
    assert not any(h.name == "DKIM alignment" for h in quiet.headers)


def test_links_weight_ignores_inline_cid_images() -> None:
    def wrapped(extra: str) -> str:
        return (
            "From: news@company.example\n"
            "To: user@company.example\n"
            "Subject: digest\n"
            "Message-ID: <news@company.example>\n"
            "MIME-Version: 1.0\n"
            "Content-Type: multipart/mixed; boundary=BOUND\n"
            "\n"
            "--BOUND\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "Смотрите https://news.company.example/post\n"
            f"{extra}"
            "--BOUND--\n"
        )

    cid = wrapped(
        "--BOUND\n"
        "Content-Type: image/png\n"
        "Content-ID: <logo@company.example>\n"
        "\n"
        "PNGDATA\n"
    )
    cid_result = analyze_text(cid, label="cid.eml")
    assert any((a.filename or "").startswith("cid-") for a in cid_result.attachments)
    assert "ссылки, и вложения" not in _reasons(cid_result)

    inline = wrapped(
        "--BOUND\n"
        "Content-Type: image/png; name=\"logo.png\"\n"
        "Content-Disposition: inline; filename=\"logo.png\"\n"
        "Content-ID: <logo@company.example>\n"
        "\n"
        "PNGDATA\n"
    )
    inline_result = analyze_text(inline, label="inline.eml")
    assert any("inline_image" in (a.risk_flags or []) for a in inline_result.attachments)
    assert "ссылки, и вложения" not in _reasons(inline_result)

    both = wrapped(
        "--BOUND\n"
        "Content-Type: image/png\n"
        "Content-ID: <logo@company.example>\n"
        "\n"
        "PNGDATA\n"
        "--BOUND\n"
        "Content-Type: application/pdf; name=\"note.pdf\"\n"
        "Content-Disposition: attachment; filename=\"note.pdf\"\n"
        "\n"
        "%PDF-1.1 note\n"
    )
    assert "ссылки, и вложения" in _reasons(analyze_text(both, label="file.eml"))


def test_named_rfc822_uses_payload_and_skips_empty_hashes() -> None:
    nested = (
        "From: inner@nested-from.example\n"
        "Reply-To: inner-reply@nested-reply.example\n"
        "To: user@company.example\n"
        "Subject: inside\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "See https://inside-named.example/x\n"
    )
    raw = (
        "From: a@example.com\n"
        "To: user@company.example\n"
        "Subject: fwd\n"
        "Message-ID: <outer@example.com>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=BOUND\n"
        "\n"
        "--BOUND\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "cover\n"
        "--BOUND\n"
        "Content-Type: message/rfc822; name=\"forward.eml\"\n"
        "Content-Disposition: attachment; filename=\"forward.eml\"\n"
        "\n"
        f"{nested}"
        "--BOUND--\n"
    )
    result = analyze_text(raw, label="forward.eml")
    att = next(a for a in result.attachments if a.filename == "forward.eml")
    assert att.size > 0
    assert "empty_file" not in (att.risk_flags or [])
    assert att.data
    assert b"nested-from.example" in att.data
    assert b"nested-reply.example" in att.data
    values = {i.value for i in result.iocs}
    assert "inner@nested-from.example" in values
    assert "inner-reply@nested-reply.example" in values
    assert "https://inside-named.example/x" in values
    empty = {
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    assert not empty.intersection(values)

    blank = AttachmentInfo(
        filename="forward.eml",
        size=0,
        mime_guess="message/rfc822",
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        risk_flags=["empty_file"],
    )
    lifted: list = []
    _lift_attachment_iocs([blank], lifted)
    assert not any(i.ioc_type.value in {"md5", "sha1", "sha256"} for i in lifted)
    assert any(i.ioc_type.value == "filename" for i in lifted)
