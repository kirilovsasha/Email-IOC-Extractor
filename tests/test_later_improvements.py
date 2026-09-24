"""Fourth-pass fixes: IOC edges, score relief, auth, MIME, batch slice."""

from __future__ import annotations

import base64
import csv

from reliquary.core.defang import refang
from reliquary.core.exporters import export_batch_csv
from reliquary.core.ioc_extractor import extract_iocs
from reliquary.core.models import AnalysisResult, FileTriageRow, Ioc, IocType, Severity
from reliquary.core.pipeline import (
    _dedup_iocs,
    analyze_text,
    campaign_divergence_keys,
    campaign_key_for,
)
from reliquary.gui.result_panels import ResultPanelsMixin


def _eml(headers: dict[str, str], body: str, *, content_type: str = "text/plain; charset=utf-8") -> str:
    lines = [f"{key}: {value}" for key, value in headers.items()]
    lines.append("MIME-Version: 1.0")
    lines.append(f"Content-Type: {content_type}")
    lines.append("")
    lines.append(body)
    return "\n".join(lines)


def _values(text: str, kind: str) -> set[str]:
    return {i.value for i in extract_iocs(text) if i.ioc_type.value == kind}


def _reasons(result) -> str:
    assert result.verdict is not None
    return " ".join(c.reason or "" for c in result.verdict.breakdown)


def _two_hops() -> str:
    return (
        "Received: from mx1.example.org (mx1.example.org [203.0.113.1]) "
        "by mx.dest.test; Wed, 17 Sep 2025 10:00:00 +0000\n"
        "Received: from sender.example.net (sender.example.net [203.0.113.2]) "
        "by mx1.example.org; Wed, 17 Sep 2025 09:59:00 +0000\n"
    )


def test_bracketed_ipv6_url_does_not_drop_the_rest() -> None:
    text = "see http://[2001:db8::1]/b and https://evil.com/a and 8.8.8.8"
    assert "http://[2001:db8::1]/b" in _values(text, "url")
    assert "https://evil.com/a" in _values(text, "url")
    assert "8.8.8.8" in _values(text, "ipv4")
    assert "evil.com" in _values(text, "domain")

    raw = _eml(
        {
            "From": "a@company.example",
            "To": "user@company.example",
            "Subject": "ipv6",
            "Message-ID": "<ipv6@company.example>",
        },
        text,
    )
    result = analyze_text(raw, label="ipv6.eml")
    assert not any(line.startswith("IOC:") for line in result.errors)
    body = {i.value for i in result.iocs}
    assert "https://evil.com/a" in body
    assert "8.8.8.8" in body
    assert "http://[2001:db8::1]/b" in body


def test_ipv6_mapped_keeps_the_ipv4_tail() -> None:
    text = "addr ::ffff:192.0.2.1 next to 192.0.2.1"
    ipv6 = _values(text, "ipv6")
    assert "::ffff:192.0.2.1" in ipv6
    assert "::ffff:192" not in ipv6
    assert "192.0.2.1" in _values(text, "ipv4")


def test_percent_encoding_stays_on_the_original_url_and_email() -> None:
    text = (
        "sales%40team@company.com "
        "https://evil.com/path%20rest "
        "https://evil.com/a%2Fb "
        "https://evil.com/a "
        "https://evil&#46;com/a"
    )
    emails = _values(text, "email")
    urls = _values(text, "url")
    assert "team@company.com" not in emails
    assert "sales%40team@company.com" in emails
    assert "https://evil.com/path%20rest" in urls
    assert "https://evil.com/a%2Fb" in urls
    assert "https://evil.com/a/b" not in urls
    assert "https://evil&#46;com/a" not in urls
    assert "https://evil.com/a" in urls


def test_url_userinfo_is_not_an_email() -> None:
    samples = (
        "https://admin:pass@evil.com/x",
        "https://microsoft.com@evil.com/x",
    )
    for text in samples:
        emails = _values(text, "email")
        assert "pass@evil.com" not in emails
        assert "microsoft.com@evil.com" not in emails
        assert text in _values(text, "url")
        assert "evil.com" in _values(text, "domain")
    both = " ".join(samples)
    emails = _values(both, "email")
    assert "pass@evil.com" not in emails
    assert "microsoft.com@evil.com" not in emails


def test_header_body_urls_dedup_with_normalize_url_key() -> None:
    slash = Ioc("https://evil.com/a/", IocType.URL, source="header")
    bare = Ioc("https://www.evil.com/a", IocType.URL, source="text")
    merged = [i for i in _dedup_iocs([slash, bare]) if i.ioc_type == IocType.URL]
    assert len(merged) == 1


def test_curly_at_refangs_like_bracket_at() -> None:
    assert "user@evil.com" in _values("user{at}evil{dot}com", "email")
    assert refang("user{at}evil{dot}com") == "user@evil.com"
    assert "user@evil.com" in _values("user[at]evil[dot]com", "email")


def test_mailbox_angles_keep_envelope_and_dsn_recipients() -> None:
    text = (
        "Return-Path: <bounces+tag@evil.com>\n"
        "Delivered-To: <user@evil.com>\n"
        "Envelope-To: <box@evil.com>\n"
        "From: <ok@good.com>\n"
        "Final-Recipient: rfc822; <gone@dead.example>\n"
        "Original-Recipient: rfc822; <orig@dead.example>\n"
        "Message-ID: <hidden@msgid.example>\n"
    )
    emails = _values(text, "email")
    assert "bounces+tag@evil.com" in emails
    assert "user@evil.com" in emails
    assert "box@evil.com" in emails
    assert "ok@good.com" in emails
    assert "gone@dead.example" in emails
    assert "orig@dead.example" in emails
    assert "hidden@msgid.example" not in emails
    assert "msgid.example" not in _values(text, "domain")


def test_backslash_is_not_part_of_a_domain() -> None:
    domains = _values("https://evil.com\\path", "domain")
    assert "evil.com\\path" not in domains
    assert "evil.com" in domains


def test_lookalike_blocks_pass_and_allowlist_relief() -> None:
    raw = (
        _two_hops()
        + "From: News <news@microsoft.com>\n"
        + "To: user@company.example\n"
        + "Subject: portal\n"
        + "Message-ID: <news@microsoft.com>\n"
        + "MIME-Version: 1.0\n"
        + "Content-Type: text/plain; charset=utf-8\n"
        + "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\n"
        + "\n"
        + "Open https://microsft.com/portal\n"
    )
    result = analyze_text(raw, label="lookalike.eml")
    assert result.verdict is not None
    assert result.verdict.score > 0
    assert result.verdict.level.value != "benign"
    reasons = _reasons(result)
    assert "Lookalike" in reasons or "microsft" in reasons
    assert "DMARC+DKIM" not in reasons
    assert "allowlist" not in reasons.lower()


def test_same_domain_reply_to_is_not_high() -> None:
    def mail(reply: str) -> str:
        return (
            _two_hops()
            + "From: Marketing <marketing@company.example>\n"
            + f"Reply-To: {reply}\n"
            + "To: user@company.example\n"
            + "Subject: hello\n"
            + "Message-ID: <m@company.example>\n"
            + "MIME-Version: 1.0\n"
            + "Content-Type: text/plain; charset=utf-8\n"
            + "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\n"
            + "\n"
            + "Обычный текст.\n"
        )

    same = analyze_text(mail("Support <support@company.example>"), label="same-reply.eml")
    assert not any(
        h.name == "Reply-To mismatch" and h.severity == Severity.HIGH for h in same.headers
    )
    assert "Reply-To отличается" not in _reasons(same)
    assert same.verdict is not None and same.verdict.score < 25

    foreign = analyze_text(mail("Support <support@other.test>"), label="foreign-reply.eml")
    assert any(
        h.name == "Reply-To mismatch" and h.severity == Severity.HIGH for h in foreign.headers
    )
    assert "Reply-To отличается" in _reasons(foreign)


def test_body_qr_url_blocks_mitigation(monkeypatch) -> None:
    monkeypatch.setattr("reliquary.core.qr_scan.qr_decoder_available", lambda: True)
    monkeypatch.setattr(
        "reliquary.core.qr_scan.decode_qr_payloads",
        lambda _data: (["https://qr.evil.example/a"], []),
    )
    blob = base64.b64encode(b"X" * 80).decode()
    raw = _eml(
        {
            "From": "News <news@microsoft.com>",
            "To": "user@company.example",
            "Subject": "notice",
            "Message-ID": "<qr@microsoft.com>",
            "Authentication-Results": "mx.example; spf=pass; dkim=pass; dmarc=pass",
        },
        f"<p>Weekly status for the team.</p><img src=\"data:image/png;base64,{blob}\">",
        content_type="text/html; charset=utf-8",
    )
    # Two hops so a one-hop Received finding does not change the score.
    raw = _two_hops() + raw
    result = analyze_text(raw, label="qr.eml")
    body = next(a for a in result.attachments if a.filename == "тело.html")
    assert "qr_url" in body.risk_flags
    assert any(entry.startswith("QR:") for entry in body.archive_entries)
    assert "DMARC+DKIM" not in _reasons(result)
    assert "allowlist" not in _reasons(result).lower()
    assert result.verdict is not None and result.verdict.score >= 8


def test_pass_beats_earlier_neutral_and_bestguesspass() -> None:
    def auth_mail(auth: str, received_spf: str) -> str:
        return (
            "From: a@bank.example\n"
            "To: user@company.example\n"
            "Subject: auth\n"
            "Message-ID: <spf@bank.example>\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text/plain; charset=utf-8\n"
            f"Authentication-Results: {auth}\n"
            f"Received-SPF: {received_spf}\n"
            "\n"
            "текст\n"
        )

    neutral = analyze_text(
        auth_mail("mx.example; spf=neutral; dkim=pass; dmarc=pass", "pass"),
        label="neutral.eml",
    )
    assert neutral.mail_identity is not None
    assert neutral.mail_identity.spf == "pass"

    guess = analyze_text(
        auth_mail("mx.example; spf=bestguesspass", "pass"),
        label="guess.eml",
    )
    assert guess.mail_identity is not None
    assert guess.mail_identity.spf == "pass"

    failed = analyze_text(
        auth_mail("mx.example; spf=pass", "fail"),
        label="spf-fail.eml",
    )
    assert failed.mail_identity is not None
    assert failed.mail_identity.spf == "fail"


def test_header_i_mismatch_is_dkim_alignment() -> None:
    raw = (
        "From: News <news@microsoft.com>\n"
        "To: user@company.example\n"
        "Subject: auth\n"
        "Message-ID: <i@microsoft.com>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "Authentication-Results: mx; dkim=pass header.d=microsoft.com "
        "header.i=@evil.test header.from=microsoft.com; dmarc=pass\n"
        "\n"
        "текст\n"
    )
    result = analyze_text(raw, label="header-i.eml")
    assert any(
        h.name == "DKIM alignment" and "evil.test" in (h.value or "") for h in result.headers
    )
    reasons = _reasons(result)
    assert "DMARC+DKIM" not in reasons
    assert "смягчение score" not in reasons

    aligned = raw.replace("header.i=@evil.test", "header.i=@microsoft.com")
    quiet = analyze_text(aligned, label="header-i-ok.eml")
    assert not any(h.name == "DKIM alignment" for h in quiet.headers)


def test_root_non_text_part_is_an_attachment() -> None:
    pdf = b"%PDF-1.4\n1 0 obj\n<< /URI (https://evil.example/a) >>\nendobj\n%%EOF\n"
    encoded = base64.b64encode(pdf).decode()
    raw = (
        "From: a@company.example\n"
        "To: user@company.example\n"
        "Subject: invoice\n"
        "Message-ID: <pdf@company.example>\n"
        "MIME-Version: 1.0\n"
        'Content-Type: application/pdf; name="invoice.pdf"\n'
        'Content-Disposition: attachment; filename="invoice.pdf"\n'
        "Content-Transfer-Encoding: base64\n"
        "\n"
        f"{encoded}\n"
    )
    result = analyze_text(raw, label="root-pdf.eml")
    assert result.attachments
    att = result.attachments[0]
    assert att.filename == "invoice.pdf"
    assert len(att.sha256) == 64
    assert "pdf_uri_action" in att.risk_flags
    assert "%PDF" not in (result.raw_text_preview or "")
    assert "/URI" in _reasons(result)

    pkcs7 = (
        "From: a@company.example\n"
        "To: user@company.example\n"
        "Subject: encrypted\n"
        "Message-ID: <p7@company.example>\n"
        "MIME-Version: 1.0\n"
        'Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"\n'
        'Content-Disposition: attachment; filename="smime.p7m"\n'
        "\n"
        "ENCRYPTEDBODY\n"
    )
    enc = analyze_text(pkcs7, label="pkcs7.eml")
    assert enc.attachments
    assert enc.attachments[0].filename == "smime.p7m"
    assert "ENCRYPTEDBODY" not in (enc.raw_text_preview or "")


def test_delivery_status_text_is_scanned_for_iocs() -> None:
    raw = (
        "From: mailer-daemon@company.example\n"
        "To: user@company.example\n"
        "Subject: Undelivered\n"
        "Message-ID: <dsn@company.example>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/report; report-type=delivery-status; boundary=BOUND\n"
        "\n"
        "--BOUND\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "Delivery failed.\n"
        "--BOUND\n"
        "Content-Type: message/delivery-status\n"
        "\n"
        "Final-Recipient: rfc822; gone@dead.example\n"
        "--BOUND--\n"
    )
    result = analyze_text(raw, label="dsn.eml")
    emails = {i.value for i in result.iocs if i.ioc_type.value == "email"}
    assert "gone@dead.example" in emails


def test_several_attachments_use_the_subject_key() -> None:
    def mail(sender: str, unique: str) -> str:
        return (
            f"From: {sender}\n"
            "To: user@company.example\n"
            "Subject: invoice q3\n"
            f"Message-ID: <{unique}@x>\n"
            "MIME-Version: 1.0\n"
            "Content-Type: multipart/mixed; boundary=BOUND\n"
            "\n"
            "--BOUND\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "body\n"
            "--BOUND\n"
            'Content-Type: application/octet-stream; name="shared.bin"\n'
            'Content-Disposition: attachment; filename="shared.bin"\n'
            "\n"
            "SAME-BYTES\n"
            "--BOUND\n"
            f'Content-Type: application/octet-stream; name="{unique}.bin"\n'
            f'Content-Disposition: attachment; filename="{unique}.bin"\n'
            "\n"
            f"UNIQUE-{unique}\n"
            "--BOUND--\n"
        )

    left = analyze_text(mail("one@evil.test", "aaa"), label="a.eml")
    right = analyze_text(mail("two@other.test", "zzz"), label="b.eml")
    assert len({a.sha256 for a in left.attachments if a.sha256}) >= 2
    key = campaign_key_for(left)
    assert key == "subj:invoice q3"
    assert key == campaign_key_for(right)
    assert key in campaign_divergence_keys([left, right])


def test_batch_csv_writes_a_longer_slice(tmp_path) -> None:
    one = analyze_text(
        _eml(
            {
                "From": "a@one.example",
                "To": "user@company.example",
                "Subject": "one",
                "Message-ID": "<one@one.example>",
            },
            "https://one.example/a",
        ),
        label="/mail/one/invoice.eml",
    )
    two = analyze_text(
        _eml(
            {
                "From": "b@two.example",
                "To": "user@company.example",
                "Subject": "two",
                "Message-ID": "<two@two.example>",
            },
            "https://two.example/b",
        ),
        label="/mail/two/invoice.eml",
    )
    assert len(one.file_rows) == 1
    out = export_batch_csv(one, tmp_path / "slice.csv", batch_results=[one, two])
    with out.open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert {row["file"] for row in rows} == {
        "/mail/one/invoice.eml",
        "/mail/two/invoice.eml",
    }


def test_batch_slice_keeps_only_the_full_path() -> None:
    class _Var:
        def __init__(self, value: str) -> None:
            self._value = value

        def get(self) -> str:
            return self._value

    host = type("Host", (), {})()
    host._batch_verdict_chip = _Var("все")
    host._batch_filter_var = _Var("only-two")
    host._batch_all_rows = [
        FileTriageRow(
            path="/mail/one/invoice.eml",
            kind="email",
            verdict_level="unknown",
            verdict_score=10,
            top_reason="alpha",
        ),
        FileTriageRow(
            path="/mail/two/invoice.eml",
            kind="email",
            verdict_level="unknown",
            verdict_score=10,
            top_reason="only-two",
        ),
    ]
    host._batch_results = [
        AnalysisResult(source_path="/mail/one/invoice.eml", source_kind="email"),
        AnalysisResult(source_path="/mail/two/invoice.eml", source_kind="email"),
    ]
    visible = ResultPanelsMixin._visible_batch_results(host)
    assert [r.source_path for r in visible] == ["/mail/two/invoice.eml"]
