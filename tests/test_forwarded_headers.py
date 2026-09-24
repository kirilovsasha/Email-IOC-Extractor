"""Regression: From / Received must survive forward banners, BOM, leading blanks."""

from __future__ import annotations

from reliquary.core.document_parser import normalize_email_bytes, normalize_email_text
from reliquary.core.pipeline import _looks_like_rfc822, analyze_text


def _forward_source(*, banner: str, with_received: bool = True) -> str:
    hops = ""
    if with_received:
        hops = (
            "Received: from mx.company.local (mx.company.local [192.0.2.10]) "
            "by inbox.company.local; Wed, 17 Sep 2025 10:01:00 +0000\n"
            "Received: from mail.partner.example (mail.partner.example [203.0.113.5]) "
            "by mx.company.local; Wed, 17 Sep 2025 10:00:30 +0000\n"
            "Received: from client by mail.partner.example; Wed, 17 Sep 2025 10:00:00 +0000\n"
        )
    return (
        f"{banner}\n"
        f"{hops}"
        "From: Alice <alice@partner.example>\n"
        "To: bob@company.local\n"
        "Subject: FW: invoice\n"
        "Date: Wed, 17 Sep 2025 10:00:00 +0000\n"
        "Message-ID: <fwd@partner.example>\n"
        "\n"
        "Please review.\n"
    )


def test_normalize_strips_gmail_forward_banner():
    raw = _forward_source(banner="---------- Forwarded message ---------")
    fixed = normalize_email_text(raw)
    assert fixed.startswith("Received:") or fixed.startswith("From:")
    assert "Forwarded message" not in fixed.split("\n", 1)[0]


def test_normalize_strips_ru_forward_banner():
    raw = _forward_source(
        banner="----------------------- Пересылаемое сообщение -----------------------"
    )
    fixed = normalize_email_text(raw)
    assert fixed.lstrip().lower().startswith(("received:", "from:"))


def test_normalize_strips_bom_and_leading_blanks():
    body = (
        "From: Alice <alice@example.com>\n"
        "Received: from x by y; Wed, 17 Sep 2025 10:00:00 +0000\n"
        "Subject: Hi\n\nbody\n"
    )
    bom = "\ufeff" + body
    assert normalize_email_text(bom).startswith("From:")
    assert normalize_email_text("\n\n" + body).startswith("From:")
    assert normalize_email_bytes(b"\xef\xbb\xbf" + body.encode()).startswith(b"From:")


def test_analyze_forwarded_paste_fills_from_and_received_hops():
    raw = _forward_source(banner="---------- Forwarded message ---------")
    assert _looks_like_rfc822(raw)
    result = analyze_text(raw, label="fwd.eml")
    assert result.source_kind == "email"
    assert "alice@partner.example" in (result.sender or "").lower()
    assert result.mail_identity is not None
    assert "alice@partner.example" in result.mail_identity.from_header.lower()
    assert result.mail_identity.received_hops == 3
    assert not any(
        h.name == "Received" and h.value == "(нет)" for h in (result.headers or [])
    )
    assert any(h.name == "Received hops" and h.value == "3" for h in result.headers)


def test_analyze_ru_forwarded_paste():
    raw = _forward_source(
        banner="-------- Пересылаемое сообщение --------",
    )
    result = analyze_text(raw, label="ru-fwd.eml")
    assert result.mail_identity is not None
    assert result.mail_identity.received_hops == 3
    assert result.mail_identity.from_header


def test_analyze_bom_paste():
    raw = (
        "\ufeffFrom: Bob <bob@example.com>\n"
        "Received: from a by b; Wed, 17 Sep 2025 10:00:00 +0000\n"
        "Received: from c by a; Wed, 17 Sep 2025 09:59:00 +0000\n"
        "Subject: Hi\n\nbody\n"
    )
    assert _looks_like_rfc822(raw)
    result = analyze_text(raw, label="bom.eml")
    assert "bob@example.com" in (result.sender or "")
    assert result.mail_identity is not None
    assert result.mail_identity.received_hops == 2


def test_normalize_preserves_clean_eml():
    clean = (
        b"Received: from a by b; Wed, 17 Sep 2025 10:00:00 +0000\n"
        b"From: a@b.c\nSubject: x\n\nbody\n"
    )
    assert normalize_email_bytes(clean) == clean
