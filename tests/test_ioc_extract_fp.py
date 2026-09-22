"""IOC extractor precision: Message-ID / usernames / auth headers / truncation."""

from __future__ import annotations

from reliquary.core.ioc_extractor import extract_iocs


def _by_type(text: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for i in extract_iocs(text):
        out.setdefault(i.ioc_type.value, set()).add(i.value)
    return out


def test_message_id_not_email_ioc() -> None:
    blob = (
        "Message-ID: <abc123@mail.example.com>\n"
        "In-Reply-To: <xyz@foo.bar>\n"
        "References: <a@b.co> <c@d.org>\n"
        "From: analyst@company.ru\n"
    )
    by = _by_type(blob)
    assert "abc123@mail.example.com" not in by.get("email", set())
    assert "xyz@foo.bar" not in by.get("email", set())
    assert "a@b.co" not in by.get("email", set())
    assert "analyst@company.ru" in by.get("email", set())
    assert "company.ru" in by.get("domain", set())
    # Message-ID host must not leak as free-text domain either
    assert "mail.example.com" not in by.get("domain", set())


def test_angle_msgid_without_at_not_domain() -> None:
    by = _by_type("Message-ID: <CA+mail.gmail.com>\n")
    assert "mail.gmail.com" not in by.get("domain", set())
    assert not by.get("email")


def test_from_angle_addr_still_email() -> None:
    by = _by_type("From: <real.user@bank.ru>")
    assert "real.user@bank.ru" in by.get("email", set())
    assert "bank.ru" in by.get("domain", set())


def test_username_not_domain() -> None:
    by = _by_type("User ivan.petrov logged in; also john.smith and sergey.ivanov")
    domains = by.get("domain", set())
    assert "ivan.petrov" not in domains
    assert "john.smith" not in domains
    assert "sergey.ivanov" not in domains


def test_auth_header_attrs_not_domain() -> None:
    blob = (
        "Authentication-Results: mx; dkim=pass header.d=sberbank.ru "
        "header.from=sberbank.ru; spf=pass smtp.mailfrom=user@evil.company.com"
    )
    by = _by_type(blob)
    domains = by.get("domain", set())
    assert "header.from" not in domains
    assert "smtp.mailfrom" not in domains
    assert "sberbank.ru" in domains
    assert "evil.company.com" in domains
    assert "user@evil.company.com" in by.get("email", set())


def test_domain_not_truncated_after_digit_label() -> None:
    by = _by_type("Contact abc123@mx1.mail.company.local please")
    domains = by.get("domain", set())
    assert "mx1.mail.company.local" in domains
    # Must not keep only the truncated suffix
    assert "mail.company.local" not in domains or "mx1.mail.company.local" in domains
    # Free-text must not emit email local-part as domain
    by2 = _by_type("anna.ivanova@company.ru wrote")
    assert "anna.ivanova" not in by2.get("domain", set())
    assert "company.ru" in by2.get("domain", set())


def test_multi_label_weird_tld_still_allowed() -> None:
    by = _by_type("C2 at evil.corp.phishing and also report.pdf as noise")
    assert "evil.corp.phishing" in by.get("domain", set())
    assert "report.pdf" not in by.get("domain", set())


def test_homoglyph_label_is_one_domain() -> None:
    """A Cyrillic letter inside a label must not yield a second, shorter domain."""
    kaspi = "k\u0430spi.kz"  # Cyrillic а
    sber = "sb\u0435rbank.ru"  # Cyrillic е
    google = "g\u043e\u043egle.com"  # Cyrillic о
    by = _by_type(
        f"From: noreply@{kaspi}\n"
        f"Login https://{kaspi}/login\n"
        f"also {sber} and {google}\n"
        "separate host spi.kz stays\n"
        "broken ka\u200bspi.kz token\n"
    )
    domains = by.get("domain", set())
    assert kaspi in domains
    assert sber in domains
    assert google in domains
    assert "kaspi.kz" in domains  # zero-width break folded into the real host
    assert "spi.kz" in domains
    assert "rbank.ru" not in domains
    assert "gle.com" not in domains
    assert "ogle.com" not in domains
    assert f"noreply@{kaspi}" in by.get("email", set())


def test_real_domains_complete() -> None:
    by = _by_type(
        "Visit https://secure-login.sberbank.ru/path and www.gosuslugi.ru "
        "plus sub.domain-name.co.uk"
    )
    domains = by.get("domain", set())
    assert "secure-login.sberbank.ru" in domains
    assert "gosuslugi.ru" in domains
    assert "sub.domain-name.co.uk" in domains
