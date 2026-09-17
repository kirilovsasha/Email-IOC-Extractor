"""Offline IOC extraction from free text."""

from __future__ import annotations

import re
from urllib.parse import unquote, urlparse

from reliquary.core.models import Ioc, IocType

# Conservative patterns — prioritize precision for SOC triage.
IPV4_RE = re.compile(
    r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.])"
)
IPV6_RE = re.compile(
    r"(?<![\w:])(?:(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,7}:|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|"
    r"::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}|"
    r"::)(?![\w:])"
)
URL_RE = re.compile(
    r"(?i)\b(?:https?|hxxps?|ftp)://[^\s<>\"')\]]+",
)
EMAIL_RE = re.compile(
    r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b"
)
DOMAIN_RE = re.compile(
    r"(?i)(?<!@)(?<![A-Fa-f0-9])\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|ru|su|info|biz|io|dev|xyz|top|club|online|site|"
    r"store|app|cloud|tech|pro|cc|tv|me|co|uk|de|fr|nl|pl|ua|kz|"
    r"by|cn|jp|kr|au|ca|us|edu|gov|mil|int)\b"
)
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

PRIVATE_IPV4_PREFIXES = (
    "10.",
    "127.",
    "169.254.",
    "192.168.",
)
PRIVATE_IPV4_RANGES_16 = tuple(f"172.{i}." for i in range(16, 32))

# Infrastructure of mail security gateways — tag, but keep for context.
REWRITER_DOMAIN_SUFFIXES = (
    "safelinks.protection.outlook.com",
    "urldefense.com",
    "urldefense.proofpoint.com",
    "mimecast.com",
    "linkprotect.cudasvc.com",
)


def defang(text: str) -> str:
    """Normalize common SOC defanging so extractors still match."""
    replacements = (
        ("hxxps://", "https://"),
        ("hxxp://", "http://"),
        ("[.]", "."),
        ("(.)", "."),
        ("{.}", "."),
        ("[:]", ":"),
        ("[@]", "@"),
    )
    out = text
    for old, new in replacements:
        out = out.replace(old, new)
        out = out.replace(old.upper(), new)
    return out


def _is_private_ipv4(ip: str) -> bool:
    if ip.startswith(PRIVATE_IPV4_PREFIXES) or ip.startswith(PRIVATE_IPV4_RANGES_16):
        return True
    if ip.startswith("0.") or ip == "255.255.255.255":
        return True
    return False


def _context_snippet(text: str, match: re.Match[str], radius: int = 40) -> str:
    start = max(0, match.start() - radius)
    end = min(len(text), match.end() + radius)
    snippet = text[start:end].replace("\n", " ").strip()
    return snippet


def _is_rewriter_host(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in REWRITER_DOMAIN_SUFFIXES)


def _valid_domain(domain: str) -> bool:
    """Drop garbage domains produced by percent-encoding leftovers."""
    d = domain.lower().rstrip(".")
    if not d or d.startswith("-") or ".." in d:
        return False
    labels = d.split(".")
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        return False
    # Reject labels that look like "%2Fevil" artifacts: start with hex digit run + word
    if re.match(r"^[0-9a-f]{2}[a-z]", labels[0]) and not re.match(r"^\d", labels[0]):
        # e.g. 2fevil-mailer — almost always encoding debris
        return False
    return True


def extract_iocs(text: str, source: str = "text") -> list[Ioc]:
    """Extract and deduplicate IOCs from arbitrary text."""
    if not text:
        return []

    # Defang + percent-decode so SafeLinks bodies don't spawn fake domains.
    cleaned = unquote(defang(text))
    found: dict[tuple[str, str], Ioc] = {}

    def add(value: str, ioc_type: IocType, match: re.Match[str], tags: list[str] | None = None) -> None:
        key = (ioc_type.value, value.lower() if ioc_type != IocType.URL else value)
        if key in found:
            return
        found[key] = Ioc(
            value=value,
            ioc_type=ioc_type,
            source=source,
            context=_context_snippet(cleaned, match),
            tags=tags or [],
        )

    for m in URL_RE.finditer(cleaned):
        url = m.group(0).rstrip(".,;:!?")
        tags = []
        if "hxxp" in m.group(0).lower():
            tags.append("was_defanged")
        add(url, IocType.URL, m, tags)
        host = urlparse(url).hostname
        if host and not _is_private_ipv4(host):
            # Domains from URLs are high-signal.
            if re.fullmatch(IPV4_RE, host):
                add(host, IocType.IPV4, m, ["from_url"])
            elif "." in host and _valid_domain(host):
                tags_d = ["from_url"]
                if _is_rewriter_host(host):
                    tags_d.append("url_rewriter")
                add(host.lower(), IocType.DOMAIN, m, tags_d)

    for m in EMAIL_RE.finditer(cleaned):
        email = m.group(0).lower()
        add(email, IocType.EMAIL, m)
        domain = email.split("@", 1)[1]
        if _valid_domain(domain):
            add(domain, IocType.DOMAIN, m, ["from_email"])

    for m in IPV4_RE.finditer(cleaned):
        ip = m.group(0)
        tags = ["private"] if _is_private_ipv4(ip) else []
        add(ip, IocType.IPV4, m, tags)

    for m in IPV6_RE.finditer(cleaned):
        add(m.group(0), IocType.IPV6, m)

    for m in SHA256_RE.finditer(cleaned):
        add(m.group(0).lower(), IocType.SHA256, m)

    for m in SHA1_RE.finditer(cleaned):
        # Skip if already captured as part of sha256 (subset rare but possible).
        val = m.group(0).lower()
        if any(i.ioc_type == IocType.SHA256 and val in i.value for i in found.values()):
            continue
        add(val, IocType.SHA1, m)

    for m in MD5_RE.finditer(cleaned):
        val = m.group(0).lower()
        if any(
            i.ioc_type in (IocType.SHA1, IocType.SHA256) and val in i.value
            for i in found.values()
        ):
            continue
        add(val, IocType.MD5, m)

    for m in CVE_RE.finditer(cleaned):
        add(m.group(0).upper(), IocType.CVE, m)

    for m in DOMAIN_RE.finditer(cleaned):
        domain = m.group(0).lower().rstrip(".")
        if not _valid_domain(domain):
            continue
        tags = ["url_rewriter"] if _is_rewriter_host(domain) else []
        add(domain, IocType.DOMAIN, m, tags)

    return list(found.values())
