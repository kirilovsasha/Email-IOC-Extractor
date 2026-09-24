"""Offline IOC extraction from free text."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import unicodedata
from html import unescape
from urllib.parse import unquote, urlparse

from reliquary.core.defang import refang as defang
from reliquary.core.lookalike import to_ascii_domain
from reliquary.core.models import Ioc, IocType

# Conservative patterns — prioritize precision for SOC triage.
IPV4_RE = re.compile(
    r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.])"
)
IP_PORT_RE = re.compile(
    r"(?<![\w.])((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)):(\d{2,5})\b"
)
# IPv4-mapped tail (::ffff:192.0.2.1) is tried before a shorter hex prefix.
_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
_IPV4_TAIL = rf"(?:{_IPV4_OCTET}\.){{3}}{_IPV4_OCTET}"
IPV6_RE = re.compile(
    r"(?<![\w:])(?:"
    rf"(?:[A-Fa-f0-9]{{1,4}}:){{6}}{_IPV4_TAIL}|"
    rf"::(?:[A-Fa-f0-9]{{1,4}}:){{0,5}}{_IPV4_TAIL}|"
    rf"(?:[A-Fa-f0-9]{{1,4}}:){{1,4}}:(?:[A-Fa-f0-9]{{1,4}}:){{1,4}}{_IPV4_TAIL}|"
    rf"(?:[A-Fa-f0-9]{{1,4}}:){{1,5}}:{_IPV4_TAIL}|"
    r"(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,7}:|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|"
    r"::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}|"
    r"::)(?![\w:])"
)
# Bracketed IPv6 is a host, not the end of the URL (']' still ends a normal URL).
URL_RE = re.compile(
    r"(?i)\b(?:https?|hxxps?|ftp)://(?:"
    r"\[[A-Fa-f0-9:.]+\][^\s<>\"')\]]*"
    r"|[^\s<>\"')\]]+"
    r")"
)
EMAIL_RE = re.compile(
    r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b"
)
# Broad TLD: 2–24 letter labels or punycode. File-like suffixes filtered in _valid_domain.
# Do not start mid-label; do not end into an email local-part (`user@` → reject via (?!@)).
DOMAIN_RE = re.compile(
    r"(?i)(?<!@)(?<![A-Za-z0-9_-])(?:xn--[a-z0-9\-]+|[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:xn--[a-z0-9\-]{1,59}|[a-z]{2,24})(?![A-Za-z0-9_@-])"
)
# Unicode host the ASCII patterns miss. TLD is a known IDN ccTLD or an ASCII label.
_IDN_CCTLD = "рф|укр|срб|бел|қаз|мон|мкд"
_UNICODE_HOST_RE = re.compile(
    rf"(?iu)(?<![\w@.-])((?:[\w-]{{1,63}}\.)+(?:{_IDN_CCTLD}|[a-z]{{2,24}}))(?![\w@-])"
)
_UNICODE_EMAIL_RE = re.compile(
    rf"(?iu)(?<![\w.])([a-z0-9._%+\-]+@(?:[\w-]{{1,63}}\.)+(?:{_IDN_CCTLD}|[a-z]{{2,24}}))(?![\w-])"
)

# Auth-results / DKIM attribute names that look like domains (header.from, smtp.mailfrom).
_AUTH_ATTR_DOMAINS = frozenset(
    {
        "header.from",
        "header.d",
        "header.i",
        "header.s",
        "header.b",
        "header.a",
        "header.t",
        "header.h",
        "smtp.mailfrom",
        "smtp.helo",
        "smtp.rcptto",
        "smtp.auth",
        "smtp.vrfy",
        "smtp.rcpt",
    }
)

# Two-label free-text domains need a plausible TLD (kills ivan.petrov / header.from).
# Multi-label hosts (evil.corp.phishing) stay allowed for phishing gTLDs.
_COMMON_TLDS = frozenset(
    {
        # ccTLD / region
        "ru",
        "su",
        "by",
        "ua",
        "kz",
        "uz",
        "am",
        "ge",
        "kg",
        "tj",
        "tm",
        "az",
        "md",
        "uk",
        "de",
        "fr",
        "it",
        "es",
        "pl",
        "cz",
        "sk",
        "nl",
        "be",
        "ch",
        "at",
        "se",
        "no",
        "fi",
        "dk",
        "ie",
        "pt",
        "gr",
        "tr",
        "il",
        "ae",
        "sa",
        "in",
        "cn",
        "jp",
        "kr",
        "tw",
        "hk",
        "sg",
        "my",
        "th",
        "vn",
        "id",
        "ph",
        "au",
        "nz",
        "ca",
        "us",
        "br",
        "mx",
        "ar",
        "cl",
        "co",
        "za",
        "eu",
        "io",
        "ai",
        "me",
        "tv",
        "cc",
        "ws",
        "to",
        "nu",
        "fm",
        "gg",
        "im",
        "je",
        "lc",
        "vc",
        "gd",
        "ms",
        "tc",
        "vg",
        "ac",
        "sh",
        # gTLD / common brand
        "com",
        "org",
        "net",
        "edu",
        "gov",
        "mil",
        "int",
        "info",
        "biz",
        "name",
        "pro",
        "aero",
        "museum",
        "coop",
        "jobs",
        "mobi",
        "tel",
        "travel",
        "xxx",
        "online",
        "site",
        "website",
        "space",
        "tech",
        "store",
        "shop",
        "app",
        "dev",
        "cloud",
        "digital",
        "email",
        "mail",
        "bank",
        "finance",
        "money",
        "company",
        "ltd",
        "llc",
        "inc",
        "corp",
        "center",
        "world",
        "global",
        "today",
        "live",
        "news",
        "media",
        "blog",
        "club",
        "vip",
        "top",
        "xyz",
        "icu",
        "buzz",
        "click",
        "link",
        "win",
        "zip",
        "mov",
        "country",
        "agency",
        "solutions",
        "services",
        "support",
        "systems",
        "network",
        "security",
        "software",
        "technology",
        "group",
        "holdings",
        "international",
        "moscow",
        "tatar",
        # local / lab
        "local",
        "localhost",
        "internal",
        "lan",
        "home",
        "corp",
        "intranet",
        "test",
        "example",
        "invalid",
    }
)

# Header names whose values are Message-IDs — blank before IOC extract.
_MSGID_HEADER_RE = re.compile(
    r"(?im)^(message-id|in-reply-to|references)\s*:.*$"
)

# Final labels that are almost always local filenames / noise, not DNS TLDs.
_FILE_LIKE_TLDS = frozenset(
    {
        "txt",
        "log",
        "csv",
        "json",
        "xml",
        "html",
        "htm",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "bmp",
        "svg",
        "mp3",
        "mp4",
        "avi",
        "mkv",
        "exe",
        "dll",
        "sys",
        "bat",
        "cmd",
        "ps1",
        "vbs",
        "js",
        "jar",
        "msi",
        "dmg",
        "iso",
        "img",
        "rar",
        "7z",
        "gz",
        "tar",
        "cab",
        "apk",
        "ipa",
        "py",
        "rb",
        "go",
        "rs",
        "c",
        "cpp",
        "h",
        "java",
        "class",
        "obj",
        "o",
        "tmp",
        "bak",
        "old",
        "ini",
        "cfg",
        "conf",
        "yaml",
        "yml",
        "toml",
        "md",
        "rtf",
        "odt",
        "ods",
        "db",
        "sql",
        "dat",
        "bin",
        "raw",
        "pcap",
        "evtx",
        "lnk",
        "reg",
        "plist",
    }
)

# Note: gTLDs like zip/mov/win are allowed — used in phishing campaigns.
# Word-ish boundaries: avoid eating hex out of GUID/UUID middle segments.
MD5_RE = re.compile(r"(?<![A-Fa-f0-9])[a-fA-F0-9]{32}(?![A-Fa-f0-9])")
SHA1_RE = re.compile(r"(?<![A-Fa-f0-9])[a-fA-F0-9]{40}(?![A-Fa-f0-9])")
SHA256_RE = re.compile(r"(?<![A-Fa-f0-9])[a-fA-F0-9]{64}(?![A-Fa-f0-9])")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
# GUID / UUID shapes that look like 32 hex when dashes are ignored — reject as hashes.
_GUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)

# Host artifacts
WIN_PATH_RE = re.compile(
    r"(?i)\b([A-Z]:\\(?:[^\s<>\"'|?*\n]+\\)*[^\s<>\"'|?*\n]+)"
)
UNC_PATH_RE = re.compile(
    r"(?i)(\\\\[^\s\\/<>\"'|]+\\[^\s<>\"'|]+(?:\\[^\s<>\"'|]+)*)"
)
REGISTRY_RE = re.compile(
    r"(?i)\b((?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)"
    r"\\[^\s<>\"'|]+)"
)
MUTEX_RE = re.compile(
    r"(?i)\b((?:Global|Local)\\[A-Za-z0-9_\-\.]{3,128})"
)

# Crypto + messenger
BITCOIN_RE = re.compile(
    r"\b((?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62})\b"
)
MONERO_RE = re.compile(
    r"\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b"
)
MESSENGER_RE = re.compile(
    r"(?i)\b((?:https?://)?(?:t\.me|telegram\.me)/[A-Za-z0-9_/=?\-]+|"
    r"(?:https?://)?(?:discord\.gg|discord\.com/invite)/[A-Za-z0-9\-]+)\b"
)

# Careful command-line extraction (tickets / EDR alerts pasted as text)
CMDLINE_RE = re.compile(
    r"(?i)((?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|wscript(?:\.exe)?|"
    r"cscript(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|"
    r"certutil(?:\.exe)?|bitsadmin(?:\.exe)?)"
    r"[^\n\r]{0,400})"
)
# Require at least one suspicious signal so bare "cmd.exe" in prose is not an IOC.
_CMDLINE_SIGNAL_RE = re.compile(
    r"(?i)(?:-enc(?:odedcommand)?\b|-e\b|/c\b|-nop\b|-w(?:indowstyle)?\s+hidden|"
    r"-executionpolicy|downloadstring|iex\b|frombase64|invoke-|https?://|"
    r"\\\\[^\s\\]+\\|:[\\/]|%[a-z0-9_]+%|\$env:)"
)

PRIVATE_IPV4_PREFIXES = (
    "10.",
    "127.",
    "169.254.",
    "192.168.",
    "100.64.",  # CGNAT start; full /10 checked below
)
PRIVATE_IPV4_RANGES_16 = tuple(f"172.{i}." for i in range(16, 32))
_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

REWRITER_DOMAIN_SUFFIXES = (
    "safelinks.protection.outlook.com",
    "urldefense.com",
    "urldefense.proofpoint.com",
    "mimecast.com",
    "linkprotect.cudasvc.com",
)


def normalize_url_key(url: str) -> str:
    """Canonical key for URL dedup: host lower, no www, no fragment, trim slash."""
    raw = url.strip()
    try:
        p = urlparse(raw)
    except Exception:  # noqa: BLE001
        return raw.lower()
    scheme = (p.scheme or "http").lower()
    host = (p.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    netloc = host
    if p.port:
        netloc = f"{host}:{p.port}"
    path = p.path or ""
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    query = f"?{p.query}" if p.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def normalize_domain_key(domain: str) -> str:
    d = domain.lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


def _is_cgnat_ipv4(ip: str) -> bool:
    """RFC 6598 shared address space 100.64.0.0/10."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return a == 100 and 64 <= b <= 127


def _is_private_ipv4(ip: str) -> bool:
    if ip.startswith(PRIVATE_IPV4_PREFIXES) or ip.startswith(PRIVATE_IPV4_RANGES_16):
        return True
    if _is_cgnat_ipv4(ip):
        return True
    if ip.startswith("0.") or ip == "255.255.255.255":
        return True
    return False


def _is_private_ipv6(ip: str) -> bool:
    try:
        addr = ipaddress.IPv6Address(ip.split("%", 1)[0])
    except ValueError:
        return False
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or (
            addr.ipv4_mapped is not None
            and _is_private_ipv4(str(addr.ipv4_mapped))
        )
    )


def _hash_looks_like_guid_context(text: str, start: int, end: int) -> bool:
    """Reject hex that sits inside a dashed GUID / UUID."""
    window = text[max(0, start - 8) : min(len(text), end + 8)]
    if _GUID_RE.search(window):
        return True
    # Contiguous hex longer than the match → fragment of a larger blob / GUID stripped
    left = start > 0 and text[start - 1] in "0123456789abcdefABCDEF"
    right = end < len(text) and text[end] in "0123456789abcdefABCDEF"
    return left or right


def _hash_has_digit_and_letter(val: str) -> bool:
    """All-digit or all-alpha hex strings are usually not file hashes in tickets."""
    has_digit = any(c.isdigit() for c in val)
    has_alpha = any(c.isalpha() for c in val)
    return has_digit and has_alpha


def _context_snippet(text: str, match: re.Match[str], radius: int = 60) -> str:
    start = max(0, match.start() - radius)
    end = min(len(text), match.end() + radius)
    snippet = text[start:end].replace("\n", " ").strip()
    return snippet


def _is_rewriter_host(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in REWRITER_DOMAIN_SUFFIXES)


def _mask_msgid_headers(text: str) -> str:
    """Blank Message-ID / In-Reply-To / References values so they are not emails/domains."""

    def _blank(m: re.Match[str]) -> str:
        return " " * len(m.group(0))

    return _MSGID_HEADER_RE.sub(_blank, text)


# Mailbox headers whose <addr> is a real address, not a Message-ID.
# DSN recipient lines may put "rfc822;" between the colon and the bracket.
# A display name may sit there too: From: Boss <boss@evil.example>.
_ANGLE_MAILBOX_OK_RE = re.compile(
    r"(?i)(?:^|[\s;])(?:"
    r"from|to|cc|bcc|sender|reply-to|mail\s*from|rcpt\s*to|"
    r"return-path|delivered-to|envelope-to|"
    r"final-recipient|original-recipient"
    r")(?:"
    r"\s*:?(?:\s*[a-z0-9-]+\s*;)?\s*"
    r"|"
    r"\s*:(?:\s*[a-z0-9-]+\s*;)?\s+\S[^<>\n]{0,80}"
    r")$"
)


def _span_in_angle_msgid(text: str, start: int, end: int) -> bool:
    """True when the span sits in <…> and is not a mailbox header value."""
    left = text.rfind("<", 0, start)
    right = text.find(">", end)
    if left == -1 or right == -1 or not (left < start < end <= right):
        return False
    window = text[max(0, left - 64) : left]
    if _ANGLE_MAILBOX_OK_RE.search(window):
        return False
    return True


def _email_is_message_id_context(text: str, match: re.Match[str]) -> bool:
    """True when the address sits in <…> and is not a mailbox header."""
    return _span_in_angle_msgid(text, match.start(), match.end())


def _domain_in_angle_msgid(text: str, start: int, end: int) -> bool:
    """Skip hostnames that only appear inside Message-ID-like <…> tokens."""
    return _span_in_angle_msgid(text, start, end)


def _is_ignorable_host_char(ch: str) -> bool:
    """Soft hyphen / zero-width / combining marks that must not split a label."""
    if ch in "\u00ad\u200b\u200c\u200d\ufeff":
        return True
    return unicodedata.category(ch) in {"Cf", "Mn"}


def _extend_domain_left_label(text: str, start: int, end: int) -> tuple[int, str]:
    """Glue Unicode letters the ASCII domain regex skipped inside one label.

    ``kаspi.kz`` (Cyrillic а) is one host. Matching at ``spi.kz`` is a suffix,
    not a second domain. Invisible breaks (``ka\\u200bspi.kz``) are dropped.
    """
    left = start
    extra: list[str] = []
    while left > 0:
        ch = text[left - 1]
        if _is_ignorable_host_char(ch):
            left -= 1
            continue
        if ch.isalnum() or ch == "-":
            extra.append(ch)
            left -= 1
            continue
        break
    raw = text[start:end]
    if not extra:
        return start, raw
    return left, "".join(reversed(extra)) + raw


def _expand_domain_left(text: str, start: int, domain: str) -> str | None:
    """Pull preceding ``label.`` segments so ``mx1.mail.x`` is not truncated to ``mail.x``.

    Returns None when the match is the host of an email (owned by EMAIL_RE) or cannot
    form a valid hostname.
    """
    s = start
    d = domain
    while s > 1 and text[s - 1] == ".":
        j = s - 2
        while j >= 0 and (text[j].isalnum() or text[j] == "-"):
            j -= 1
        if j >= 0 and text[j] == "@":
            return None
        label = text[j + 1 : s - 1]
        if not label or not re.fullmatch(
            r"(?i)(?:xn--[a-z0-9\-]+|[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)", label
        ):
            break
        d = f"{label}.{d}"
        s = j + 1
    if s > 0 and text[s - 1] == "@":
        return None
    return d


def _unicode_host_ascii(host: str) -> str | None:
    """IDNA form of a Unicode host, or None when it is not a domain."""
    raw = (host or "").lower().rstrip(".")
    if not raw or not any(ord(ch) > 127 for ch in raw):
        return None
    ascii_dom, _is_idn = to_ascii_domain(raw)
    ascii_dom = (ascii_dom or "").lower().rstrip(".")
    if not ascii_dom or not _valid_domain(ascii_dom, free_text=True):
        return None
    return ascii_dom


def _valid_domain(domain: str, *, free_text: bool = False) -> bool:
    """Drop garbage domains produced by percent-encoding leftovers / filenames."""
    d = domain.lower().rstrip(".")
    if not d or d.startswith("-") or ".." in d or "\\" in d:
        return False
    if d in _AUTH_ATTR_DOMAINS or d.startswith("header.") or d.startswith("smtp."):
        return False
    labels = d.split(".")
    if len(labels) < 2:
        return False
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        return False
    tld = labels[-1]
    if tld in _FILE_LIKE_TLDS:
        return False
    if tld.isdigit():
        return False
    # Two-label free-text hosts need a real-ish TLD (ivan.petrov / header.from).
    if free_text and len(labels) == 2 and not tld.startswith("xn--") and tld not in _COMMON_TLDS:
        return False
    # Pure hex labels (percent-encoding leftovers), not real DNS.
    if re.fullmatch(r"[0-9a-f]{8,}", labels[0]) and any(c.isdigit() for c in labels[0]):
        return False
    return True


def _valid_port(port: str) -> bool:
    try:
        n = int(port)
    except ValueError:
        return False
    return 1 <= n <= 65535


def _b58decode(s: str) -> bytes | None:
    try:
        n = 0
        for byte in s.encode("ascii"):
            n = n * 58 + _BASE58_ALPHABET.index(byte)
    except (ValueError, UnicodeEncodeError):
        return None
    # Preserve leading zeros (Base58 '1')
    pad = 0
    for char in s:
        if char == "1":
            pad += 1
        else:
            break
    full = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return b"\x00" * pad + full


def _bitcoin_base58check(addr: str) -> bool:
    raw = _b58decode(addr)
    if raw is None or len(raw) < 25:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return checksum == digest


def _bech32_polymod(values: list[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bitcoin_bech32(addr: str) -> bool:
    """Lightweight Bech32/Bech32m check for bc1… addresses."""
    s = addr.lower()
    if not (14 <= len(s) <= 74) or not s.startswith("bc1"):
        return False
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    pos = s.rfind("1")
    if pos < 1:
        return False
    hrp, data_part = s[:pos], s[pos + 1 :]
    if hrp != "bc" or len(data_part) < 6:
        return False
    try:
        data = [charset.index(c) for c in data_part]
    except ValueError:
        return False
    hrp_expand = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    mod = _bech32_polymod(hrp_expand + data)
    return mod in (1, 0x2BC830A3)  # bech32 / bech32m


def _looks_like_bitcoin(addr: str) -> bool:
    low = addr.lower()
    if low.startswith("bc1"):
        return _bitcoin_bech32(addr)
    if not (26 <= len(addr) <= 35):
        return False
    return _bitcoin_base58check(addr)


def _trim_cmdline(cmd: str) -> str:
    """Keep the process invocation; drop trailing ticket prose."""
    cmd = cmd.strip().rstrip(".,;")
    # Cut at double-space + capital letter run typical of pasted prose
    m = re.search(r"\s{2,}(?=[A-ZА-Я])", cmd)
    if m and m.start() >= 12:
        cmd = cmd[: m.start()]
    if len(cmd) > 240:
        cmd = cmd[:240].rstrip()
    return cmd


def _url_userinfo_ats(text: str) -> set[int]:
    """Absolute indexes of '@' that separate URL userinfo from the host."""
    ats: set[int] = set()
    for match in URL_RE.finditer(text):
        url = match.group(0)
        scheme_idx = url.find("://")
        if scheme_idx < 0:
            continue
        rest_start = scheme_idx + 3
        rest = url[rest_start:]
        cut = len(rest)
        for sep in "/?#":
            pos = rest.find(sep)
            if 0 <= pos < cut:
                cut = pos
        rel = rest[:cut].rfind("@")
        if rel >= 0:
            ats.add(match.start() + rest_start + rel)
    return ats


def _url_hostname(url: str) -> str | None:
    """Host of an already found URL. Percent-decoding stays on this copy."""
    try:
        return urlparse(unquote(url)).hostname
    except ValueError:
        return None


def _mask_url_tails(text: str) -> str:
    """Blank URL path, query and fragment so a file segment is not a domain."""

    def repl(match: re.Match[str]) -> str:
        url = match.group(0)
        scheme_idx = url.find("://")
        if scheme_idx < 0:
            return url
        rest = url[scheme_idx + 3 :]
        cut = len(rest)
        for sep in ("/", "?", "#"):
            pos = rest.find(sep)
            if pos >= 0:
                cut = min(cut, pos)
        if cut == len(rest):
            return url
        start = scheme_idx + 3 + cut
        return url[:start] + (" " * (len(url) - start))

    return URL_RE.sub(repl, text)


# Numeric (&#46;) and named (&amp;) entities on a URL that was already found.
_URL_ENTITY_RE = re.compile(r"&(?:#\d+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]+);")


def extract_iocs(text: str, source: str = "text") -> list[Ioc]:
    """Extract and deduplicate IOCs from arbitrary text."""
    if not text:
        return []

    # Percent-decoding the whole blob turns %40 into a foreign mailbox and
    # splits a URL on %20. Decode only the host of a URL that was already found.
    cleaned = _mask_msgid_headers(defang(text))
    userinfo_ats = _url_userinfo_ats(cleaned)
    found: dict[tuple[str, str], Ioc] = {}

    def add(
        value: str,
        ioc_type: IocType,
        match: re.Match[str],
        tags: list[str] | None = None,
    ) -> None:
        if ioc_type == IocType.URL:
            key = (ioc_type.value, normalize_url_key(value))
        elif ioc_type == IocType.DOMAIN:
            key = (ioc_type.value, normalize_domain_key(value))
        else:
            key = (ioc_type.value, value.lower())
        ctx = _context_snippet(cleaned, match)
        if key in found:
            prev = found[key]
            if value != prev.value and value.lower() not in (prev.context or "").lower():
                prev.context = f"{prev.context} ‖ variant:{value}"[:400]
            for t in tags or []:
                if t not in prev.tags:
                    prev.tags.append(t)
            return
        store_value = value
        if ioc_type == IocType.DOMAIN:
            store_value = normalize_domain_key(value)
        found[key] = Ioc(
            value=store_value,
            ioc_type=ioc_type,
            source=source,
            context=ctx,
            tags=list(tags or []),
        )

    messenger_urls: set[str] = set()
    for m in MESSENGER_RE.finditer(cleaned):
        raw = m.group(1).rstrip(".,;:!?")
        value = raw if "://" in raw.lower() else f"https://{raw}"
        tags = ["telegram"] if "t.me" in value.lower() or "telegram" in value.lower() else ["discord"]
        add(value, IocType.MESSENGER, m, tags)
        messenger_urls.add(normalize_url_key(value))

    for m in URL_RE.finditer(cleaned):
        url = m.group(0).rstrip(".,;:!?")
        if _URL_ENTITY_RE.search(url):
            url = unescape(url)
        if normalize_url_key(url) in messenger_urls:
            continue
        tags = []
        if "hxxp" in m.group(0).lower():
            tags.append("was_defanged")
        add(url, IocType.URL, m, tags)
        host = _url_hostname(url)
        if host and not _is_private_ipv4(host):
            if re.fullmatch(IPV4_RE, host):
                add(host, IocType.IPV4, m, ["from_url"])
            elif "." in host and _valid_domain(host):
                tags_d = ["from_url"]
                if _is_rewriter_host(host):
                    tags_d.append("url_rewriter")
                add(host.lower(), IocType.DOMAIN, m, tags_d)

    for m in EMAIL_RE.finditer(cleaned):
        if _email_is_message_id_context(cleaned, m):
            continue
        at_pos = m.start() + m.group(0).rfind("@")
        if at_pos in userinfo_ats:
            continue
        email = m.group(0).lower()
        add(email, IocType.EMAIL, m)
        domain = email.split("@", 1)[1]
        if _valid_domain(domain):
            add(domain, IocType.DOMAIN, m, ["from_email"])

    for m in IP_PORT_RE.finditer(cleaned):
        ip, port = m.group(1), m.group(2)
        if not _valid_port(port):
            continue
        tags = ["private"] if _is_private_ipv4(ip) else []
        add(f"{ip}:{port}", IocType.IP_PORT, m, tags)
        add(ip, IocType.IPV4, m, tags)

    for m in IPV4_RE.finditer(cleaned):
        ip = m.group(0)
        tags = ["private"] if _is_private_ipv4(ip) else []
        add(ip, IocType.IPV4, m, tags)

    for m in IPV6_RE.finditer(cleaned):
        ip6 = m.group(0)
        tags = ["private"] if _is_private_ipv6(ip6) else []
        add(ip6, IocType.IPV6, m, tags)

    for m in SHA256_RE.finditer(cleaned):
        val = m.group(0).lower()
        if _hash_looks_like_guid_context(cleaned, m.start(), m.end()):
            continue
        if not _hash_has_digit_and_letter(val):
            continue
        add(val, IocType.SHA256, m)

    for m in SHA1_RE.finditer(cleaned):
        val = m.group(0).lower()
        if _hash_looks_like_guid_context(cleaned, m.start(), m.end()):
            continue
        if not _hash_has_digit_and_letter(val):
            continue
        if any(i.ioc_type == IocType.SHA256 and val in i.value for i in found.values()):
            continue
        add(val, IocType.SHA1, m)

    for m in MD5_RE.finditer(cleaned):
        val = m.group(0).lower()
        if _hash_looks_like_guid_context(cleaned, m.start(), m.end()):
            continue
        if not _hash_has_digit_and_letter(val):
            continue
        if any(
            i.ioc_type in (IocType.SHA1, IocType.SHA256) and val in i.value
            for i in found.values()
        ):
            continue
        add(val, IocType.MD5, m)

    for m in CVE_RE.finditer(cleaned):
        add(m.group(0).upper(), IocType.CVE, m)

    for m in UNC_PATH_RE.finditer(cleaned):
        path = m.group(1).rstrip(".,;:)")
        if path.count("\\") >= 3:
            add(path, IocType.UNC, m)

    for m in WIN_PATH_RE.finditer(cleaned):
        path = m.group(1).rstrip(".,;:)")
        if "\\" in path and len(path) >= 6:
            add(path, IocType.FILEPATH, m)

    for m in REGISTRY_RE.finditer(cleaned):
        key = m.group(1).rstrip(".,;:)")
        add(key, IocType.REGISTRY, m)

    for m in MUTEX_RE.finditer(cleaned):
        add(m.group(1), IocType.MUTEX, m)

    for m in BITCOIN_RE.finditer(cleaned):
        addr = m.group(1)
        if _looks_like_bitcoin(addr) and not re.fullmatch(r"[a-fA-F0-9]{32,64}", addr):
            add(addr, IocType.BITCOIN, m)

    for m in MONERO_RE.finditer(cleaned):
        add(m.group(1), IocType.MONERO, m)

    for m in CMDLINE_RE.finditer(cleaned):
        cmd = _trim_cmdline(m.group(1))
        if len(cmd) < 12 or not _CMDLINE_SIGNAL_RE.search(cmd):
            continue
        add(cmd, IocType.COMMAND_LINE, m, ["process"])

    for m in DOMAIN_RE.finditer(_mask_url_tails(cleaned)):
        raw = m.group(0).rstrip(".")
        start, raw = _extend_domain_left_label(cleaned, m.start(), m.end())
        raw = raw.rstrip(".")
        end = m.end()
        if start != m.start() and not _valid_domain(raw, free_text=True):
            start, raw = m.start(), m.group(0).rstrip(".")
        if _domain_in_angle_msgid(cleaned, start, end):
            continue
        at = start
        while at > 0 and _is_ignorable_host_char(cleaned[at - 1]):
            at -= 1
        if at > 0 and cleaned[at - 1] == "@":
            if (at - 1) in userinfo_ats:
                continue
            local_end = at - 1
            local_start = local_end
            while local_start > 0 and (
                cleaned[local_start - 1].isalnum() or cleaned[local_start - 1] in "._%+-"
            ):
                local_start -= 1
            local = cleaned[local_start:local_end]
            if local and _valid_domain(raw, free_text=True):
                add(f"{local.lower()}@{raw.lower()}", IocType.EMAIL, m)
                add(raw.lower(), IocType.DOMAIN, m, ["from_email"])
            continue
        expanded = _expand_domain_left(cleaned, start, raw)
        if expanded is None:
            continue
        domain = expanded.lower().rstrip(".")
        if not _valid_domain(domain, free_text=True):
            continue
        tags = ["url_rewriter"] if _is_rewriter_host(domain) else []
        if domain.startswith("xn--") or ".xn--" in domain:
            tags.append("punycode")
        add(domain, IocType.DOMAIN, m, tags)

    for m in _UNICODE_EMAIL_RE.finditer(cleaned):
        if _email_is_message_id_context(cleaned, m):
            continue
        email = m.group(1).lower()
        host = email.split("@", 1)[1]
        if _unicode_host_ascii(host) is None:
            continue
        add(email, IocType.EMAIL, m)
        add(host, IocType.DOMAIN, m, ["from_email"])

    for m in _UNICODE_HOST_RE.finditer(cleaned):
        if _domain_in_angle_msgid(cleaned, m.start(), m.end()):
            continue
        host = m.group(1).lower().rstrip(".")
        if _unicode_host_ascii(host) is None:
            continue
        at = m.start()
        if at > 0 and cleaned[at - 1] == "@":
            continue
        add(host, IocType.DOMAIN, m)

    return list(found.values())
