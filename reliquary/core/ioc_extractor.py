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
IP_PORT_RE = re.compile(
    r"(?<![\w.])((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)):(\d{2,5})\b"
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
# Broad TLD: 2–24 letter labels or punycode. File-like suffixes filtered in _valid_domain.
DOMAIN_RE = re.compile(
    r"(?i)(?<!@)(?<![A-Fa-f0-9])\b(?:xn--[a-z0-9\-]+|[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:xn--[a-z0-9\-]{1,59}|[a-z]{2,24})\b"
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
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

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
    r"[^\n\r]{8,400})"
)

PRIVATE_IPV4_PREFIXES = (
    "10.",
    "127.",
    "169.254.",
    "192.168.",
)
PRIVATE_IPV4_RANGES_16 = tuple(f"172.{i}." for i in range(16, 32))

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
    return text[start:end].replace("\n", " ").strip()


def _is_rewriter_host(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in REWRITER_DOMAIN_SUFFIXES)


def _valid_domain(domain: str) -> bool:
    """Drop garbage domains produced by percent-encoding leftovers / filenames."""
    d = domain.lower().rstrip(".")
    if not d or d.startswith("-") or ".." in d:
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
    if re.match(r"^[0-9a-f]{2}[a-z]", labels[0]) and not re.match(r"^\d", labels[0]):
        return False
    return True


def _valid_port(port: str) -> bool:
    try:
        n = int(port)
    except ValueError:
        return False
    return 1 <= n <= 65535


def _looks_like_bitcoin(addr: str) -> bool:
    if addr.lower().startswith("bc1"):
        return 14 <= len(addr) <= 74
    return 26 <= len(addr) <= 35


def extract_iocs(text: str, source: str = "text") -> list[Ioc]:
    """Extract and deduplicate IOCs from arbitrary text."""
    if not text:
        return []

    cleaned = unquote(defang(text))
    found: dict[tuple[str, str], Ioc] = {}

    def add(
        value: str,
        ioc_type: IocType,
        match: re.Match[str],
        tags: list[str] | None = None,
    ) -> None:
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

    for m in MESSENGER_RE.finditer(cleaned):
        raw = m.group(1).rstrip(".,;:!?")
        value = raw if "://" in raw.lower() else f"https://{raw}"
        tags = ["telegram"] if "t.me" in value.lower() or "telegram" in value.lower() else ["discord"]
        add(value, IocType.MESSENGER, m, tags)
        add(value, IocType.URL, m, ["messenger", *tags])

    for m in URL_RE.finditer(cleaned):
        url = m.group(0).rstrip(".,;:!?")
        tags = []
        if "hxxp" in m.group(0).lower():
            tags.append("was_defanged")
        add(url, IocType.URL, m, tags)
        host = urlparse(url).hostname
        if host and not _is_private_ipv4(host):
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
        add(m.group(0), IocType.IPV6, m)

    for m in SHA256_RE.finditer(cleaned):
        add(m.group(0).lower(), IocType.SHA256, m)

    for m in SHA1_RE.finditer(cleaned):
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
        cmd = m.group(1).strip().rstrip(".,;")
        if len(cmd) >= 12:
            add(cmd, IocType.COMMAND_LINE, m, ["process"])

    for m in DOMAIN_RE.finditer(cleaned):
        domain = m.group(0).lower().rstrip(".")
        if not _valid_domain(domain):
            continue
        tags = ["url_rewriter"] if _is_rewriter_host(domain) else []
        if domain.startswith("xn--") or ".xn--" in domain:
            tags.append("punycode")
        add(domain, IocType.DOMAIN, m, tags)

    return list(found.values())
