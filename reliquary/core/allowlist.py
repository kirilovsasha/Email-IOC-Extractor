"""Built-in allowlist — tag known-safe mail/CDN hosts to cut IOC noise.

Optional local overrides: ``allowlist_extra.txt`` next to the exe/project,
or an explicit path from CLI / prefs (domains and IPs, one per line).
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from reliquary.core.paths import app_dir

# CDN / mail infra / link wrappers — tagged allowlisted (filterable in GUI).
DEFAULT_ALLOW_DOMAINS = frozenset(
    {
        "microsoft.com",
        "microsoftonline.com",
        "office.com",
        "office365.com",
        "outlook.com",
        "live.com",
        "googleapis.com",
        "google.com",
        "gstatic.com",
        "youtube.com",
        "cloudflare.com",
        "akamaihd.net",
        "akamaized.net",
        "amazon.com",
        "amazonaws.com",
        "azure.com",
        "windows.net",
        "apple.com",
        "icloud.com",
        "github.com",
        "githubusercontent.com",
        "linkedin.com",
        "facebook.com",
        "fbcdn.net",
        "twitter.com",
        "x.com",
        "twimg.com",
        "safelinks.protection.outlook.com",
        "urldefense.proofpoint.com",
        "urldefense.com",
        "mimecast.com",
        "linkprotect.cudasvc.com",
    }
)

DEFAULT_ALLOW_IPS = frozenset(
    {
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
    }
)

_EXTRA_NAME = "allowlist_extra.txt"
_IP_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$|^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
)


def default_extra_allowlist_path() -> Path:
    return app_dir() / _EXTRA_NAME


def resolve_allowlist_path(explicit: str | Path | None = None) -> Path | None:
    """Explicit path wins; otherwise ``allowlist_extra.txt`` next to app if present."""
    if explicit is not None and str(explicit).strip():
        return Path(str(explicit).strip())
    candidate = default_extra_allowlist_path()
    return candidate if candidate.is_file() else None


def parse_allowlist_lines(text: str) -> tuple[set[str], set[str]]:
    """Parse allowlist file body into (domains, ips).

    Lines: ``#`` comments ignored. Optional prefixes ``domain:`` / ``ip:``.
    Bare IPv4/IPv6 → IP set; everything else → domain set (supports ``*.cdn.example``).
    """
    domains: set[str] = set()
    ips: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if lower.startswith("domain:"):
            val = line.split(":", 1)[1].strip().lower().rstrip(".")
            if val:
                domains.add(val)
            continue
        if lower.startswith("ip:"):
            val = line.split(":", 1)[1].strip().lower()
            if val:
                ips.add(val)
            continue
        val = lower.rstrip(".")
        if _IP_RE.match(val) or ":" in val and val.count(":") >= 2:
            ips.add(val)
        else:
            domains.add(val)
    return domains, ips


def load_extra_allowlist(path: str | Path | None) -> tuple[set[str], set[str]]:
    if path is None:
        return set(), set()
    p = Path(path)
    if not p.is_file():
        return set(), set()
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return set(), set()
    return parse_allowlist_lines(text)


def build_allowlist(
    *,
    extra_path: str | Path | None = None,
    extra_domains: set[str] | None = None,
    extra_ips: set[str] | None = None,
) -> tuple[set[str], set[str]]:
    """Built-in allowlist merged with optional file / in-memory extras."""
    domains = set(DEFAULT_ALLOW_DOMAINS)
    ips = set(DEFAULT_ALLOW_IPS)
    path = resolve_allowlist_path(extra_path)
    file_domains, file_ips = load_extra_allowlist(path)
    domains |= file_domains
    ips |= file_ips
    if extra_domains:
        domains |= {d.lower().rstrip(".") for d in extra_domains if d}
    if extra_ips:
        ips |= {i.lower() for i in extra_ips if i}
    return domains, ips


def _wildcard_match(value: str, pattern: str) -> bool:
    if "*" not in pattern:
        return value == pattern
    parts = pattern.split("*")
    regex = "^" + ".*".join(re.escape(p) for p in parts) + "$"
    return re.match(regex, value, re.IGNORECASE) is not None


def domain_matches(host: str, domains: set[str]) -> bool:
    h = host.lower().rstrip(".")
    for d in domains:
        if "*" in d:
            if _wildcard_match(h, d):
                return True
            continue
        if h == d or h.endswith("." + d):
            return True
    return False


def value_matches(val: str, patterns: set[str]) -> bool:
    v = val.lower().rstrip(".")
    for p in patterns:
        if "*" in p:
            if _wildcard_match(v, p):
                return True
        elif v == p:
            return True
    return False


def tag_allowlist(iocs, allow_domains: set[str], allow_ips: set[str]) -> None:
    """Mutate IOC tags in place: allowlisted."""
    for ioc in iocs:
        val = ioc.value.lower().rstrip(".")
        itype = ioc.ioc_type.value
        if itype in ("domain", "email", "url", "messenger"):
            host = val
            if itype == "email" and "@" in val:
                host = val.split("@", 1)[1]
            elif itype in ("url", "messenger"):
                host = urlparse(val if "://" in val else f"https://{val}").hostname or ""
            if host and domain_matches(host, allow_domains):
                if "allowlisted" not in ioc.tags:
                    ioc.tags.append("allowlisted")
        elif itype in ("ipv4", "ip_port"):
            ip = val.split(":", 1)[0]
            if value_matches(ip, allow_ips) or ip in allow_ips:
                if "allowlisted" not in ioc.tags:
                    ioc.tags.append("allowlisted")
