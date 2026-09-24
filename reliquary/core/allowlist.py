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


# Suffix match stays for mail and CDN hosts. These roots also cover user buckets.
_CLOUD_STORAGE_ROOTS = frozenset(
    {
        "amazonaws.com",
        "windows.net",
        "azure.com",
        "googleapis.com",
        "githubusercontent.com",
        "google.com",
        "live.com",
        "office.com",
    }
)

# Product hosts where the user owns the content. Mail and CDN names stay listed.
_GOOGLE_USER_HOSTS = (
    "drive.google.com",
    "docs.google.com",
    "sites.google.com",
    "script.google.com",
    "storage.cloud.google.com",
)

# User content on Microsoft consumer hosts. Mail names stay allowlisted.
_MS_USER_HOSTS = (
    "onedrive.live.com",
    "storage.live.com",
    "sway.office.com",
)


def _is_path_style_s3(host: str) -> bool:
    """S3 endpoint: the bucket is in the path, not in the hostname."""
    if not host.endswith(".amazonaws.com"):
        return False
    return host == "s3.amazonaws.com" or host.startswith(("s3.", "s3-"))


def _is_google_user_host(host: str) -> bool:
    return any(host == name or host.endswith("." + name) for name in _GOOGLE_USER_HOSTS)


def _is_ms_user_host(host: str) -> bool:
    return any(host == name or host.endswith("." + name) for name in _MS_USER_HOSTS)


def is_user_cloud_storage_host(host: str) -> bool:
    """User bucket / Drive host, not the provider's own mail or CDN name."""
    h = (host or "").lower().rstrip(".")
    if not h:
        return False
    if h.endswith(".amazonaws.com") and (".s3." in h or ".s3-" in h):
        if not (h.startswith("s3.") or h.startswith("s3-")):
            return True
    if _is_path_style_s3(h) or _is_google_user_host(h) or _is_ms_user_host(h):
        return True
    if re.search(
        r"^[a-z0-9][a-z0-9-]{1,62}\.(?:blob|file|dfs|web)\.core\.windows\.net$",
        h,
    ):
        return True
    if h == "storage.googleapis.com" or h.endswith(".storage.googleapis.com"):
        return True
    if h.endswith(".githubusercontent.com"):
        return True
    if h.endswith(".azure.com") and (".blob." in h or ".storage." in h or ".file." in h):
        return True
    return False


def domain_matches(host: str, domains: set[str]) -> bool:
    h = host.lower().rstrip(".")
    user_cloud = is_user_cloud_storage_host(h)
    for d in domains:
        if "*" in d:
            if _wildcard_match(h, d):
                return True
            continue
        if h == d:
            return True
        if h.endswith("." + d):
            if user_cloud and d in _CLOUD_STORAGE_ROOTS:
                continue
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
        elif itype == "ipv6":
            if value_matches(val, allow_ips) or val in allow_ips:
                if "allowlisted" not in ioc.tags:
                    ioc.tags.append("allowlisted")
        elif itype in ("ipv4", "ip_port"):
            ip = val.split(":", 1)[0]
            if value_matches(ip, allow_ips) or ip in allow_ips:
                if "allowlisted" not in ioc.tags:
                    ioc.tags.append("allowlisted")


def append_allowlist_entry(
    entry: str,
    *,
    path: str | Path | None = None,
) -> Path:
    """Append a domain/IP to ``allowlist_extra.txt`` (create if missing).

    Returns the path written. Raises ``ValueError`` on empty entry.
    """
    raw = (entry or "").strip().lower().rstrip(".")
    if not raw:
        raise ValueError("empty allowlist entry")
    # Strip URL/email to host when possible
    if "@" in raw and "://" not in raw:
        raw = raw.split("@", 1)[-1]
    elif "://" in raw or raw.startswith("www."):
        host = urlparse(raw if "://" in raw else f"https://{raw}").hostname
        if host:
            raw = host.lower().rstrip(".")
    target = (
        Path(path) if path is not None and str(path).strip() else default_extra_allowlist_path()
    )
    existing_domains, existing_ips = load_extra_allowlist(
        target if target.is_file() else None
    )
    is_ip = bool(_IP_RE.match(raw) or (":" in raw and raw.count(":") >= 2))
    if is_ip and raw in existing_ips:
        return target
    if not is_ip and raw in existing_domains:
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    prefix = "ip:" if is_ip else "domain:"
    with target.open("a", encoding="utf-8") as fh:
        fh.write(f"{prefix}{raw}\n")
    return target
