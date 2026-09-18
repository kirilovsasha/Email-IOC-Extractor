"""Default and user allowlists / denylists for IOC noise control."""

from __future__ import annotations

from pathlib import Path

from reliquary.core.paths import config_path, ensure_user_lists

# CDN / mail infra / telemetry — tag as allowlisted (kept, but filterable).
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


def load_list_file(name: str) -> set[str]:
    """Load one entry per line from app dir (exe folder or project root)."""
    ensure_user_lists()
    path = config_path(name)
    if not path.is_file():
        return set()
    out: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return set()
    for line in lines:
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        out.add(line)
    return out


def list_file_path(name: str) -> Path:
    ensure_user_lists()
    return config_path(name)


def build_allowlist() -> tuple[set[str], set[str]]:
    domains = set(DEFAULT_ALLOW_DOMAINS) | {
        e for e in load_list_file("allowlist.txt") if not _looks_like_ip(e)
    }
    ips = set(DEFAULT_ALLOW_IPS) | {
        e for e in load_list_file("allowlist.txt") if _looks_like_ip(e)
    }
    return domains, ips


def build_denylist() -> set[str]:
    return load_list_file("denylist.txt")


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def domain_matches(host: str, domains: set[str]) -> bool:
    h = host.lower().rstrip(".")
    if h in domains:
        return True
    return any(h.endswith("." + d) for d in domains)


def tag_allowlist_denylist(iocs, allow_domains: set[str], allow_ips: set[str], deny: set[str]) -> None:
    """Mutate IOC tags in place: allowlisted / denylisted."""
    for ioc in iocs:
        val = ioc.value.lower().rstrip(".")
        itype = ioc.ioc_type.value
        if itype in ("domain", "email", "url", "messenger"):
            host = val
            if itype == "email" and "@" in val:
                host = val.split("@", 1)[1]
            elif itype in ("url", "messenger"):
                from urllib.parse import urlparse

                host = urlparse(val if "://" in val else f"https://{val}").hostname or ""
            if host and domain_matches(host, allow_domains):
                if "allowlisted" not in ioc.tags:
                    ioc.tags.append("allowlisted")
            if val in deny or (host and domain_matches(host, deny)):
                if "denylisted" not in ioc.tags:
                    ioc.tags.append("denylisted")
        elif itype in ("ipv4", "ip_port"):
            ip = val.split(":", 1)[0]
            if ip in allow_ips:
                if "allowlisted" not in ioc.tags:
                    ioc.tags.append("allowlisted")
            if ip in deny or val in deny:
                if "denylisted" not in ioc.tags:
                    ioc.tags.append("denylisted")
        else:
            if val in deny:
                if "denylisted" not in ioc.tags:
                    ioc.tags.append("denylisted")
