"""Default and user allowlists / denylists for IOC noise control."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from reliquary.core.paths import config_path, ensure_user_lists, file_mtime_iso

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

_ENTRY_RE = re.compile(r"^([^#]+?)(?:\s+#\s*(.*))?$")


def parse_list_line(line: str) -> tuple[str, str] | None:
    """Return (entry, ticket_comment) or None for empty/comment lines."""
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    m = _ENTRY_RE.match(raw)
    if not m:
        return None
    entry = m.group(1).strip().lower()
    comment = (m.group(2) or "").strip()
    if not entry:
        return None
    return entry, comment


def load_list_entries(name: str) -> list[tuple[str, str]]:
    """Load (entry, comment) pairs from app dir."""
    ensure_user_lists()
    path = config_path(name)
    if not path.is_file():
        return []
    out: list[tuple[str, str]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        parsed = parse_list_line(line)
        if parsed:
            out.append(parsed)
    return out


def load_list_file(name: str) -> set[str]:
    """Load entries (without comments) from app dir."""
    return {e for e, _ in load_list_entries(name)}


def list_file_path(name: str) -> Path:
    ensure_user_lists()
    return config_path(name)


def list_mtime_label(name: str) -> str:
    path = list_file_path(name)
    stamp = file_mtime_iso(path)
    return stamp or "—"


def build_allowlist() -> tuple[set[str], set[str]]:
    entries = load_list_file("allowlist.txt")
    domains = set(DEFAULT_ALLOW_DOMAINS) | {e for e in entries if not _looks_like_ip(e)}
    ips = set(DEFAULT_ALLOW_IPS) | {e for e in entries if _looks_like_ip(e)}
    return domains, ips


def build_denylist() -> set[str]:
    return load_list_file("denylist.txt")


def _looks_like_ip(value: str) -> bool:
    # Strip wildcard noise for classification
    bare = value.replace("*", "")
    parts = bare.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts if p != "")
    except ValueError:
        return False


def _wildcard_match(value: str, pattern: str) -> bool:
    """Simple glob: * only. Exact and suffix domain match also via domain_matches."""
    if "*" not in pattern:
        return value == pattern
    # Escape then restore *
    parts = pattern.split("*")
    if not parts:
        return False
    # Build regex
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
            if value_matches(val, deny) or (host and domain_matches(host, deny)):
                if "denylisted" not in ioc.tags:
                    ioc.tags.append("denylisted")
        elif itype in ("ipv4", "ip_port"):
            ip = val.split(":", 1)[0]
            if value_matches(ip, allow_ips) or ip in allow_ips:
                if "allowlisted" not in ioc.tags:
                    ioc.tags.append("allowlisted")
            if value_matches(ip, deny) or value_matches(val, deny):
                if "denylisted" not in ioc.tags:
                    ioc.tags.append("denylisted")
        else:
            if value_matches(val, deny):
                if "denylisted" not in ioc.tags:
                    ioc.tags.append("denylisted")


def append_list_entries(name: str, entries: list[str], comment: str = "") -> int:
    """Append unique entries to allow/deny list. Returns count added."""
    ensure_user_lists()
    path = config_path(name)
    existing = load_list_file(name)
    added = 0
    lines: list[str] = []
    for raw in entries:
        parsed = parse_list_line(raw) if "#" in raw else None
        if parsed:
            entry, cmt = parsed
        else:
            entry = raw.strip().lower()
            cmt = comment
        if not entry or entry.startswith("#"):
            continue
        if entry in existing:
            continue
        existing.add(entry)
        if cmt:
            lines.append(f"{entry}  # {cmt}")
        else:
            lines.append(entry)
        added += 1
    if not lines:
        return 0
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n")
        fh.write("\n".join(lines))
        fh.write("\n")
    return added


def import_entries_from_csv(path: str | Path, *, column: str | None = None) -> list[str]:
    """Extract indicator-like values from CSV (column name or first column)."""
    p = Path(path)
    text = p.read_text(encoding="utf-8-sig", errors="replace")
    reader = csv.DictReader(text.splitlines())
    out: list[str] = []
    if reader.fieldnames:
        col = column
        if col is None:
            for candidate in ("value", "indicator", "ioc", "domain", "ip", "Attribute.value"):
                if candidate in reader.fieldnames:
                    col = candidate
                    break
            if col is None:
                col = reader.fieldnames[0]
        for row in reader:
            val = (row.get(col) or "").strip()
            if val:
                out.append(val)
        return out
    # No header — plain lines
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line.split(",")[0].strip())
    return out


def import_entries_from_misp(path: str | Path) -> list[str]:
    """Pull Attribute.value (and similar) from MISP event JSON."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    values: list[str] = []

    def _walk(obj):
        if isinstance(obj, dict):
            if "value" in obj and isinstance(obj["value"], str):
                # Prefer Attribute-like objects
                if obj.get("type") or "category" in obj or "Event" in obj or "Attribute" in str(
                    type(obj)
                ):
                    values.append(obj["value"])
                elif "Attribute" not in obj and "Event" not in obj:
                    values.append(obj["value"])
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    event = data.get("Event", data)
    attrs = event.get("Attribute") if isinstance(event, dict) else None
    if isinstance(attrs, list):
        for attr in attrs:
            if isinstance(attr, dict) and attr.get("value"):
                values.append(str(attr["value"]))
    else:
        _walk(data)
    # Dedup preserve order
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        key = v.strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(v.strip())
    return out
