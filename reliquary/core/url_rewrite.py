"""Unwrap enterprise URL rewriters without network access."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote, urlparse

from reliquary.core.models import UrlRewriteResult

# Patterns for common secure-email / proxy wrappers.
PROOFPOINT_V2 = re.compile(
    r"https?://urldefense(?:\.proofpoint)?\.com/v2/url\?[^\\s\"'<>]+",
    re.IGNORECASE,
)
PROOFPOINT_V3 = re.compile(
    r"https?://urldefense(?:\.proofpoint)?\.com/v3/__[^_]+__[^\\s\"'<>]*",
    re.IGNORECASE,
)
SAFELINKS = re.compile(
    r"https?://[a-z0-9.-]*safelinks\.protection\.outlook\.com/\?[^\\s\"'<>]+",
    re.IGNORECASE,
)
MIMECAST = re.compile(
    r"https?://[a-z0-9.-]*mimecast\.com/[^\\s\"'<>]*",
    re.IGNORECASE,
)
BARRACUDA = re.compile(
    r"https?://linkprotect\.cudasvc\.com/url\?[^\\s\"'<>]+",
    re.IGNORECASE,
)
FIREYE = re.compile(
    r"https?://[a-z0-9.-]*fireeye\.com/[^\\s\"'<>]*url\?[^\\s\"'<>]+",
    re.IGNORECASE,
)
CISCO_UMBRELLA = re.compile(
    r"https?://(?:secure-web\.cisco\.com|.*\.url\.trendmicro\.com)/[^\\s\"'<>]+",
    re.IGNORECASE,
)
GOOGLE_REDIRECT = re.compile(
    r"https?://(?:www\.)?google\.[a-z.]+/url\?[^\\s\"'<>]+",
    re.IGNORECASE,
)
DEFENDER_ATP = re.compile(
    r"https?://[a-z0-9.-]*(?:safelinks\.protection\.outlook\.com|"
    r"protection\.office\.com|aka\.ms)/[^\\s\"'<>]*",
    re.IGNORECASE,
)
# Blue Coat / Symantec ProxySG: /*,1,0/ or /proxy?url=
PROXYSG = re.compile(
    r"https?://[a-z0-9.-]+(?::\d+)?/(?:\*,\d+(?:,\d+)?/|.*(?:proxy|cfredirect))"
    r"[^\\s\"'<>]*",
    re.IGNORECASE,
)
KASPERSKY = re.compile(
    r"https?://[a-z0-9.-]*(?:kaspersky|klclick|click\.kaspersky)[a-z0-9.-]*/"
    r"[^\\s\"'<>]+",
    re.IGNORECASE,
)
DRWEB = re.compile(
    r"https?://[a-z0-9.-]*(?:drweb|drweb-av)[a-z0-9.-]*/[^\\s\"'<>]+",
    re.IGNORECASE,
)
GENERIC_URL = re.compile(r"(?i)\bhttps?://[^\s<>\"')\]]+")


def _decode_proofpoint_v2(url: str) -> str | None:
    qs = parse_qs(urlparse(url).query)
    if "u" not in qs:
        return None
    raw = qs["u"][0]
    # Proofpoint encodes '.' as '-'. '-' as '--', '_' as '_-', etc.
    decoded = (
        raw.replace("-3A", ":")
        .replace("-2F", "/")
        .replace("-3F", "?")
        .replace("-3D", "=")
        .replace("-26", "&")
        .replace("-25", "%")
        .replace("-40", "@")
        .replace("_", "/")
        .replace("-2D", "-")
        .replace("-5F", "_")
    )
    # Remaining dashes often stand for dots in host path segments.
    decoded = re.sub(r"(?<!-)-(?!-)", ".", decoded)
    decoded = decoded.replace("--", "-")
    return unquote(decoded)


def _decode_proofpoint_v3(url: str) -> str | None:
    # Format: .../v3/__https://example.com/path__;params!!
    m = re.search(r"/v3/__(.+?)__", url)
    if not m:
        return None
    return unquote(m.group(1))


def _param_url(url: str, keys: tuple[str, ...]) -> str | None:
    qs = parse_qs(urlparse(url).query)
    for key in keys:
        if key in qs and qs[key]:
            return unquote(qs[key][0])
    return None


def _path_embedded_url(url: str) -> str | None:
    """Extract http(s) URL embedded in path (common for SG / AV wrappers)."""
    # ProxySG: http://proxy:8080/*,1,/http://evil.example/path
    m = re.search(r"/\*,\d+(?:,\d+)?/(https?://.+)$", url, re.IGNORECASE)
    if m:
        return unquote(m.group(1).rstrip(".,;:!?)"))
    # Percent-encoded target in path
    m = re.search(r"/(https?%3A%2F%2F[^\\s\"'<>]+)", url, re.IGNORECASE)
    if m:
        return unquote(m.group(1).rstrip(".,;:!?)"))
    # Second http(s) occurrence (wrapper host + embedded target)
    matches = list(re.finditer(r"https?://", url, re.IGNORECASE))
    if len(matches) >= 2:
        return unquote(url[matches[1].start() :].rstrip(".,;:!?)"))
    return None


def _is_proxysg(lower: str, original: str) -> bool:
    if "/*," in original or "/*%2c" in lower:
        return True
    if "cfredirect" in lower or "proxysg" in lower or "bluecoat" in lower:
        return True
    # Host often corporate; path carries embedded target
    if re.search(r"/\*,\d+", original):
        return True
    return False


def _decode_proxysg(url: str) -> str | None:
    candidate = _param_url(url, ("url", "u", "target", "dest", "redirect"))
    if candidate and candidate.startswith("http"):
        return candidate
    return _path_embedded_url(url)


def unwrap_url(url: str) -> UrlRewriteResult:
    """Attempt to unwrap a single URL. Never contacts the network."""
    original = url.rstrip(".,;:!?)")
    lower = original.lower()
    unwrapped = original
    rewriter = "none"

    try:
        if "urldefense" in lower and "/v2/url" in lower:
            candidate = _decode_proofpoint_v2(original)
            if candidate:
                unwrapped, rewriter = candidate, "proofpoint_v2"
        elif "urldefense" in lower and "/v3/" in lower:
            candidate = _decode_proofpoint_v3(original)
            if candidate:
                unwrapped, rewriter = candidate, "proofpoint_v3"
        elif "safelinks.protection.outlook.com" in lower:
            candidate = _param_url(original, ("url", "u"))
            if candidate:
                unwrapped, rewriter = candidate, "microsoft_safelinks"
        elif "linkprotect.cudasvc.com" in lower:
            candidate = _param_url(original, ("a", "url"))
            if candidate:
                unwrapped, rewriter = candidate, "barracuda"
        elif "mimecast.com" in lower:
            candidate = _param_url(original, ("url", "u", "target"))
            if candidate:
                unwrapped, rewriter = candidate, "mimecast"
        elif "fireeye.com" in lower:
            candidate = _param_url(original, ("url", "u"))
            if candidate:
                unwrapped, rewriter = candidate, "fireeye"
        elif "secure-web.cisco.com" in lower or "url.trendmicro.com" in lower:
            candidate = _param_url(original, ("url", "u", "dest", "target", "link"))
            if candidate:
                unwrapped, rewriter = candidate, "cisco_umbrella"
        elif "google." in lower and "/url?" in lower:
            candidate = _param_url(original, ("q", "url", "u"))
            if candidate and candidate.startswith("http"):
                unwrapped, rewriter = candidate, "google_redirect"
        elif "protection.office.com" in lower or "aka.ms" in lower:
            candidate = _param_url(original, ("url", "u", "link"))
            if candidate:
                unwrapped, rewriter = candidate, "defender_atp"
        elif _is_proxysg(lower, original):
            candidate = _decode_proxysg(original)
            if candidate:
                unwrapped, rewriter = candidate, "proxysg"
        elif "kaspersky" in lower or "klclick" in lower:
            candidate = _param_url(original, ("url", "u", "target", "link", "redir"))
            if not candidate:
                candidate = _path_embedded_url(original)
            if candidate:
                unwrapped, rewriter = candidate, "kaspersky"
        elif "drweb" in lower:
            candidate = _param_url(original, ("url", "u", "target", "link"))
            if not candidate:
                candidate = _path_embedded_url(original)
            if candidate:
                unwrapped, rewriter = candidate, "drweb"
        else:
            # Generic redirectors: ?url=, ?dest=, ?redirect=, ?r=, ?target=
            candidate = _param_url(
                original,
                ("url", "u", "dest", "destination", "redirect", "r", "target", "link"),
            )
            host = (urlparse(original).hostname or "").lower()
            if candidate and candidate.startswith("http") and host and host not in candidate:
                unwrapped, rewriter = candidate, "generic_redirect"
    except (ValueError, KeyError, IndexError, TypeError, re.error):
        # Keep original on any parse failure — offline safety first.
        return UrlRewriteResult(
            original=original, unwrapped=original, rewriter="parse_error", changed=False
        )

    return UrlRewriteResult(
        original=original,
        unwrapped=unwrapped,
        rewriter=rewriter,
        changed=unwrapped != original,
    )


def find_and_unwrap(text: str) -> list[UrlRewriteResult]:
    """Find URLs in text and unwrap rewriter wrappers."""
    if not text:
        return []
    results: list[UrlRewriteResult] = []
    seen: set[str] = set()
    for m in GENERIC_URL.finditer(text):
        url = m.group(0).rstrip(".,;:!?)")
        if url in seen:
            continue
        seen.add(url)
        results.append(unwrap_url(url))
    return results
