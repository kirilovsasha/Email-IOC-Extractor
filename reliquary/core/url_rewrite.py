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
        else:
            # Generic redirectors: ?url=, ?dest=, ?redirect=, ?r=, ?target=
            candidate = _param_url(
                original, ("url", "u", "dest", "destination", "redirect", "r", "target", "link")
            )
            host = (urlparse(original).hostname or "").lower()
            if candidate and candidate.startswith("http") and host and host not in candidate:
                unwrapped, rewriter = candidate, "generic_redirect"
    except Exception:
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
