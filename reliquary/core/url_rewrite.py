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


def _unwrap_once(url: str) -> tuple[str, str]:
    """Single-hop unwrap via rewriter registry. Returns (url, rewriter_name)."""
    original = url.rstrip(".,;:!?)")
    lower = original.lower()

    def _match_proofpoint_v2(u: str, low: str) -> bool:
        return "urldefense" in low and "/v2/url" in low

    def _match_proofpoint_v3(u: str, low: str) -> bool:
        return "urldefense" in low and "/v3/" in low

    def _match_safelinks(u: str, low: str) -> bool:
        return "safelinks.protection.outlook.com" in low

    def _match_barracuda(u: str, low: str) -> bool:
        return "linkprotect.cudasvc.com" in low

    def _match_mimecast(u: str, low: str) -> bool:
        return "mimecast.com" in low

    def _match_fireeye(u: str, low: str) -> bool:
        return "fireeye.com" in low

    def _match_cisco(u: str, low: str) -> bool:
        return "secure-web.cisco.com" in low or "url.trendmicro.com" in low

    def _match_google(u: str, low: str) -> bool:
        return "google." in low and "/url?" in low

    def _match_defender(u: str, low: str) -> bool:
        return "protection.office.com" in low or "aka.ms" in low

    def _match_kaspersky(u: str, low: str) -> bool:
        return "kaspersky" in low or "klclick" in low

    def _match_drweb(u: str, low: str) -> bool:
        return "drweb" in low

    def _match_mailru(u: str, low: str) -> bool:
        host = (urlparse(u).hostname or "").lower()
        if host.endswith(("mail.ru", "imgsmail.ru", "list.ru", "bk.ru", "inbox.ru")):
            return any(
                x in low
                for x in ("click", "away", "/cgi-bin/link", "redir", "go?", "goto")
            )
        return "click.mail.ru" in low or "away.mail.ru" in low

    def _match_yandex(u: str, low: str) -> bool:
        host = (urlparse(u).hostname or "").lower()
        if host.startswith(("clck.yandex.", "away.yandex.", "l.yandex.", "href.yandex.")):
            return True
        if "yandex." in host or host.endswith("yandex.ru") or host.endswith("ya.ru"):
            return any(
                x in low
                for x in ("/clck/", "/redir/", "away.yandex", "l.yandex", "/goto?", "cc/")
            )
        return False

    def _match_vk(u: str, low: str) -> bool:
        host = (urlparse(u).hostname or "").lower()
        if host in {"vk.com", "vk.ru", "vk.cc", "away.vk.com"} or host.endswith(".vk.com"):
            return any(x in low for x in ("away.php", "/away", "to=", "cc/"))
        return False

    def _match_ok(u: str, low: str) -> bool:
        host = (urlparse(u).hostname or "").lower()
        if host in {"ok.ru", "odnoklassniki.ru"} or host.endswith(".ok.ru"):
            return "dk?" in low or "st.cmd" in low or "redirect" in low or "away" in low
        return False

    def _match_sber_gov(u: str, low: str) -> bool:
        host = (urlparse(u).hostname or "").lower()
        # Corporate / gov click-wraps sometimes front real destinations (RU + BY)
        if any(
            host.endswith(x)
            for x in (
                "sberbank.ru",
                "sber.ru",
                "gosuslugi.ru",
                "mos.ru",
                "nalog.gov.ru",
                "nalog.gov.by",
                "portal.gov.by",
                "belarusbank.by",
                "belapb.by",
                "priorbank.by",
                "nbrb.by",
                "erip.by",
                "raschet.by",
                "oplati.by",
                "belpost.by",
            )
        ):
            return any(
                x in low for x in ("/redirect", "/redir", "url=", "target=", "goto=", "link=")
            )
        return False

    def _match_bitrix(u: str, low: str) -> bool:
        host = (urlparse(u).hostname or "").lower()
        if "bitrix" in host or host.endswith(("bitrix24.ru", "bitrix24.com")):
            return any(
                x in low
                for x in ("/redirect", "redirect=", "goto=", "url=", "link=", "/click/")
            )
        # On-prem Bitrix often under /bitrix/redirect.php
        return "/bitrix/redirect" in low or "/bitrix/rk.php" in low

    def _match_amocrm(u: str, low: str) -> bool:
        host = (urlparse(u).hostname or "").lower()
        if "amocrm" in host or host.endswith(("amo.tm", "amo.crm")):
            return True
        return "amocrm" in low and any(
            x in low for x in ("redirect", "goto", "url=", "link=")
        )

    def _match_1c(u: str, low: str) -> bool:
        host = (urlparse(u).hostname or "").lower()
        # 1C:Enterprise HTTP services / published databases often carry ?url=
        if any(x in host for x in ("1c.ru", "1c-bitrix", "1c.")):
            return any(x in low for x in ("redirect", "url=", "goto=", "link="))
        if "/hs/" in low or "/do/" in low:  # 1C HTTP service path patterns
            return any(x in low for x in ("url=", "redirect", "goto="))
        return "e1c://" in low or "e1cib/" in low

    def _decode_kaspersky(u: str) -> str | None:
        return _param_url(u, ("url", "u", "target", "link", "redir")) or _path_embedded_url(u)

    def _decode_drweb(u: str) -> str | None:
        return _param_url(u, ("url", "u", "target", "link")) or _path_embedded_url(u)

    def _decode_mailru(u: str) -> str | None:
        return (
            _param_url(u, ("url", "u", "target", "link", "redir", "goto"))
            or _path_embedded_url(u)
        )

    def _decode_yandex(u: str) -> str | None:
        return (
            _param_url(u, ("url", "u", "target", "link", "redir", "dst", "to"))
            or _path_embedded_url(u)
        )

    def _decode_vk(u: str) -> str | None:
        return _param_url(u, ("to", "url", "u", "target", "link")) or _path_embedded_url(u)

    def _decode_ok(u: str) -> str | None:
        return _param_url(u, ("st.layer.w", "url", "u", "target", "link", "redir"))

    def _decode_sber_gov(u: str) -> str | None:
        return _param_url(u, ("url", "u", "target", "link", "redir", "goto"))

    def _decode_google(u: str) -> str | None:
        candidate = _param_url(u, ("q", "url", "u"))
        if candidate and candidate.startswith("http"):
            return candidate
        return None

    def _decode_generic(u: str) -> str | None:
        candidate = _param_url(
            u, ("url", "u", "dest", "destination", "redirect", "r", "target", "link")
        )
        host = (urlparse(u).hostname or "").lower()
        if candidate and candidate.startswith("http") and host and host not in candidate:
            return candidate
        return None

    # Ordered registry: (name, match(url, lower) -> bool, decode(url) -> str|None)
    registry: list[tuple[str, object, object]] = [
        ("proofpoint_v2", _match_proofpoint_v2, _decode_proofpoint_v2),
        ("proofpoint_v3", _match_proofpoint_v3, _decode_proofpoint_v3),
        ("microsoft_safelinks", _match_safelinks, lambda u: _param_url(u, ("url", "u"))),
        ("barracuda", _match_barracuda, lambda u: _param_url(u, ("a", "url"))),
        ("mimecast", _match_mimecast, lambda u: _param_url(u, ("url", "u", "target"))),
        ("fireeye", _match_fireeye, lambda u: _param_url(u, ("url", "u"))),
        (
            "cisco_umbrella",
            _match_cisco,
            lambda u: _param_url(u, ("url", "u", "dest", "target", "link")),
        ),
        ("google_redirect", _match_google, _decode_google),
        ("defender_atp", _match_defender, lambda u: _param_url(u, ("url", "u", "link"))),
        ("proxysg", lambda u, low: _is_proxysg(low, u), _decode_proxysg),
        ("kaspersky", _match_kaspersky, _decode_kaspersky),
        ("drweb", _match_drweb, _decode_drweb),
        ("mailru_away", _match_mailru, _decode_mailru),
        ("yandex_redir", _match_yandex, _decode_yandex),
        ("vk_away", _match_vk, _decode_vk),
        ("ok_redir", _match_ok, _decode_ok),
        ("ru_gov_redir", _match_sber_gov, _decode_sber_gov),
        (
            "bitrix_redir",
            _match_bitrix,
            lambda u: _param_url(u, ("goto", "url", "u", "link", "redirect", "r"))
            or _path_embedded_url(u),
        ),
        (
            "amocrm_redir",
            _match_amocrm,
            lambda u: _param_url(u, ("url", "u", "link", "redirect", "goto", "target"))
            or _path_embedded_url(u),
        ),
        (
            "onec_redir",
            _match_1c,
            lambda u: _param_url(u, ("url", "u", "link", "redirect", "goto"))
            or _path_embedded_url(u),
        ),
        ("generic_redirect", lambda _u, _low: True, _decode_generic),
    ]

    try:
        for name, match, decode in registry:
            if not match(original, lower):  # type: ignore[operator]
                continue
            candidate = decode(original)  # type: ignore[operator]
            if candidate:
                return candidate, name
            if name != "generic_redirect":
                # Named rewriter matched host but failed decode — stop (don't fall through)
                break
    except (ValueError, KeyError, IndexError, TypeError, re.error):
        return original, "parse_error"
    return original, "none"


def unwrap_url(url: str, *, max_hops: int = 5) -> UrlRewriteResult:
    """Unwrap rewriter wrappers, including nested chains (offline)."""
    original = url.rstrip(".,;:!?)")
    current = original
    chain: list[str] = []
    last_rewriter = "none"

    for _ in range(max(1, max_hops)):
        nxt, rewriter = _unwrap_once(current)
        if rewriter in ("none", "parse_error") or nxt == current:
            if rewriter == "parse_error" and not chain:
                return UrlRewriteResult(
                    original=original,
                    unwrapped=original,
                    rewriter="parse_error",
                    changed=False,
                    chain=[],
                )
            break
        chain.append(rewriter)
        last_rewriter = rewriter
        current = nxt.rstrip(".,;:!?)")

    return UrlRewriteResult(
        original=original,
        unwrapped=current,
        rewriter=last_rewriter if chain else "none",
        changed=current != original,
        chain=chain,
    )


def find_and_unwrap(text: str) -> list[UrlRewriteResult]:
    """Find URLs in text and unwrap rewriter wrappers (with nested chains)."""
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
