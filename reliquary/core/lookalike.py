"""Brand lookalike / IDN / homoglyph heuristics (fully offline)."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

# Well-known brand registrable domains (ASCII). Org profiles may extend via brands.txt.
DEFAULT_BRANDS: tuple[str, ...] = (
    "microsoft.com",
    "office.com",
    "outlook.com",
    "live.com",
    "google.com",
    "gmail.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "aws.amazon.com",
    "paypal.com",
    "ebay.com",
    "facebook.com",
    "meta.com",
    "linkedin.com",
    "dropbox.com",
    "github.com",
    "sberbank.ru",
    "sber.ru",
    "tinkoff.ru",
    "vtb.ru",
    "gazprombank.ru",
    "alfabank.ru",
    "yandex.ru",
    "mail.ru",
    "gosuslugi.ru",
    # Республика Беларусь — банки / госуслуги / платежи
    "belarusbank.by",
    "belapb.by",
    "belgazprombank.by",
    "priorbank.by",
    "mtbank.by",
    "alfabank.by",
    "belveb.by",
    "bsb.by",
    "nbrb.by",
    "nalog.gov.by",
    "portal.gov.by",
    "minfin.gov.by",
    "pravo.by",
    "president.gov.by",
    "belpost.by",
    "belpochta.by",
    "erip.by",
    "raschet.by",
    "oplati.by",
)

# Display-name → expected brand domains (RU/BY SOC spoof surface).
# Более длинные/специфичные метки — выше (substring match).
_BRAND_DISPLAY_NAMES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("сбербанк", ("sberbank.ru", "sber.ru")),
    ("сбер", ("sberbank.ru", "sber.ru")),
    ("госуслуги", ("gosuslugi.ru",)),
    ("gosuslugi", ("gosuslugi.ru",)),
    ("microsoft", ("microsoft.com", "office.com", "outlook.com", "live.com")),
    ("office 365", ("microsoft.com", "office.com", "outlook.com")),
    ("outlook", ("outlook.com", "microsoft.com", "office.com", "live.com")),
    ("google", ("google.com", "gmail.com")),
    ("gmail", ("gmail.com", "google.com")),
    ("apple", ("apple.com", "icloud.com")),
    ("paypal", ("paypal.com",)),
    ("яндекс", ("yandex.ru",)),
    ("yandex", ("yandex.ru",)),
    ("mail.ru", ("mail.ru",)),
    ("тинькофф", ("tinkoff.ru", "tbank.ru")),
    ("втб", ("vtb.ru",)),
    ("альфа-банк", ("alfabank.ru", "alfa.ru", "alfabank.by")),
    ("альфа банк", ("alfabank.ru", "alfa.ru", "alfabank.by")),
    ("альфа", ("alfabank.ru", "alfa.ru", "alfabank.by")),
    ("фнс", ("nalog.gov.ru", "nalog.ru")),
    ("налоговая", ("nalog.gov.ru", "nalog.ru", "nalog.gov.by")),
    ("цб рф", ("cbr.ru",)),
    ("цб", ("cbr.ru",)),
    ("банк россии", ("cbr.ru",)),
    ("почта россии", ("pochta.ru", "russianpost.ru")),
    ("госключ", ("goskey.ru", "gosuslugi.ru")),
    ("мос.ру", ("mos.ru",)),
    ("мвд", ("мвд.рф", "mvd.ru")),
    # Беларусь
    ("беларусбанк", ("belarusbank.by",)),
    ("belarusbank", ("belarusbank.by",)),
    ("белагропромбанк", ("belapb.by",)),
    ("белагро", ("belapb.by",)),
    ("belagroprombank", ("belapb.by",)),
    ("белгазпромбанк", ("belgazprombank.by",)),
    ("belgazprombank", ("belgazprombank.by",)),
    ("приорбанк", ("priorbank.by",)),
    ("priorbank", ("priorbank.by",)),
    ("мтбанк", ("mtbank.by",)),
    ("mtbank", ("mtbank.by",)),
    ("белвэб", ("belveb.by",)),
    ("ббсбанк", ("bsb.by",)),
    ("нацбанк рб", ("nbrb.by",)),
    ("нацбанк", ("nbrb.by",)),
    ("нбрб", ("nbrb.by",)),
    ("мнс рб", ("nalog.gov.by",)),
    ("мнс", ("nalog.gov.by",)),
    ("міністэрства па падатках", ("nalog.gov.by",)),
    ("портал госуслуг рб", ("portal.gov.by",)),
    ("портал рб", ("portal.gov.by",)),
    ("белпочта", ("belpost.by", "belpochta.by")),
    ("belpost", ("belpost.by", "belpochta.by")),
    ("ерип", ("erip.by", "raschet.by", "oplati.by")),
    ("еріp", ("erip.by", "raschet.by", "oplati.by")),
    ("оплати", ("oplati.by", "erip.by", "raschet.by")),
    ("расчет by", ("raschet.by", "erip.by")),
)

# Common visual confusables → ASCII (subset; offline, no full Unicode confusables table).
_CONFUSABLES = str.maketrans(
    {
        "а": "a",  # Cyrillic
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ї": "i",
        "ё": "e",
        "ѕ": "s",
        "ɡ": "g",
        "ｌ": "l",
        "０": "0",
        "１": "1",
        "３": "3",
        "５": "5",
        "８": "8",
    }
)

_DOMAIN_RE = re.compile(
    r"(?i)\b(?:https?://)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b"
)


@dataclass(frozen=True)
class LookalikeHit:
    value: str
    brand: str
    kind: str  # idn | homoglyph | levenshtein | brand_spoof
    detail: str


def load_brands(extra_path: str | Path | None = None) -> tuple[str, ...]:
    brands = list(DEFAULT_BRANDS)
    if extra_path is None:
        return tuple(brands)
    path = Path(extra_path)
    if not path.is_file():
        return tuple(brands)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return tuple(brands)
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        brands.append(line.lower().lstrip("@").lstrip("."))
    # preserve order, unique
    seen: set[str] = set()
    out: list[str] = []
    for b in brands:
        if b not in seen:
            seen.add(b)
            out.append(b)
    return tuple(out)


def _registrable(host: str) -> str:
    host = host.lower().strip(".").strip()
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def to_ascii_domain(host: str) -> tuple[str, bool]:
    """Return (ascii_or_best_effort, is_idn)."""
    host = host.lower().strip(".")
    if not host:
        return "", False
    try:
        ascii_host = host.encode("idna").decode("ascii")
        is_idn = ascii_host != host and ("xn--" in ascii_host or any(ord(c) > 127 for c in host))
        return ascii_host, is_idn or any(ord(c) > 127 for c in host)
    except (UnicodeError, UnicodeDecodeError):
        return host, any(ord(c) > 127 for c in host)


def normalize_homoglyph(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text).lower()
    return folded.translate(_CONFUSABLES)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins = cur[j - 1] + 1
            delete = prev[j] + 1
            sub = prev[j - 1] + (ca != cb)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def extract_hosts_from_text(text: str) -> list[str]:
    hosts: list[str] = []
    for m in _DOMAIN_RE.finditer(text or ""):
        raw = m.group(1).lower()
        if raw.startswith("www."):
            raw = raw[4:]
        hosts.append(raw)
    return hosts


def host_from_email_or_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if "@" in value and "://" not in value:
        return value.rsplit("@", 1)[-1].lower().strip(">")
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = (parsed.hostname or "").lower()
        return host
    except (UnicodeError, ValueError, TypeError, AttributeError):
        return value.lower()


def check_domain(
    domain: str,
    brands: tuple[str, ...] | None = None,
    *,
    max_distance: int = 2,
) -> list[LookalikeHit]:
    """Compare a domain against brand list for IDN / homoglyph / near-miss."""
    brands = brands or DEFAULT_BRANDS
    domain = domain.lower().strip(".")
    if not domain or "." not in domain:
        return []
    ascii_dom, is_idn = to_ascii_domain(domain)
    reg = _registrable(ascii_dom or domain)
    norm = normalize_homoglyph(reg)
    hits: list[LookalikeHit] = []

    if is_idn:
        hits.append(
            LookalikeHit(
                value=domain,
                brand="",
                kind="idn",
                detail=f"IDN/punycode домен: {domain} → {ascii_dom or domain}",
            )
        )

    for brand in brands:
        brand_reg = _registrable(brand)
        if reg == brand_reg or norm == brand_reg:
            continue
        brand_norm = normalize_homoglyph(brand_reg)
        # Homoglyph: normalized form matches brand but original differs
        if norm == brand_norm and reg != brand_reg:
            hits.append(
                LookalikeHit(
                    value=domain,
                    brand=brand,
                    kind="homoglyph",
                    detail=f"Homoglyph к {brand}: {domain}",
                )
            )
            continue
        # Brand label in a different TLD / extra labels (microsoft-secure.com)
        brand_label = brand_reg.split(".")[0]
        # Short brand labels (vtb, sber, …) are noisy for substring / edit-distance FP
        short_brand = len(brand_label) < 5
        if (
            len(brand_label) >= 5
            and brand_label in norm.replace("-", "")
            and brand_reg not in reg
        ):
            if brand_label not in reg.split(".")[0]:
                # e.g. secure-microsoft.top
                pass
            if brand_label in norm and not reg.endswith(brand_reg):
                hits.append(
                    LookalikeHit(
                        value=domain,
                        brand=brand,
                        kind="brand_spoof",
                        detail=f"Похоже на бренд {brand}: {domain}",
                    )
                )
                continue
        dist = levenshtein(norm, brand_norm)
        eff_max = 1 if short_brand else max_distance
        len_slack = 0 if short_brand else max_distance
        if (
            1 <= dist <= eff_max
            and abs(len(norm) - len(brand_norm)) <= len_slack
            and (not short_brand or len(norm) >= 4)
        ):
            hits.append(
                LookalikeHit(
                    value=domain,
                    brand=brand,
                    kind="levenshtein",
                    detail=f"Lookalike ({dist}) к {brand}: {domain}",
                )
            )
    return hits


def parse_from_display_and_addr(from_header: str) -> tuple[str, str]:
    """Return (display_name_lower, email_addr_lower) from a From header."""
    raw = (from_header or "").strip()
    if not raw:
        return "", ""
    # "Name" <user@domain> or Name <user@domain>
    m = re.search(r'^"?([^"<]*)"?\s*<([^>]+)>', raw)
    if m:
        return m.group(1).strip().lower(), m.group(2).strip().lower()
    if "@" in raw:
        return "", raw.strip("<> ").lower()
    return raw.lower(), ""


def check_display_name_spoof(from_header: str) -> list[LookalikeHit]:
    """Brand display name with mismatched From domain (classic spoof)."""
    display, addr = parse_from_display_and_addr(from_header)
    if not display or not addr or "@" not in addr:
        return []
    host = addr.rsplit("@", 1)[-1].lower().strip(".")
    hits: list[LookalikeHit] = []
    for label, brands in _BRAND_DISPLAY_NAMES:
        if label not in display:
            continue
        # Exact / subdomain match (works for portal.gov.by, nalog.gov.by, …)
        if any(
            host == b or host.endswith("." + b) or _registrable(host) == b
            for b in brands
        ):
            continue
        brand = brands[0]
        hits.append(
            LookalikeHit(
                value=from_header[:120],
                brand=brand,
                kind="display_spoof",
                detail=f"Имя «{display[:40]}» похоже на {brand}, но From: {addr}",
            )
        )
        break
    return hits


def scan_lookalikes(
    *,
    from_addr: str = "",
    text: str = "",
    domains: list[str] | None = None,
    brands: tuple[str, ...] | None = None,
) -> list[LookalikeHit]:
    brands = brands or DEFAULT_BRANDS
    candidates: list[str] = []
    out: list[LookalikeHit] = []
    if from_addr:
        out.extend(check_display_name_spoof(from_addr))
        h = host_from_email_or_url(from_addr)
        if h:
            candidates.append(h)
    for d in domains or []:
        candidates.append(d.lower())
    for h in extract_hosts_from_text(text):
        candidates.append(h)

    seen: set[str] = set()
    for host in candidates:
        key = host.lower()
        if key in seen:
            continue
        seen.add(key)
        for hit in check_domain(host, brands):
            sig = (hit.kind, hit.value, hit.brand)
            if sig not in {(h.kind, h.value, h.brand) for h in out}:
                out.append(hit)
    return out[:12]
