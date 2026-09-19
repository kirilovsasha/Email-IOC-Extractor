"""Body / HTML content signals for phishing triage (offline)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from html import unescape
from urllib.parse import urlparse

from bs4 import BeautifulSoup

CREDENTIAL_RE = re.compile(
    r"(?i)\b("
    r"login|sign[\s-]?in|log[\s-]?in|password|passwd|passcode|"
    r"webmail|owa|outlook\s*web|account\s*verify|verify\s*account|"
    r"update\s*your\s*(?:password|account)|"
    r"войти|вход|пароль|учетн\w*\s*запис|подтвердите\s*аккаунт|"
    r"веб[- ]?почт"
    r")\b"
)

HIDDEN_STYLE_RE = re.compile(
    r"(?i)(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|"
    r"opacity\s*:\s*0|color\s*:\s*#?fff(?:fff)?|"
    r"mso-hide\s*:\s*all)"
)


@dataclass(frozen=True)
class ContentSignal:
    kind: str
    detail: str
    weight_key: str  # maps to VerdictConfig field name suffix


def _visible_text(soup: BeautifulSoup) -> str:
    for tag in soup(["script", "style"]):
        tag.decompose()
    return soup.get_text("\n", strip=True)


def _href_mismatch(soup: BeautifulSoup) -> list[ContentSignal]:
    hits: list[ContentSignal] = []
    for a in soup.find_all("a", href=True):
        href = unescape(str(a.get("href") or "")).strip()
        label = a.get_text(" ", strip=True)
        if not href or not label or href.startswith(("mailto:", "#", "tel:")):
            continue
        # Skip if label is not URL-like
        label_l = label.lower().strip()
        if "://" not in label_l and "." not in label_l:
            continue
        try:
            href_host = (urlparse(href).hostname or "").lower()
        except Exception:  # noqa: BLE001
            continue
        # Extract host-ish from visible label
        label_host = label_l
        if "://" in label_host:
            try:
                label_host = (urlparse(label_host).hostname or label_host).lower()
            except Exception:  # noqa: BLE001
                pass
        label_host = label_host.split("/")[0].split("?")[0].lstrip("www.")
        href_host = href_host.lstrip("www.")
        if href_host and label_host and href_host != label_host and label_host in label_l:
            if len(label_host) >= 4 and "." in label_host:
                hits.append(
                    ContentSignal(
                        "href_mismatch",
                        f"Ссылка «{label[:60]}» ведёт на {href_host}",
                        "weight_href_mismatch",
                    )
                )
                if len(hits) >= 3:
                    break
    return hits


def _hidden_text(html: str, soup: BeautifulSoup) -> list[ContentSignal]:
    if not html:
        return []
    if HIDDEN_STYLE_RE.search(html):
        # Confirm there is substantial text in hidden nodes
        hidden_bits = 0
        for el in soup.find_all(style=True):
            style = str(el.get("style") or "")
            if HIDDEN_STYLE_RE.search(style):
                hidden_bits += len(el.get_text(" ", strip=True))
        if hidden_bits >= 20:
            return [
                ContentSignal(
                    "hidden_text",
                    f"Скрытый HTML-текст (~{hidden_bits} символов)",
                    "weight_hidden_text",
                )
            ]
        return [
            ContentSignal(
                "hidden_style",
                "HTML со стилями скрытия текста (display:none / font-size:0 …)",
                "weight_hidden_text",
            )
        ]
    return []


def _html_forms(soup: BeautifulSoup) -> list[ContentSignal]:
    forms = soup.find_all("form")
    if not forms:
        return []
    has_password = any(
        str(inp.get("type") or "").lower() == "password"
        for form in forms
        for inp in form.find_all("input")
    )
    if has_password:
        return [
            ContentSignal(
                "html_password_form",
                "HTML-форма с полем password",
                "weight_credential_harvest",
            )
        ]
    return [
        ContentSignal(
            "html_form",
            f"HTML-формы в письме: {len(forms)}",
            "weight_html_form",
        )
    ]


def analyze_content_signals(
    text: str,
    html: str = "",
    *,
    has_qr: bool = False,
    has_urls: bool = False,
    has_attachments: bool = False,
) -> list[ContentSignal]:
    """Return unique content signals from plain text and optional HTML body."""
    signals: list[ContentSignal] = []
    blob = f"{text or ''}\n{html or ''}"

    if CREDENTIAL_RE.search(blob):
        signals.append(
            ContentSignal(
                "credential_harvest",
                "Маркеры сбора учётных данных / webmail login",
                "weight_credential_harvest",
            )
        )

    soup: BeautifulSoup | None = None
    if html and ("<" in html):
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:  # noqa: BLE001
            soup = None
        if soup is not None:
            signals.extend(_href_mismatch(soup))
            signals.extend(_hidden_text(html, soup))
            signals.extend(_html_forms(soup))

    if has_qr and has_urls is False and not has_attachments:
        signals.append(
            ContentSignal(
                "qr_only",
                "QR без обычных URL/вложений — возможен QR-phishing",
                "weight_qr_only",
            )
        )
    elif has_qr:
        signals.append(
            ContentSignal(
                "qr_present",
                "В письме/вложении обнаружен QR с URL",
                "weight_qr_present",
            )
        )

    # Dedupe by kind
    seen: set[str] = set()
    out: list[ContentSignal] = []
    for s in signals:
        if s.kind in seen:
            continue
        seen.add(s.kind)
        out.append(s)
    return out
