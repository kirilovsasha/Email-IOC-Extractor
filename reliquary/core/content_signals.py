"""Body / HTML content signals for phishing triage (offline)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from html import unescape
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from reliquary.core.verdict_config import DEFAULT_SUSPICIOUS_TLDS

CREDENTIAL_RE = re.compile(
    r"(?i)\b("
    r"login|sign[\s-]?in|log[\s-]?in|password|passwd|passcode|"
    r"webmail|owa|outlook\s*web|account\s*verify|verify\s*account|"
    r"update\s*your\s*(?:password|account)|"
    r"войти|вход|пароль|учетн\w*\s*запис|подтвердите\s*аккаунт|"
    r"веб[- ]?почт"
    r")\b"
)

BEC_RE = re.compile(
    r"(?i)\b("
    r"wire\s*transfer|bank\s*transfer|change\s*(?:of\s*)?banking|"
    r"new\s*(?:bank\s*)?details|payment\s*instructions|"
    r"реквизит\w*|перевод\w*\s*(?:на\s*)?(?:сч[её]т|карт)|"
    r"смен\w*\s*реквизит|оплат\w*\s*сегодня|срочн\w*\s*оплат|"
    r"только\s*(?:в\s*)?(?:telegram|телеграм|whatsapp|ватсап)|"
    r"пишите\s*только\s*сюда|не\s*звоните|CEO\s*urgent|"
    r"генеральн\w*\s*директор|финансов\w*\s*директор|"
    # RU BEC / finance surface
    r"сч[её]т[\s\-]*фактур\w*|"
    r"акт\s+сверк\w*|"
    r"срочн\w*\s*перев(?:од|ед|ест)\w*|"
    r"реквизит\w*\s+на\s+карт\w*|"
    r"изменит\w*\s+плат[её]жн\w*|"
    r"\bCFO\b|главбух\w*|казнач[её]й\w*|"
    # Беларусь: ЕРИП / УНП / р/с / IBAN BY
    r"ерип|еріp|erip|"
    r"унп\b|"
    r"р/\s*с|р/?\s*сч[её]т|расч[её]тн\w*\s*сч[её]т|"
    r"iban\s*by\d{2}|by\d{2}\s*[a-z0-9]{4}|"
    r"оплат\w*\s*(?:через\s*)?(?:ерип|еріp|oplati|оплати)|"
    r"новые\s+реквизиты\s+(?:рб|беларус)"
    r")\b"
)

MESSENGER_LURE_RE = re.compile(
    r"(?i)("
    r"\btelegram\b|\bтелеграм\w*|\bwhatsapp\b|\bватсап\w*|"
    r"(?:telegram|телеграм|whatsapp|ватсап|t\.me)[^\n]{0,48}@[a-zA-Z][\w.]{2,31}|"
    r"@[a-zA-Z][\w.]{2,31}[^\n]{0,48}(?:telegram|телеграм|whatsapp|ватсап|t\.me)|"
    r"пишите\s+(?:в|мне\s+в)\s+(?:telegram|телеграм|whatsapp|ватсап)|"
    r"напишите\s+(?:в|мне\s+в)\s+(?:telegram|телеграм|whatsapp|ватсап)|"
    r"write\s+(?:me\s+)?(?:in|on|via)\s+(?:telegram|whatsapp)|"
    r"contact\s+(?:me\s+)?(?:in|on|via)\s+(?:telegram|whatsapp)|"
    r"только\s+(?:в\s+)?(?:telegram|телеграм|whatsapp|ватсап)"
    r")"
)

QR_LURE_RE = re.compile(
    r"(?i)("
    r"scan\s+the\s+qr|"
    r"scan\s+(?:this\s+)?qr|"
    r"сканируй(?:те)?\s+(?:qr|код)|"
    r"отсканируй(?:те)?|"
    r"QR[\s\-]*код|"
    r"qr[\s\-]*code"
    r")"
)

HIDDEN_STYLE_RE = re.compile(
    r"(?i)(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?|"
    r"opacity\s*:\s*0|color\s*:\s*#?fff(?:fff)?|"
    r"mso-hide\s*:\s*all|"
    r"position\s*:\s*absolute\s*;\s*left\s*:\s*-|"
    r"left\s*:\s*-\d{3,}|"
    r"font-size\s*:\s*0\s*;|"
    r"max-height\s*:\s*0|max-width\s*:\s*0|"
    r"overflow\s*:\s*hidden\s*;\s*(?:height|width)\s*:\s*0)"
)

DANGEROUS_SCHEME_RE = re.compile(
    r"(?i)(?:search-ms|ms-msdt|ms-officecmd|ms-appinstaller|vbscript|mhtml|file)\s*:"
)
USERINFO_URL_RE = re.compile(
    r"(?i)\bhttps?://([^\s/@<>\"']*\.[^\s/@<>\"']*)@[^\s/<>\"']+"
)
PAYMENT_CHANGE_RE = re.compile(
    r"(?i)("
    r"смен\w{0,8}\s+реквизит|"
    r"нов\w{2,8}\s+реквизит|"
    r"изменил\w{0,6}\s+(?:реквизит|плат[её]жн|банковск)|"
    r"change\s+(?:of\s+)?(?:bank(?:ing)?|payment)\s+details|"
    r"updated?\s+(?:bank|payment)\s+details|"
    r"новые\s+банковск"
    r")"
)
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
CALLBACK_RE = re.compile(
    r"(?i)("
    r"не\s+отвечайте\s+на\s+(?:это\s+)?письм|"
    r"не\s+пишите.{0,24}перезвон|"
    r"перезвоните|"
    r"позвоните\s+(?:мне|нам|по\s+номер)|"
    r"call\s+(?:me|us)\s+back|"
    r"do\s+not\s+reply.{0,48}\bcall\b|"
    r"только\s+по\s+телефон"
    r")"
)

SHORTENER_RE = re.compile(
    r"(?i)\bhttps?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|"
    r"cutt\.ly|rebrand\.ly|clck\.ru|vk\.cc|u\.to)/[^\s<>\"')\]]+"
)

MESSENGER_URL_RE = re.compile(
    r"(?i)\b(?:https?://)?(?:t\.me|telegram\.me|wa\.me|chat\.whatsapp\.com|"
    r"discord\.gg)/[^\s<>\"')\]]+"
)

ARCHIVE_PASSWORD_RE = re.compile(
    r"(?i)("
    r"password\s*(?:is|:|=)|pass\s*:\s*\S+|"
    r"пароль\s*(?:архива|от\s*архива|для\s*архива|rar|zip|7z)?\s*[:=]|"
    r"архив\s+защищ|"
    r"password[\s\-]*protected"
    r")"
)

OOB_DELIVERY_RE = re.compile(
    r"(?i)("
    r"пароль\s+в\s+(?:telegram|телеграм|whatsapp|ватсап|sms|смс)|"
    r"password\s+(?:in|via)\s+(?:telegram|whatsapp|sms)|"
    r"скача(?:йте|ть)\s+(?:с|по)\s+(?:ссылке|clck|bit\.ly|vk\.cc)|"
    r"download\s+(?:from|via)\s+(?:telegram|short\s*link)|"
    r"файл\s+на\s+(?:яндекс\.?диск|google\s*drive|mail\.ru\s*cloud)"
    r")"
)

CLOUD_LURE_RE = re.compile(
    r"(?i)("
    r"https?://(?:disk\.yandex\.(?:ru|com)|yadi\.sk|yandex\.ru/disk|"
    r"cloud\.mail\.ru|docs\.google\.com/(?:file|document|uc)|"
    r"drive\.google\.com/(?:file|open)|dropbox\.com/s|"
    r"1drv\.ms|onedrive\.live\.com)/[^\s<>\"')\]]*"
    r"|"
    r"(?:скача(?:йте|ть)|файл|документ|архив)\s+(?:на|в|по)\s+"
    r"(?:яндекс\.?\s*диск|yandex\s*disk|mail\.ru\s*облак|google\s*drive|"
    r"облак[еу]|диск[еу]\s+яндекс)"
    r")"
)

CLICKFIX_RE = re.compile(
    r"(?i)("
    r"\bwin\s*\+\s*r\b|"
    r"windows\s*\+\s*r\b|"
    r"клавиш\w{0,8}\s+win\b|"
    r"нажмите\s+win\b|"
    r"powershell(?:\.exe)?\s+(?:-enc|-e\b|-encodedcommand)|"
    r"\bmshta(?:\.exe)?\b|"
    r"certutil(?:\.exe)?\s+-urlcache|"
    r"вставьте\s+команду|"
    r"выполните\s+команду|"
    r"\brun\s+dialog\b|"
    r"press\s+(?:the\s+)?windows\s+key"
    r")"
)

FAKE_AUTH_RE = re.compile(
    r"(?i)(authentication-results\s*:|spf\s*=\s*pass|dkim\s*=\s*pass|dmarc\s*=\s*pass)"
)
_HEADERISH_AUTH_RE = re.compile(
    r"(?i)^(authentication-results|received-spf|dkim-signature|arc-authentication-results)\s*:"
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
    from reliquary.core.url_rewrite import unwrap_url

    hits: list[ContentSignal] = []
    for a in soup.find_all("a", href=True):
        href = unescape(str(a.get("href") or "")).strip()
        label = a.get_text(" ", strip=True)
        if not href or not label or href.startswith(("mailto:", "#", "tel:")):
            continue
        label_l = label.lower().strip()
        if "://" not in label_l and "." not in label_l:
            continue
        try:
            final = unwrap_url(href)
            href_for_host = final.unwrapped if final.changed else href
            href_host = (urlparse(href_for_host).hostname or "").lower()
        except (ValueError, TypeError, AttributeError):
            continue
        label_host = label_l
        if "://" in label_host:
            try:
                label_host = (urlparse(label_host).hostname or label_host).lower()
            except (ValueError, TypeError, AttributeError):
                pass
        label_host = label_host.split("/")[0].split("?")[0].lstrip("www.")
        href_host = href_host.lstrip("www.")
        if href_host and label_host and href_host != label_host and label_host in label_l:
            if len(label_host) >= 4 and "." in label_host:
                detail = f"Ссылка «{label[:60]}» ведёт на {href_host}"
                if final.changed and final.chain:
                    detail += f" (после unwrap: {'→'.join(final.chain)})"
                hits.append(
                    ContentSignal(
                        "href_mismatch",
                        detail,
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


def _html_forms(
    soup: BeautifulSoup, tlds: tuple[str, ...]
) -> list[ContentSignal]:
    forms = soup.find_all("form")
    if not forms:
        return []
    out: list[ContentSignal] = []
    has_password = any(
        str(inp.get("type") or "").lower() == "password"
        for form in forms
        for inp in form.find_all("input")
    )
    if has_password:
        out.append(
            ContentSignal(
                "html_password_form",
                "HTML-форма с полем password",
                "weight_credential_harvest",
            )
        )
    else:
        out.append(
            ContentSignal(
                "html_form",
                f"HTML-формы в письме: {len(forms)}",
                "weight_html_form",
            )
        )
    for form in forms:
        action = unescape(str(form.get("action") or "")).strip()
        action_l = action.lower()
        if action_l.startswith("javascript:"):
            out.append(
                ContentSignal(
                    "dangerous_scheme",
                    f"form action javascript: {action[:60]}",
                    "weight_dangerous_scheme",
                )
            )
            break
        if not action or action_l.startswith(("#", "mailto:")):
            continue
        try:
            host = (urlparse(action if "://" in action else f"//{action}").hostname or "").lower()
        except (ValueError, TypeError, AttributeError):
            host = ""
        raw_ip = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host or ""))
        bad_tld = any(
            (host or "").endswith(tld) or f"{tld}/" in action.lower()
            for tld in tlds
        )
        if raw_ip or bad_tld:
            out.append(
                ContentSignal(
                    "form_action_suspicious",
                    f"form action → подозрительный хост: {action[:80]}",
                    "weight_form_action_suspicious",
                )
            )
            break
    return out


def _cid_phishing(soup: BeautifulSoup, html: str) -> list[ContentSignal]:
    """CID-only phishing: cid: images + http links + almost no visible text."""
    if not html:
        return []
    cid_imgs = soup.find_all("img", src=True)
    has_cid = any(str(img.get("src") or "").lower().startswith("cid:") for img in cid_imgs)
    if not has_cid:
        return []
    has_http_a = any(
        str(a.get("href") or "").lower().startswith(("http://", "https://"))
        for a in soup.find_all("a", href=True)
    )
    if not has_http_a:
        return []
    visible = _visible_text(soup)
    # Strip whitespace / punctuation — almost no readable copy
    letters = re.sub(r"[\s\W_]+", "", visible, flags=re.UNICODE)
    if len(letters) <= 40:
        return [
            ContentSignal(
                "cid_phishing",
                "CID-картинки + http-ссылка при почти пустом тексте — CID-phishing",
                "weight_cid_phishing",
            )
        ]
    return []


def _dangerous_schemes(blob: str, soup: BeautifulSoup | None) -> list[ContentSignal]:
    """URI schemes used as mail lures (search-ms, ms-msdt, file, javascript, …)."""
    hits: list[str] = []
    match = DANGEROUS_SCHEME_RE.search(blob or "")
    if match:
        hits.append(match.group(0)[:40])
    if soup is not None:
        for tag in soup.find_all(href=True):
            href = unescape(str(tag.get("href") or "")).strip()
            if href.lower().startswith("javascript:"):
                hits.append("javascript:")
                break
    if not hits:
        return []
    return [
        ContentSignal(
            "dangerous_scheme",
            f"Опасная URI-схема: {hits[0]}",
            "weight_dangerous_scheme",
        )
    ]


def _url_userinfo(blob: str) -> list[ContentSignal]:
    """https://brand.tld@attacker.tld — visible brand is the userinfo, not the host."""
    match = USERINFO_URL_RE.search(blob or "")
    if not match:
        return []
    return [
        ContentSignal(
            "url_userinfo",
            f"URL с userinfo (бренд перед @): {match.group(0)[:80]}",
            "weight_url_userinfo",
        )
    ]


def _fake_auth_in_body(text: str, html: str) -> ContentSignal | None:
    """SPF/DKIM/DMARC pass painted into the body, not a real header."""
    blobs: list[str] = []
    if html:
        blobs.append(html)
    lines: list[str] = []
    for line in (text or "").splitlines():
        if _HEADERISH_AUTH_RE.match(line.strip()):
            continue
        lines.append(line)
    if lines:
        blobs.append("\n".join(lines))
    match = None
    for blob in blobs:
        match = FAKE_AUTH_RE.search(blob)
        if match:
            break
    if not match:
        return None
    return ContentSignal(
        "fake_auth_results",
        f"В теле письма поддельный Authentication-Results: {match.group(0)[:48]}",
        "weight_fake_auth_results",
    )


def _image_only_body(soup: BeautifulSoup) -> list[ContentSignal]:
    """HTML with pictures and a link, almost no readable text (no OCR)."""
    imgs = soup.find_all("img")
    if not imgs:
        return []
    non_cid = [
        str(img.get("src") or "")
        for img in imgs
        if not str(img.get("src") or "").lower().startswith("cid:")
    ]
    if not non_cid:
        return []
    has_link = any(
        str(a.get("href") or "").lower().startswith(("http://", "https://"))
        for a in soup.find_all("a", href=True)
    )
    if not has_link:
        return []
    letters = re.sub(r"[\s\W_]+", "", soup.get_text(" ", strip=True), flags=re.UNICODE)
    if len(letters) > 40:
        return []
    return [
        ContentSignal(
            "image_only_body",
            "HTML почти без текста: картинка и http-ссылка",
            "weight_image_only_body",
        )
    ]


def _payment_token_signal(blob: str) -> ContentSignal | None:
    """IBAN / БИК+счёт / карта / СБП only together with payment-change language."""
    if not blob or not PAYMENT_CHANGE_RE.search(blob):
        return None
    bits: list[str] = []
    if IBAN_RE.search(blob):
        bits.append("IBAN")
    if re.search(r"\b04\d{7}\b", blob) and re.search(r"\b\d{20}\b", blob):
        bits.append("БИК+счёт")
    if re.search(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", blob):
        bits.append("карта")
    if re.search(r"(?i)\bсбп\b", blob) and re.search(r"(?:\+7|8)[\s(-]?\d{3}", blob):
        bits.append("СБП")
    if not bits:
        return None
    return ContentSignal(
        "payment_tokens",
        "Смена реквизитов + " + ", ".join(bits),
        "weight_payment_tokens",
    )


def analyze_content_signals(
    text: str,
    html: str = "",
    *,
    has_qr: bool = False,
    has_urls: bool = False,
    has_attachments: bool = False,
    has_encrypted_archive: bool = False,
    has_office_encrypted: bool = False,
    suspicious_tlds: tuple[str, ...] | None = None,
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

    if BEC_RE.search(blob):
        signals.append(
            ContentSignal(
                "bec_payment",
                "Маркеры BEC / смены реквизитов / оплаты вне канала",
                "weight_bec_payment",
            )
        )

    payment = _payment_token_signal(blob)
    if payment is not None:
        signals.append(payment)

    if CALLBACK_RE.search(blob):
        signals.append(
            ContentSignal(
                "bec_callback",
                "Callback-фишинг: просят не отвечать на письмо и позвонить",
                "weight_bec_callback",
            )
        )

    signals.extend(_url_userinfo(blob))

    click = CLICKFIX_RE.search(blob)
    if click:
        signals.append(
            ContentSignal(
                "clickfix",
                f"ClickFix / Win+R / команда в теле: {click.group(0)[:60]}",
                "weight_clickfix",
            )
        )

    fake_auth = _fake_auth_in_body(text or "", html or "")
    if fake_auth is not None:
        signals.append(fake_auth)

    if ARCHIVE_PASSWORD_RE.search(blob):
        if has_encrypted_archive or has_office_encrypted:
            signals.append(
                ContentSignal(
                    "archive_password_match",
                    "Пароль в теле + шифрованный архив или Office",
                    "weight_archive_password_match",
                )
            )
        else:
            signals.append(
                ContentSignal(
                    "archive_password",
                    "В теле указан пароль архива",
                    "weight_archive_password",
                )
            )

    if OOB_DELIVERY_RE.search(blob):
        signals.append(
            ContentSignal(
                "oob_delivery",
                "Доставка вне канала: пароль/файл через Telegram/шортенер/облако",
                "weight_oob_delivery",
            )
        )

    cloud_hit = CLOUD_LURE_RE.search(blob)
    if cloud_hit and not has_attachments:
        signals.append(
            ContentSignal(
                "cloud_lure",
                f"Файл только в облаке (без вложения): {cloud_hit.group(0)[:80]}",
                "weight_cloud_lure",
            )
        )

    short_hits = SHORTENER_RE.findall(blob)
    if short_hits:
        signals.append(
            ContentSignal(
                "url_shortener",
                f"URL-шортенер: {short_hits[0][:80]}",
                "weight_url_shortener",
            )
        )

    msg_hits = MESSENGER_URL_RE.findall(blob)
    http_urls = re.findall(r"(?i)\bhttps?://[^\s<>\"')\]]+", blob)
    non_messenger = [
        u
        for u in http_urls
        if not MESSENGER_URL_RE.search(u) and not SHORTENER_RE.search(u)
    ]
    if msg_hits and len(non_messenger) == 0 and not has_attachments:
        signals.append(
            ContentSignal(
                "messenger_only",
                f"Только messenger-ссылка (Telegram/WhatsApp/Discord): {msg_hits[0][:60]}",
                "weight_messenger_only",
            )
        )

    lure_hit = MESSENGER_LURE_RE.search(blob)
    if lure_hit:
        signals.append(
            ContentSignal(
                "messenger_lure",
                f"Messenger-lure в тексте (Telegram/WhatsApp/@channel): {lure_hit.group(0)[:60]}",
                "weight_messenger_lure",
            )
        )

    qr_lure_hit = QR_LURE_RE.search(blob)
    if qr_lure_hit:
        signals.append(
            ContentSignal(
                "qr_lure",
                f"Призыв сканировать QR: {qr_lure_hit.group(0)[:60]}",
                "weight_qr_lure",
            )
        )

    tlds = suspicious_tlds or DEFAULT_SUSPICIOUS_TLDS
    soup: BeautifulSoup | None = None
    if html and ("<" in html):
        try:
            soup = BeautifulSoup(html, "lxml")
        except (ValueError, TypeError, OSError):
            soup = None
        if soup is not None:
            signals.extend(_href_mismatch(soup))
            signals.extend(_hidden_text(html, soup))
            signals.extend(_html_forms(soup, tlds))
            signals.extend(_cid_phishing(soup, html))
            if not any(s.kind == "cid_phishing" for s in signals):
                signals.extend(_image_only_body(soup))
    signals.extend(_dangerous_schemes(blob, soup))

    has_credential = any(s.kind == "credential_harvest" for s in signals) or bool(
        CREDENTIAL_RE.search(blob)
    )
    if has_qr and has_credential:
        signals.append(
            ContentSignal(
                "qr_credential",
                "QR + маркеры сбора учётных данных — композитный канал",
                "weight_qr_credential",
            )
        )

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
