"""Per-category verdict scorers."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

from reliquary.core.content_signals import analyze_content_signals
from reliquary.core.lookalike import load_brands, load_org_domains, scan_lookalikes
from reliquary.core.models import (
    AnalysisResult,
    ScoreContribution,
    Severity,
)
from reliquary.core.verdict_config import URGENCY_RE, VerdictConfig


def _apply_cap(
    contributions: list[ScoreContribution],
    cap: int,
    category: str,
) -> tuple[int, list[ScoreContribution]]:
    total = sum(c.points for c in contributions)
    if total <= cap:
        return total, contributions
    # Scale down proportionally and mark capped
    if total <= 0:
        return 0, contributions
    scaled: list[ScoreContribution] = []
    remaining = cap
    for i, c in enumerate(contributions):
        if i == len(contributions) - 1:
            pts = remaining
        else:
            pts = max(0, int(round(c.points * cap / total)))
            remaining -= pts
        scaled.append(
            ScoreContribution(
                category=category,
                points=pts,
                reason=c.reason + (" [cap]" if pts < c.points else ""),
                capped=pts < c.points or True,
            )
        )
    # Fix rounding drift
    drift = cap - sum(c.points for c in scaled)
    if drift and scaled:
        scaled[-1] = ScoreContribution(
            category=scaled[-1].category,
            points=scaled[-1].points + drift,
            reason=scaled[-1].reason,
            capped=True,
        )
    return cap, scaled


def _score_headers(
    result: AnalysisResult, cfg: VerdictConfig
) -> tuple[int, list[ScoreContribution]]:
    parts: list[ScoreContribution] = []
    tier_weight = {
        Severity.CRITICAL: cfg.weight_header_critical,
        Severity.HIGH: cfg.weight_header_high,
        Severity.MEDIUM: cfg.weight_header_medium,
        Severity.LOW: cfg.weight_header_low,
    }
    # Lookalike owns the main display-spoof weight. A small header nudge keeps
    # Reply-To + spoof above the malicious line without a second full HIGH.
    compound_headers = {
        "Sender mismatch",
        "Orphan reply",
        "Mailer brand mismatch",
    }
    display_spoof = False
    best: dict[Severity, str] = {}
    counts: dict[Severity, int] = {}
    msgid_note = ""
    resent_added = False
    for h in result.headers:
        if h.name == "Display-name spoof":
            display_spoof = True
            continue
        if h.name == "Message-ID domain":
            msgid_note = h.note or "Домен Message-ID отличается от From"
        if h.name == "Resent-From domain":
            if not resent_added:
                parts.append(
                    ScoreContribution(
                        "headers",
                        cfg.weight_resent_from_mismatch,
                        h.note or "Домен Resent-From отличается от From",
                    )
                )
                resent_added = True
            continue
        if h.name in compound_headers:
            continue
        if h.severity not in tier_weight:
            continue
        counts[h.severity] = counts.get(h.severity, 0) + 1
        if h.severity not in best:
            best[h.severity] = h.note or h.name
    if msgid_note:
        best[Severity.LOW] = msgid_note
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        if sev not in best:
            continue
        parts.append(ScoreContribution("headers", tier_weight[sev], best[sev]))
        if counts.get(sev, 0) >= 2 and sev in (Severity.CRITICAL, Severity.HIGH):
            parts.append(
                ScoreContribution(
                    "headers",
                    max(4, tier_weight[sev] // 2),
                    f"Доп. {sev.value} header findings (×{counts[sev]})",
                )
            )
    if display_spoof:
        parts.append(
            ScoreContribution(
                "headers",
                cfg.weight_header_low,
                "Display-name spoof (основной вес — в lookalike)",
            )
        )
    return _apply_cap(parts, cfg.cap_headers, "headers")


def _score_attachments(
    result: AnalysisResult, cfg: VerdictConfig
) -> tuple[int, list[ScoreContribution]]:
    parts: list[ScoreContribution] = []
    high_flags = {
        "double_extension",
        "dangerous_extension",
        "ole_macros_suspected",
        "ooxml_vba",
        "mime_mismatch",
        "macro_enabled_office",
        "nested_email",
        "qr_url",
        "archive_dangerous_member",
        "encrypted_archive",
        "iso_image",
        "disk_image",
        "shortcut_lnk",
        "lnk_dangerous",
        "lnk_http_target",
        "onenote_attachment",
        "pdf_javascript",
        "pdf_uri_action",
        "html_smuggling",
        "svg_script",
        "cab_archive",
        "cab_contains_lnk",
        "archive_nested_email",
        "zip_bomb_suspect",
        "tnef_attachment",
        "iso_contains_lnk",
        "iso_contains_exe",
        "disk_contains_exe",
        "office_hyperlink",
        "office_remote_template",
        "nested_archive",
        "archive_double_extension",
        "script_attachment",
        "script_url",
        "html_polyglot",
        "rar_archive",
        "yara_match",
        "office_dde",
        "ole_package",
        "pdf_openaction_uri",
        "pdf_launch",
        "pdf_submitform",
        "pdf_gotor",
        "onenote_embedded_file",
        "lure_shortcut",
        "lure_shortcut_target",
        "rtf_exploit",
        "rtf_objupdate",
        "rtf_equation",
        "rtf_ole",
        "office_encrypted",
        "office_external_data",
        "office_xlm",
        "office_vba_live",
        "html_form_action",
        "iso_contains_script",
        "disk_contains_script",
    }
    seen_flags: set[str] = set()
    soft_noted = False
    for att in result.attachments:
        hit = high_flags.intersection(att.risk_flags) - seen_flags
        if hit:
            seen_flags |= hit
            rest = set(hit)
            if "encrypted_archive" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_encrypted_archive,
                        f"Шифрованный архив «{att.filename}» — содержимое не извлечено офлайн",
                    )
                )
                rest.discard("encrypted_archive")
            if "office_encrypted" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_office_encrypted,
                        f"Зашифрованный Office «{att.filename}» — содержимое не извлечено",
                    )
                )
                rest.discard("office_encrypted")
                rest.discard("encrypted_archive")
            if "iso_image" in rest or "disk_image" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_attachment_iso
                        if "iso_image" in rest
                        else cfg.weight_disk_image,
                        f"Образ диска «{att.filename}»"
                        + (" (ISO/IMG)" if "iso_image" in rest else " (VHD/WIM)"),
                    )
                )
                rest.discard("iso_image")
                rest.discard("disk_image")
                rest.discard("dangerous_extension")
            if "lnk_dangerous" in rest or "lnk_http_target" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_lnk_dangerous,
                        f"LNK «{att.filename}»: опасная цель (cmd/powershell/http)",
                    )
                )
                rest.discard("lnk_dangerous")
                rest.discard("lnk_http_target")
                rest.discard("shortcut_lnk")
                rest.discard("lnk_target")
                rest.discard("dangerous_extension")
            elif "shortcut_lnk" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_attachment_lnk,
                        f"Ярлык LNK «{att.filename}»",
                    )
                )
                rest.discard("shortcut_lnk")
                rest.discard("lnk_target")
                rest.discard("dangerous_extension")
            if "onenote_attachment" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_attachment_onenote,
                        f"OneNote-вложение «{att.filename}»",
                    )
                )
                rest.discard("onenote_attachment")
            if "pdf_javascript" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_pdf_javascript,
                        f"PDF «{att.filename}»: JavaScript / OpenAction",
                    )
                )
                rest.discard("pdf_javascript")
            if "pdf_uri_action" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_pdf_uri_action,
                        f"PDF «{att.filename}»: /URI-действие (внешняя ссылка)",
                    )
                )
                rest.discard("pdf_uri_action")
            if "html_smuggling" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_html_smuggling,
                        f"HTML-smuggling во вложении «{att.filename}»",
                    )
                )
                rest.discard("html_smuggling")
            if "svg_script" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_html_smuggling,
                        f"SVG со script «{att.filename}»",
                    )
                )
                rest.discard("svg_script")
            if "cab_contains_lnk" in rest or "cab_archive" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_cab_archive,
                        f"CAB «{att.filename}»"
                        + (" содержит .lnk" if "cab_contains_lnk" in rest else ""),
                    )
                )
                rest.discard("cab_contains_lnk")
                rest.discard("cab_archive")
            if "archive_nested_email" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_archive_nested_email,
                        f"Архив «{att.filename}» содержит вложенное письмо",
                    )
                )
                rest.discard("archive_nested_email")
            if "zip_bomb_suspect" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_zip_bomb,
                        f"Подозрение на zip-bomb «{att.filename}»",
                    )
                )
                rest.discard("zip_bomb_suspect")
            if "tnef_attachment" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_tnef,
                        f"TNEF/winmail.dat «{att.filename}»",
                    )
                )
                rest.discard("tnef_attachment")
            if "iso_contains_lnk" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_iso_lnk,
                        f"ISO «{att.filename}» содержит .lnk",
                    )
                )
                rest.discard("iso_contains_lnk")
            if "iso_contains_exe" in rest or "disk_contains_exe" in rest or (
                "iso_contains_script" in rest or "disk_contains_script" in rest
            ):
                kinds: list[str] = []
                if "iso_contains_exe" in rest or "disk_contains_exe" in rest:
                    kinds.append(".exe/.dll/.scr")
                if "iso_contains_script" in rest or "disk_contains_script" in rest:
                    kinds.append("скрипт")
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_iso_exe,
                        f"Образ «{att.filename}» содержит {' + '.join(kinds)}",
                    )
                )
                rest.discard("iso_contains_exe")
                rest.discard("disk_contains_exe")
                rest.discard("iso_contains_script")
                rest.discard("disk_contains_script")
                rest.discard("archive_dangerous_member")
            if "office_remote_template" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_office_remote_template,
                        f"OOXML remote template «{att.filename}»",
                    )
                )
                rest.discard("office_remote_template")
            if "html_polyglot" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_html_polyglot,
                        f"HTML-polyglot «{att.filename}»",
                    )
                )
                rest.discard("html_polyglot")
                rest.discard("html_attachment")
            if "rar_archive" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_rar_archive,
                        f"RAR-архив «{att.filename}»",
                    )
                )
                rest.discard("rar_archive")
            if "office_hyperlink" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_office_hyperlink,
                        f"OOXML-гиперссылки в «{att.filename}»",
                    )
                )
                rest.discard("office_hyperlink")
            if "nested_archive" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_nested_archive,
                        f"Вложенный архив внутри «{att.filename}»",
                    )
                )
                rest.discard("nested_archive")
            if "archive_double_extension" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_archive_double_extension,
                        f"Двойное расширение члена архива «{att.filename}»",
                    )
                )
                rest.discard("archive_double_extension")
            if "script_attachment" in rest or "script_url" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_script_attachment,
                        f"Скрипт-вложение «{att.filename}»"
                        + (" с URL" if "script_url" in rest else ""),
                    )
                )
                rest.discard("script_attachment")
                rest.discard("script_url")
                rest.discard("dangerous_extension")
            if "yara_match" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_yara_match,
                        f"YARA match на «{att.filename}»",
                    )
                )
                rest.discard("yara_match")
            if "office_dde" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_office_dde,
                        f"Excel DDE / formula injection в «{att.filename}»",
                    )
                )
                rest.discard("office_dde")
            if "ole_package" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_ole_package,
                        f"OLE Package / Ole10Native в «{att.filename}»",
                    )
                )
                rest.discard("ole_package")
                rest.discard("ole_embedded_object")
            if "pdf_openaction_uri" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_pdf_openaction_uri,
                        f"PDF «{att.filename}»: OpenAction + /URI вместе",
                    )
                )
                rest.discard("pdf_openaction_uri")
            if "onenote_embedded_file" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_attachment_onenote,
                        f"OneNote со встроенным файлом «{att.filename}»",
                    )
                )
                rest.discard("onenote_embedded_file")
                rest.discard("onenote_attachment")
            if "pdf_launch" in rest or "pdf_submitform" in rest or "pdf_gotor" in rest:
                which = [
                    name
                    for name in ("pdf_launch", "pdf_submitform", "pdf_gotor")
                    if name in rest
                ]
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_pdf_launch,
                        f"PDF «{att.filename}»: {', '.join(which)}",
                    )
                )
                rest.discard("pdf_launch")
                rest.discard("pdf_submitform")
                rest.discard("pdf_gotor")
            if "lure_shortcut" in rest or "lure_shortcut_target" in rest:
                target = next(
                    (e for e in (att.archive_entries or []) if e),
                    "",
                )
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_lure_shortcut,
                        f"Файл-ярлык «{att.filename}»"
                        + (f" → {target[:80]}" if target else ""),
                    )
                )
                rest.discard("lure_shortcut")
                rest.discard("lure_shortcut_target")
                rest.discard("dangerous_extension")
            if "rtf_exploit" in rest or "rtf_objupdate" in rest or "rtf_equation" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_rtf_exploit,
                        f"RTF «{att.filename}»: objupdate / Equation / OLE",
                    )
                )
                rest.discard("rtf_exploit")
                rest.discard("rtf_objupdate")
                rest.discard("rtf_equation")
                rest.discard("rtf_ole")
            if "office_xlm" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_office_xlm,
                        f"Excel 4.0 / XLM «{att.filename}»",
                    )
                )
                rest.discard("office_xlm")
            if "office_vba_live" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_office_vba_live,
                        f"VBA автозапуск/загрузка «{att.filename}»",
                    )
                )
                rest.discard("office_vba_live")
                # Presence of vbaProject stays a soft flag only when live markers are absent.
                rest.discard("ooxml_vba")
                rest.discard("ole_macros_suspected")
                rest.discard("macro_enabled_office")
            if "html_form_action" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_form_action_suspicious,
                        f"HTML «{att.filename}»: form action на IP или подозрительный TLD",
                    )
                )
                rest.discard("html_form_action")
            if "office_external_data" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_office_external_data,
                        f"OOXML внешние данные «{att.filename}» (connections/WEBSERVICE/HYPERLINK)",
                    )
                )
                rest.discard("office_external_data")
            if rest:
                pts = cfg.weight_attachment_flag * min(2, len(rest))
                parts.append(
                    ScoreContribution(
                        "attachments",
                        pts,
                        f"Вложение «{att.filename}»: {', '.join(sorted(rest))}",
                    )
                )
        elif not soft_noted and (
            "archive" in att.risk_flags
            or "office_macro_capable" in att.risk_flags
            or "html_attachment" in att.risk_flags
            or "mht_attachment" in att.risk_flags
            or "svg_attachment" in att.risk_flags
        ):
            soft_noted = True
            pts = (
                cfg.weight_html_attachment
                if {"html_attachment", "mht_attachment", "svg_attachment"}.intersection(
                    att.risk_flags
                )
                else cfg.weight_attachment_soft
            )
            parts.append(
                ScoreContribution(
                    "attachments",
                    pts,
                    f"Вложение «{att.filename}» требует ручной проверки",
                )
            )
    return _apply_cap(parts, cfg.cap_attachments, "attachments")


def _suspicious_tld_host(value: str, kind: str) -> str:
    """Host of a domain or URL. A path segment such as q3.zip is not a zone."""
    if kind == "domain":
        return (value or "").lower().strip().rstrip(".")
    if kind != "url":
        return ""
    try:
        host = urlparse(value).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def _is_file_attachment(att) -> bool:
    """File attachment. Inline / CID images stay in the list for QR only."""
    if "inline_image" in (getattr(att, "risk_flags", None) or []):
        return False
    name = (getattr(att, "filename", "") or "").lower()
    return not name.startswith("cid-")


def _originating_received(result: AnalysisResult) -> str:
    """Received hop closest to the sender, not the recipient gateway.

    Several hops: the last one is the origin. One hop has no separate origin.
    If that only line is the recipient gateway, it does not earn this relief.
    An internal hostname on that same single line still does.
    """
    origin = (result.raw_headers or {}).get("Received-Origin", "") or ""
    if origin.strip():
        return origin
    for finding in result.headers:
        if finding.name == "Received (origin)" and (finding.value or "").strip():
            return finding.value
    mid = result.mail_identity
    if mid is not None and mid.received_hops <= 1:
        hop = mid.first_received or ""
        if hop and _RECIPIENT_GATEWAY_RE.search(hop):
            return ""
        return hop
    return ""


def _url_host(value: str) -> str:
    try:
        return (urlparse(value).hostname or "").lower()
    except ValueError:
        return ""


def _host_is_raw_ip(host: str) -> bool:
    """Hostname of an already found URL is a raw IPv4 or IPv6 address."""
    host = (host or "").strip().lower()
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return True
    if ":" not in host:
        return False
    try:
        ipaddress.IPv6Address(host.split("%", 1)[0])
    except ValueError:
        return False
    return True


def _score_urls(
    result: AnalysisResult, cfg: VerdictConfig
) -> tuple[int, list[ScoreContribution]]:
    parts: list[ScoreContribution] = []
    if any(u.changed for u in result.url_rewrites):
        nested = sum(1 for u in result.url_rewrites if len(u.chain) > 1)
        detail = "Обнаружены URL rewrite (SafeLinks/Proofpoint/…) — развёрнуты локально"
        if nested:
            detail = (
                f"Вложенные URL-цепочки unwrap ({nested}) — "
                "SafeLinks/ProxySG/… развёрнуты локально"
            )
        parts.append(
            ScoreContribution(
                "urls",
                cfg.weight_url_rewrite + (3 if nested else 0),
                detail,
            )
        )

    ip_urls = [
        i
        for i in result.iocs
        if i.ioc_type.value == "url" and _host_is_raw_ip(_url_host(i.value))
    ]
    if ip_urls:
        parts.append(
            ScoreContribution(
                "urls",
                cfg.weight_url_raw_ip,
                "URL ведёт на сырой IP-адрес",
            )
        )

    suspicious_tlds = cfg.suspicious_tlds or ()
    for ioc in result.iocs:
        host = _suspicious_tld_host(ioc.value, ioc.ioc_type.value)
        if host and any(host.endswith(tld) for tld in suspicious_tlds):
            parts.append(
                ScoreContribution(
                    "urls",
                    cfg.weight_suspicious_tld,
                    f"Подозрительная зона в индикаторе: {ioc.value}",
                )
            )
            break
    return _apply_cap(parts, cfg.cap_urls, "urls")


def _from_domain(result: AnalysisResult) -> str:
    raw = ""
    if result.mail_identity and result.mail_identity.from_header:
        raw = result.mail_identity.from_header
    elif result.sender:
        raw = result.sender
    if "<" in raw and ">" in raw:
        raw = raw.split("<", 1)[1].split(">", 1)[0]
    raw = raw.strip().lower().strip(">")
    if "@" not in raw:
        return ""
    return raw.rsplit("@", 1)[-1].strip()


_FREEMAIL_DOMAINS = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "mail.ru",
        "bk.ru",
        "inbox.ru",
        "list.ru",
        "yandex.ru",
        "ya.ru",
        "yandex.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "icloud.com",
        "rambler.ru",
        "yahoo.com",
    }
)
_LURE_FILE_SUFFIXES = (
    ".html",
    ".htm",
    ".url",
    ".iqy",
    ".slk",
    ".settingcontent-ms",
    ".library-ms",
    ".searchconnector-ms",
    ".appref-ms",
    ".diagcab",
    ".hta",
    ".scf",
    ".chm",
)


def _append_lure_compounds(result: AnalysisResult, signals: list) -> None:
    """Password+lure-file and freemail+BEC, scored with the content cap."""
    from reliquary.core.content_signals import ContentSignal

    kinds = {s.kind for s in signals}
    lure_file = any(
        (a.filename or "").lower().endswith(_LURE_FILE_SUFFIXES)
        or "lure_shortcut" in (a.risk_flags or [])
        or "html_attachment" in (a.risk_flags or [])
        for a in result.attachments
    )
    if (
        lure_file
        and kinds.intersection({"archive_password", "archive_password_match"})
        and "password_lure_file" not in kinds
    ):
        signals.append(
            ContentSignal(
                "password_lure_file",
                "Пароль в теле и вложение HTML/ярлык",
                "weight_password_lure_file",
            )
        )
    if "bec_payment" in kinds and "freemail_bec" not in kinds:
        dom = _from_domain(result)
        if dom in _FREEMAIL_DOMAINS:
            signals.append(
                ContentSignal(
                    "freemail_bec",
                    f"BEC с freemail From ({dom})",
                    "weight_freemail_bec",
                )
            )


def _text_for_score(result: AnalysisResult) -> str:
    """Same corpus IOC extraction already built, else the source preview."""
    return result.score_text or result.raw_text_preview or ""


def _html_for_score(result: AnalysisResult) -> str:
    if result.score_html:
        return result.score_html
    return result.html_preview or ""


def _score_content(
    result: AnalysisResult, cfg: VerdictConfig
) -> tuple[int, list[ScoreContribution]]:
    parts: list[ScoreContribution] = []
    blob = f"{result.subject}\n{_text_for_score(result)}"
    if URGENCY_RE.search(blob):
        parts.append(
            ScoreContribution(
                "content",
                cfg.weight_urgency,
                "В теме/тексте маркеры срочности / social engineering",
            )
        )

    has_urls = any(i.ioc_type.value == "url" for i in result.iocs)
    has_att = bool(result.attachments)
    has_file = any(_is_file_attachment(a) for a in result.attachments)
    if has_urls and has_file and result.source_kind == "email":
        parts.append(
            ScoreContribution(
                "content",
                cfg.weight_links_and_attachments,
                "Письмо содержит и ссылки, и вложения",
            )
        )

    has_qr = any(
        "qr_url" in a.risk_flags or any(e.startswith("QR:") for e in a.archive_entries)
        for a in result.attachments
    )
    has_enc = any("encrypted_archive" in (a.risk_flags or []) for a in result.attachments)
    has_office_enc = any("office_encrypted" in (a.risk_flags or []) for a in result.attachments)
    signals = analyze_content_signals(
        _text_for_score(result),
        _html_for_score(result),
        has_qr=has_qr,
        has_urls=has_urls,
        has_attachments=has_att,
        has_encrypted_archive=has_enc,
        has_office_encrypted=has_office_enc,
        suspicious_tlds=cfg.suspicious_tlds,
    )
    _append_lure_compounds(result, signals)
    # Persist kinds on result for export / corpus. A YARA hit may already
    # occupy the list; this pass still has to be visible to mitigation.
    if signals:
        have = list(result.content_signals or [])
        seen = set(have)
        for sig in signals:
            if sig.kind not in seen:
                have.append(sig.kind)
                seen.add(sig.kind)
        result.content_signals = have

    weight_map = {
        "weight_credential_harvest": cfg.weight_credential_harvest,
        "weight_bec_payment": cfg.weight_bec_payment,
        "weight_href_mismatch": cfg.weight_href_mismatch,
        "weight_hidden_text": cfg.weight_hidden_text,
        "weight_html_form": cfg.weight_html_form,
        "weight_qr_only": cfg.weight_qr_only,
        "weight_qr_present": cfg.weight_qr_present,
        "weight_qr_lure": cfg.weight_qr_lure,
        "weight_qr_credential": cfg.weight_qr_credential,
        "weight_url_shortener": cfg.weight_url_shortener,
        "weight_messenger_only": cfg.weight_messenger_only,
        "weight_messenger_lure": cfg.weight_messenger_lure,
        "weight_archive_password": cfg.weight_archive_password,
        "weight_archive_password_match": cfg.weight_archive_password_match,
        "weight_oob_delivery": cfg.weight_oob_delivery,
        "weight_cloud_lure": cfg.weight_cloud_lure,
        "weight_cid_phishing": cfg.weight_cid_phishing,
        "weight_form_action_suspicious": cfg.weight_form_action_suspicious,
        "weight_wrap_lure": cfg.weight_wrap_lure,
        "weight_campaign_divergence": cfg.weight_campaign_divergence,
        "weight_dangerous_scheme": cfg.weight_dangerous_scheme,
        "weight_url_userinfo": cfg.weight_url_userinfo,
        "weight_bec_callback": cfg.weight_bec_callback,
        "weight_payment_tokens": cfg.weight_payment_tokens,
        "weight_password_lure_file": cfg.weight_password_lure_file,
        "weight_freemail_bec": cfg.weight_freemail_bec,
        "weight_clickfix": cfg.weight_clickfix,
        "weight_image_only_body": cfg.weight_image_only_body,
        "weight_fake_auth_results": cfg.weight_fake_auth_results,
    }
    for sig in signals:
        pts = weight_map.get(sig.weight_key, 8)
        parts.append(ScoreContribution("content", pts, sig.detail))

    # Proxy wrap × lure composite (SafeLinks / Mail.ru / VK / Bitrix + lure)
    wrap_kinds = {
        "microsoft_safelinks",
        "mailru_away",
        "vk_away",
        "bitrix_redir",
        "yandex_redir",
        "ok_redir",
        "kaspersky_wrap",
        "drweb_wrap",
    }
    has_wrap = any(u.changed for u in result.url_rewrites) or any(
        (getattr(u, "rewriter", "") or "") in wrap_kinds for u in result.url_rewrites
    )
    sig_kinds = {s.kind for s in signals} | set(result.content_signals or [])
    has_lure = bool(
        URGENCY_RE.search(blob)
        or sig_kinds.intersection(
            {
                "credential_harvest",
                "archive_password",
                "archive_password_match",
                "qr_lure",
                "qr_credential",
            }
        )
    )
    if has_wrap and has_lure and "wrap_lure" not in sig_kinds:
        parts.append(
            ScoreContribution(
                "content",
                cfg.weight_wrap_lure,
                "URL-wrap (SafeLinks/Mail.ru/VK/…) + lure (urgency/credential/archive/QR)",
            )
        )
        if "wrap_lure" not in (result.content_signals or []):
            result.content_signals = list(result.content_signals or []) + ["wrap_lure"]

    return _apply_cap(parts, cfg.cap_content, "content")


def _score_lookalike(
    result: AnalysisResult,
    cfg: VerdictConfig,
    *,
    brands_path: str | Path | None = None,
    org_domains_path: str | Path | None = None,
) -> tuple[int, list[ScoreContribution]]:
    parts: list[ScoreContribution] = []
    brands = load_brands(brands_path)
    org_domains = load_org_domains(org_domains_path)
    from_addr = ""
    if result.mail_identity and result.mail_identity.from_header:
        from_addr = result.mail_identity.from_header
    elif result.sender:
        from_addr = result.sender
    domains = [
        i.value
        for i in result.iocs
        if i.ioc_type.value in ("domain", "url", "email")
    ]
    hits = scan_lookalikes(
        from_addr=from_addr,
        text=_text_for_score(result),
        domains=domains,
        brands=brands,
        org_domains=org_domains,
    )
    seen_kinds: set[str] = set()
    display_pts = 0
    # A bare IDN adds nothing unless this pass also has a brand homoglyph.
    idn_weight = cfg.weight_idn if any(hit.kind == "homoglyph" for hit in hits) else 0
    for hit in hits:
        if hit.kind in seen_kinds and hit.kind != "levenshtein":
            continue
        seen_kinds.add(hit.kind)
        if hit.kind == "idn":
            pts = idn_weight
        elif hit.kind in ("display_spoof", "org_display_spoof"):
            # Cap display-spoof so spoof cases don't all pin at 100 with compounds
            room = max(0, cfg.cap_display_spoof - display_pts)
            pts = min(cfg.weight_display_spoof, room)
            display_pts += pts
        else:
            pts = cfg.weight_lookalike
        if hit.kind in ("org_lookalike", "org_display_spoof"):
            _remember_signal(result, "org_domain")
        if pts <= 0:
            continue
        parts.append(ScoreContribution("lookalike", pts, hit.detail))
        if len(parts) >= 3:
            break
    # Prefer tighter lookalike budget when display_spoof dominated
    lookalike_cap = (
        min(cfg.cap_lookalike, cfg.cap_display_spoof)
        if display_pts > 0
        else cfg.cap_lookalike
    )
    return _apply_cap(parts, lookalike_cap, "lookalike")


def _remember_signal(result: AnalysisResult, kind: str) -> None:
    if kind not in (result.content_signals or []):
        result.content_signals = list(result.content_signals or []) + [kind]


def _append_lure_pair_compounds(
    result: AnalysisResult,
    parts: list[ScoreContribution],
    cfg: VerdictConfig,
) -> None:
    """Pairs that should clear suspicious (30): image+link, macro+password, HTML form."""
    sigs = set(result.content_signals or [])
    flags = {f for att in result.attachments for f in (att.risk_flags or [])}
    if "image_only_body" in sigs and "image_only_link" not in sigs:
        parts.append(
            ScoreContribution(
                "compound",
                cfg.weight_image_only_link,
                "Картинка без текста и внешняя http-ссылка",
            )
        )
        _remember_signal(result, "image_only_link")
    macroish = flags.intersection(
        {
            "office_xlm",
            "office_vba_live",
            "ooxml_vba",
            "ole_macros_suspected",
            "macro_enabled_office",
        }
    )
    if (
        macroish
        and sigs.intersection({"archive_password", "archive_password_match"})
        and "macro_password" not in sigs
    ):
        parts.append(
            ScoreContribution(
                "compound",
                cfg.weight_macro_password,
                "Макрос или XLM и пароль в теле письма",
            )
        )
        _remember_signal(result, "macro_password")
    html_att = flags.intersection(
        {"html_attachment", "mht_attachment", "svg_attachment", "html_form_action"}
    )
    formish = "form_action_suspicious" in sigs or "html_form_action" in flags
    if html_att and formish and "html_form_lure" not in sigs:
        parts.append(
            ScoreContribution(
                "compound",
                cfg.weight_html_form_lure,
                "HTML-вложение и подозрительный form action",
            )
        )
        _remember_signal(result, "html_form_lure")


def _score_compounds(
    result: AnalysisResult,
    cfg: VerdictConfig,
    *,
    prior_breakdown: list[ScoreContribution] | None = None,
) -> tuple[int, list[ScoreContribution]]:
    """Compound boosts: SPF+lookalike, Reply-To, Return-Path, ARC, reply-chain, campaign."""
    parts: list[ScoreContribution] = []
    mid = result.mail_identity

    spf_bad = False
    spf_softfail_only = False
    dmarc_pass = False
    dmarc_fail = False
    dmarc_none = False
    spf_fail = False
    reply_mismatch = False
    return_path_mismatch = False
    arc_fail = False
    reply_chain = False

    for h in result.headers:
        name = (h.name or "").lower()
        val = (h.value or "").lower()
        note = (h.note or "").lower()
        if name.endswith(" result") or name in ("spf", "dkim", "dmarc", "received-spf"):
            if "spf" in name and val in ("fail", "softfail"):
                spf_bad = True
                if val == "fail":
                    spf_fail = True
                elif val == "softfail":
                    spf_softfail_only = True
            if "dmarc" in name:
                if val == "pass":
                    dmarc_pass = True
                if val == "fail":
                    dmarc_fail = True
                if val in ("none", "permerror", "temperror"):
                    dmarc_none = True
            if name.startswith("arc") and val == "fail":
                arc_fail = True
        if "softfail" in val or "softfail" in note:
            if "spf" in name or "spf" in note or "auth" in name:
                spf_bad = True
                if "fail" not in val.replace("softfail", ""):
                    spf_softfail_only = True
        if "reply-to mismatch" in name:
            reply_mismatch = True
        if "return-path mismatch" in name:
            return_path_mismatch = True
        # Only real ARC fail / ARC result fail — not "Auth fail без ARC"
        if name == "arc result" and val == "fail":
            arc_fail = True
        if name == "arc" and "fail" in val and "нет" not in val:
            arc_fail = True
        if "reply-chain anomaly" in name:
            reply_chain = True

    if mid:
        spf_m = (mid.spf or "").lower()
        dmarc_m = (mid.dmarc or "").lower()
        if spf_m in ("fail", "softfail"):
            spf_bad = True
            if spf_m == "fail":
                spf_fail = True
            elif spf_m == "softfail":
                spf_softfail_only = True
        if dmarc_m == "pass":
            dmarc_pass = True
        if dmarc_m == "fail":
            dmarc_fail = True
        if dmarc_m in ("none", "permerror", "temperror", ""):
            if dmarc_m != "pass":
                dmarc_none = dmarc_m in ("none", "permerror", "temperror") or not dmarc_m

    prior = prior_breakdown or []
    lookalike_hit = any(c.category == "lookalike" and c.points > 0 for c in prior)

    # SPF softfail alone must NOT stack unless lookalike/display_spoof also fires.
    # Hard SPF fail is already scored in headers — use half compound to avoid pin@100.
    if spf_bad and lookalike_hit:
        pts = cfg.weight_spf_lookalike
        if spf_fail:
            pts = max(4, cfg.weight_spf_lookalike // 2)
        parts.append(
            ScoreContribution(
                "compound",
                pts,
                "SPF softfail/fail + lookalike/display-spoof",
            )
        )

    # Reply-To mismatch + weak auth (no DMARC pass / DMARC fail / SPF fail)
    if reply_mismatch and ((not dmarc_pass) or dmarc_fail or spf_fail or spf_bad):
        parts.append(
            ScoreContribution(
                "compound",
                cfg.weight_reply_to_spoof,
                "Reply-To mismatch при слабой auth (нет DMARC pass / fail)",
            )
        )

    # Return-Path ≠ From + weak DMARC / no alignment / softfail
    weak_dmarc = (not dmarc_pass) or dmarc_fail or dmarc_none or spf_softfail_only or spf_fail
    if return_path_mismatch and weak_dmarc:
        parts.append(
            ScoreContribution(
                "compound",
                cfg.weight_return_path_mismatch,
                "Return-Path ≠ From при слабой DMARC/auth — усиление mismatch",
            )
        )

    if arc_fail:
        parts.append(
            ScoreContribution(
                "compound",
                cfg.weight_arc_fail,
                "ARC-Authentication-Results fail",
            )
        )

    if reply_chain:
        # Credential/BEC already in content; always score the header anomaly
        parts.append(
            ScoreContribution(
                "compound",
                cfg.weight_reply_chain_anomaly,
                "Reply-chain spoof: From ≠ prior Message-ID domain / Re:+чужой From",
            )
        )

    # Campaign divergence (batch peers or content signal)
    if "campaign_divergence" in (result.content_signals or []):
        parts.append(
            ScoreContribution(
                "compound",
                cfg.weight_campaign_divergence,
                "Кампания: один ключ, разные From-домены (≥2 писем)",
            )
        )
    elif result.file_rows and len(result.file_rows) >= 2:
        by_key: dict[str, set[str]] = {}
        for row in result.file_rows:
            key = (row.campaign_key or "").strip()
            if not key:
                continue
            sender = (row.sender or "").strip().lower()
            dom = ""
            if "@" in sender:
                addr = sender
                if "<" in sender and ">" in sender:
                    addr = sender.split("<", 1)[1].split(">", 1)[0]
                dom = addr.rsplit("@", 1)[-1].strip(">")
            if dom:
                by_key.setdefault(key, set()).add(dom)
        if any(len(doms) >= 2 for doms in by_key.values()):
            parts.append(
                ScoreContribution(
                    "compound",
                    cfg.weight_campaign_divergence,
                    "Кампания: один ключ, разные From-домены (≥2 писем)",
                )
            )
            if "campaign_divergence" not in (result.content_signals or []):
                result.content_signals = list(result.content_signals or []) + [
                    "campaign_divergence"
                ]

    for h in result.headers:
        if h.name == "Sender mismatch" and h.severity == Severity.HIGH:
            parts.append(
                ScoreContribution(
                    "compound",
                    cfg.weight_sender_mismatch,
                    "Sender ≠ From без DMARC pass",
                )
            )
            break
    if any(h.name == "Orphan reply" for h in result.headers):
        parts.append(
            ScoreContribution(
                "compound",
                cfg.weight_orphan_reply,
                "Тема Re:/Отв: без In-Reply-To и References",
            )
        )
    if any(h.name == "Mailer brand mismatch" for h in result.headers):
        parts.append(
            ScoreContribution(
                "compound",
                cfg.weight_mailer_brand,
                "Скриптовый X-Mailer при display-name бренда",
            )
        )

    _append_lure_pair_compounds(result, parts, cfg)

    total = sum(c.points for c in parts)
    return total, parts


# Inbound cloud gateways. They are not an originating hop when they are the only Received.
_RECIPIENT_GATEWAY_RE = re.compile(
    r"(?i)\b("
    r"outlook\.office365\.com|mail\.protection\.outlook\.com|"
    r"protection\.outlook\.com|mail\.google\.com|googlemail\.com"
    r")"
)

_INTERNAL_RELAY_RE = re.compile(
    r"(?i)\b("
    r"mail\.internal|intranet|corp\.local|ad\.local|"
    r"mail\.[a-z0-9\-]+\.(local|lan|corp|internal)|"
    r"mx\.[a-z0-9\-]+\.(local|lan|corp|internal)|"
    r"outlook\.office365\.com|mail\.protection\.outlook\.com|"
    r"protection\.outlook\.com|mail\.google\.com|googlemail\.com|"
    # Typical RU / on-prem relay hostnames seen in Received
    r"mail\.(sber|vtb|alfa|gazprom|rosneft|rzd|rt\.ru)|"
    r"relay\.[a-z0-9\-]+\.(ru|local)|"
    r"smtp\.[a-z0-9\-]+\.(local|lan|corp)"
    r")"
)


def _apply_mitigation_floor(
    contributions: list[ScoreContribution],
    max_abs: int,
) -> tuple[int, list[ScoreContribution]]:
    """Clamp total mitigation so score cannot be reduced by more than ``max_abs``."""
    total = sum(c.points for c in contributions)
    if total >= 0:
        return 0, []
    floor = -abs(max_abs)
    if total >= floor:
        return total, contributions
    # Scale negative points up toward floor (less mitigation)
    if total == 0:
        return 0, contributions
    scaled: list[ScoreContribution] = []
    remaining = floor
    for i, c in enumerate(contributions):
        if i == len(contributions) - 1:
            pts = remaining
        else:
            pts = int(round(c.points * floor / total))
            remaining -= pts
        scaled.append(
            ScoreContribution(
                category="mitigation",
                points=pts,
                reason=c.reason + " [cap]",
                capped=True,
            )
        )
    drift = floor - sum(c.points for c in scaled)
    if drift and scaled:
        scaled[-1] = ScoreContribution(
            category="mitigation",
            points=scaled[-1].points + drift,
            reason=scaled[-1].reason,
            capped=True,
        )
    return floor, scaled


def _score_mitigations(
    result: AnalysisResult,
    cfg: VerdictConfig,
    *,
    allowlist_domains: set[str] | None = None,
    prior_breakdown: list[ScoreContribution] | None = None,
) -> tuple[int, list[ScoreContribution]]:
    """Negative contributions when auth/path looks trusted (DMARC pass, internal MX).

    Skipped when strong attack signals are present so phishing with forged
    'pass' auth (or brand spoof) is not under-scored. Benign markers
    (auto-reply / calendar / signature) still apply unless high-risk attachments
    or credential/BEC content are present.
    """
    mid = result.mail_identity
    high_att = {
        "double_extension",
        "dangerous_extension",
        "ole_macros_suspected",
        "ooxml_vba",
        "macro_enabled_office",
        "nested_email",
        "qr_url",
        "archive_dangerous_member",
        "encrypted_archive",
        "mime_mismatch",
        "iso_image",
        "shortcut_lnk",
        "lnk_dangerous",
        "lnk_http_target",
        "onenote_attachment",
        "pdf_javascript",
        "pdf_uri_action",
        "html_smuggling",
        "svg_script",
        "cab_archive",
        "cab_contains_lnk",
        "archive_nested_email",
        "zip_bomb_suspect",
        "tnef_attachment",
        "iso_contains_lnk",
        "iso_contains_exe",
        "disk_contains_exe",
        "office_hyperlink",
        "office_remote_template",
        "nested_archive",
        "archive_double_extension",
        "script_attachment",
        "script_url",
        "disk_image",
        "html_polyglot",
        "rar_archive",
        "yara_match",
        "office_dde",
        "ole_package",
        "pdf_openaction_uri",
        "pdf_launch",
        "pdf_submitform",
        "pdf_gotor",
        "onenote_embedded_file",
        "lure_shortcut",
        "lure_shortcut_target",
        "rtf_exploit",
        "office_encrypted",
        "office_external_data",
        "office_xlm",
        "office_vba_live",
        "html_form_action",
        "iso_contains_script",
        "disk_contains_script",
    }
    has_high_att = any(high_att.intersection(a.risk_flags) for a in result.attachments)
    bad_content = {
        "href_mismatch",
        "credential_harvest",
        "bec_payment",
        "qr_only",
        "qr_lure",
        "qr_credential",
        "messenger_lure",
        "hidden_text",
        "archive_password_match",
        "oob_delivery",
        "cloud_lure",
        "cid_phishing",
        "form_action_suspicious",
        "wrap_lure",
        "campaign_divergence",
        "dangerous_scheme",
        "url_userinfo",
        "bec_callback",
        "payment_tokens",
        "password_lure_file",
        "freemail_bec",
        "clickfix",
        "image_only_body",
        "image_only_link",
        "macro_password",
        "html_form_lure",
        "fake_auth_results",
        "org_domain",
    }
    has_bad_content = bool(bad_content.intersection(result.content_signals or []))
    # Brand lookalike blocks the same relief as display-name spoof.
    # A bare IDN (почта.рф) is not that lookalike; a homoglyph still is.
    has_positive_lookalike = any(
        c.category == "lookalike"
        and c.points > 0
        and not (c.reason or "").startswith("IDN/punycode")
        for c in (prior_breakdown or [])
    )
    # Display-name spoof must block allowlist-From mitigation
    has_display_spoof = any(
        c.category == "lookalike"
        and ("Имя" in (c.reason or "") or "spoof" in (c.reason or "").lower() or "похож" in (c.reason or "").lower())
        for c in (result.verdict.breakdown if result.verdict else []) or []
    )
    # Also detect from lookalike scan of From header when breakdown not yet filled
    if not has_display_spoof and mid and mid.from_header:
        try:
            from reliquary.core.lookalike import check_display_name_spoof

            has_display_spoof = bool(check_display_name_spoof(mid.from_header))
        except (ImportError, TypeError, ValueError):
            has_display_spoof = False

    parts: list[ScoreContribution] = []

    blocks_relief = has_display_spoof or has_positive_lookalike
    # Benign operational markers — apply unless clear attack surface
    if not has_high_att and not has_bad_content and not blocks_relief:
        parts.extend(_benign_marker_parts(result, cfg))

    if mid is None:
        return _apply_mitigation_floor(parts, cfg.cap_mitigation) if parts else (0, [])

    if has_high_att or has_bad_content or blocks_relief:
        return _apply_mitigation_floor(parts, cfg.cap_mitigation) if parts else (0, [])

    attack_headers = any(
        h.severity in (Severity.HIGH, Severity.CRITICAL)
        and not (h.name.endswith(" result") and (h.value or "").lower() == "pass")
        for h in result.headers
    )
    auth_impaired = any(
        h.name.endswith(" result")
        and (h.value or "").lower()
        in ("fail", "softfail", "permerror", "temperror", "none")
        for h in result.headers
    )
    if attack_headers or auth_impaired:
        return _apply_mitigation_floor(parts, cfg.cap_mitigation) if parts else (0, [])

    has_alignment_fail = any(h.name == "DKIM alignment" for h in result.headers)

    dmarc_ok = (mid.dmarc or "").lower() == "pass"
    dkim_ok = (mid.dkim or "").lower() == "pass"
    spf_ok = (mid.spf or "").lower() == "pass"

    if dmarc_ok and dkim_ok and not has_alignment_fail:
        parts.append(
            ScoreContribution(
                "mitigation",
                cfg.weight_dmarc_pass_aligned,
                "DMARC+DKIM pass без misalignment — смягчение score",
            )
        )
    elif spf_ok and dkim_ok and dmarc_ok:
        parts.append(
            ScoreContribution(
                "mitigation",
                cfg.weight_auth_full_pass,
                "SPF+DKIM+DMARC pass — смягчение score",
            )
        )

    hop = _originating_received(result)
    from_m = re.search(r"(?i)\bfrom\s+([^\s\(;]+)", hop)
    hop_from = from_m.group(1) if from_m else hop
    if hop_from and _INTERNAL_RELAY_RE.search(hop_from):
        parts.append(
            ScoreContribution(
                "mitigation",
                cfg.weight_internal_relay,
                "Received hop похож на внутренний / доверенный MX",
            )
        )

    # Org allowlist: trusted From domain → soft mitigation (IOC tags alone don't change score)
    if allowlist_domains:
        from_hdr = mid.from_header or ""
        host = ""
        if "@" in from_hdr:
            addr = from_hdr
            if "<" in from_hdr and ">" in from_hdr:
                addr = from_hdr.split("<", 1)[1].split(">", 1)[0]
            host = addr.rsplit("@", 1)[-1].strip().lower().strip(">")
        if host:
            try:
                from reliquary.core.allowlist import domain_matches

                if domain_matches(host, allowlist_domains):
                    parts.append(
                        ScoreContribution(
                            "mitigation",
                            cfg.weight_allowlisted_from,
                            f"From-домен в allowlist: {host}",
                        )
                    )
            except (ImportError, TypeError, ValueError):
                pass

    return _apply_mitigation_floor(parts, cfg.cap_mitigation)


_AUTO_REPLY_SUBJ = re.compile(
    r"(?i)^(auto[-\s]?reply|automatic reply|out of office|ооо|автоответ|"
    r"не\s*у\s*компьютера|away from (?:the )?office)\b"
)
_CALENDAR_RE = re.compile(r"(?i)BEGIN:VCALENDAR")
_VCAL_BLOCK_RE = re.compile(
    r"(?is)BEGIN:VCALENDAR.{0,8000}?END:VCALENDAR"
)


def _calendar_surface(result: AnalysisResult, blob: str) -> bool:
    """Calendar relief only when a calendar part is already present."""
    if _CALENDAR_RE.search(blob or ""):
        return True
    return any(
        (a.mime_guess or "").lower() == "text/calendar"
        or (a.filename or "").lower().endswith((".ics", ".ical"))
        for a in result.attachments
    )


def _ics_contains_url(result: AnalysisResult, blob: str) -> bool:
    """True when the calendar payload itself carries an http(s) link."""
    return _ics_payload_matches(result, blob, re.compile(r"(?i)https?://"), re.compile(br"(?i)https?://"))


def _ics_has_attach(result: AnalysisResult, blob: str) -> bool:
    """True when the calendar payload carries an ATTACH property."""
    return _ics_payload_matches(
        result,
        blob,
        re.compile(r"(?im)^ATTACH[;:]"),
        re.compile(br"(?im)^ATTACH[;:]"),
    )


def _ics_payload_matches(
    result: AnalysisResult,
    blob: str,
    text_re: re.Pattern[str],
    raw_re: re.Pattern[bytes],
) -> bool:
    for match in _VCAL_BLOCK_RE.finditer(blob or ""):
        if text_re.search(match.group(0)):
            return True
    for att in result.attachments:
        name = (att.filename or "").lower()
        mime = (att.mime_guess or "").lower()
        if mime != "text/calendar" and not name.endswith((".ics", ".ical")):
            continue
        raw = att.data or b""
        if raw_re.search(raw):
            return True
    return False


_CORP_SIG_RE = re.compile(
    r"(?i)(с уважением|best regards|kind regards|confidentiality notice|"
    r"это сообщение и любые вложения|disclaimer|юридическ\w+\s+оговорк)"
)


def _header_domain(value: str) -> str:
    raw = (value or "").strip()
    if "<" in raw and ">" in raw:
        raw = raw.split("<", 1)[1].split(">", 1)[0]
    if "@" not in raw:
        return ""
    return raw.rsplit("@", 1)[-1].strip().lower().strip(">").strip(".")


def _domains_related(left: str, right: str) -> bool:
    if not left or not right:
        return False
    return left == right or left.endswith("." + right) or right.endswith("." + left)


_LIST_UNSUB_URL_RE = re.compile(r"(?i)https?://[^\s<>\"']+")
_LIST_UNSUB_MAIL_RE = re.compile(r"(?i)mailto:([^>\s,]+)")


def _list_unsubscribe_hosts(value: str) -> list[str]:
    hosts: list[str] = []
    for match in _LIST_UNSUB_URL_RE.finditer(value or ""):
        try:
            host = (urlparse(match.group(0)).hostname or "").lower().rstrip(".")
        except ValueError:
            host = ""
        if host:
            hosts.append(host)
    for match in _LIST_UNSUB_MAIL_RE.finditer(value or ""):
        dom = _header_domain(match.group(1))
        if dom:
            hosts.append(dom)
    return hosts


def _list_unsubscribe_foreign(result: AnalysisResult) -> bool:
    """A List-Unsubscribe host that is not the From domain."""
    mid = result.mail_identity
    if mid is None:
        return False
    raw = (mid.list_unsubscribe or "").strip()
    if not raw:
        return False
    from_dom = _header_domain(mid.from_header)
    if not from_dom:
        return False
    hosts = _list_unsubscribe_hosts(raw)
    if not hosts:
        return False
    return any(not _domains_related(from_dom, host) for host in hosts)


def _foreign_reply_domain(result: AnalysisResult) -> bool:
    """Reply-To or prior thread domain is not the From domain."""
    mid = result.mail_identity
    if mid is None:
        return False
    from_dom = _header_domain(mid.from_header)
    reply_dom = _header_domain(mid.reply_to)
    if from_dom and reply_dom and not _domains_related(from_dom, reply_dom):
        return True
    return any((h.name or "") == "Reply-chain anomaly" for h in result.headers)


def _benign_marker_parts(
    result: AnalysisResult, cfg: VerdictConfig
) -> list[ScoreContribution]:
    parts: list[ScoreContribution] = []
    mid = result.mail_identity
    subj = (result.subject or (mid.subject if mid else "") or "").strip()
    blob = f"{subj}\n{_text_for_score(result)}\n{_html_for_score(result)}"
    # Dangerous attachments and payment-change content skip this whole function.
    # A foreign reply domain skips only calendar and thread credit.
    foreign_reply = _foreign_reply_domain(result)

    auto = ((mid.auto_submitted if mid else "") or "").lower()
    if (auto and auto not in ("no", "")) or _AUTO_REPLY_SUBJ.search(subj):
        parts.append(
            ScoreContribution(
                "mitigation",
                cfg.weight_auto_reply,
                "Автоответ / Out-of-Office — смягчение score",
            )
        )
    if (
        not foreign_reply
        and _calendar_surface(result, blob)
        and not (_ics_contains_url(result, blob) or _ics_has_attach(result, blob))
    ):
        parts.append(
            ScoreContribution(
                "mitigation",
                cfg.weight_calendar_invite,
                "Календарное приглашение / ICS — смягчение score",
            )
        )
    if _CORP_SIG_RE.search(blob) and not any(
        k in (result.content_signals or [])
        for k in ("credential_harvest", "bec_payment", "href_mismatch")
    ):
        parts.append(
            ScoreContribution(
                "mitigation",
                cfg.weight_corp_signature,
                "Похоже на корпоративную подпись / дисклеймер",
            )
        )
    if mid and (mid.in_reply_to or mid.references) and not foreign_reply:
        # Same gateway prefix the campaign subject key strips, then the reply prefix.
        thread_subj = subj
        for _ in range(4):
            stripped = re.sub(
                r"(?i)^(?:\[(?:external|внешнее)\]|внешняя\s+почта:)\s*",
                "",
                thread_subj,
                count=1,
            ).strip()
            if stripped == thread_subj:
                break
            thread_subj = stripped
        if re.match(
            r"(?i)^(?:re(?:\[\d+\])?|fw|fwd|ответ|отв|переслано|пересл|на)\s*:",
            thread_subj,
        ):
            parts.append(
                ScoreContribution(
                    "mitigation",
                    cfg.weight_thread_reply,
                    "Ответ в существующем треде (In-Reply-To / References)",
                )
            )
    # Bulk / mailing-list markers
    prec = ((mid.precedence if mid else "") or "").lower()
    list_hdr = (
        ((mid.list_unsubscribe if mid else "") or "")
        + " "
        + ((mid.list_id if mid else "") or "")
    ).strip()
    if (list_hdr or prec in ("bulk", "list", "junk")) and not _list_unsubscribe_foreign(
        result
    ):
        parts.append(
            ScoreContribution(
                "mitigation",
                cfg.weight_mailing_list,
                "Рассылка / List-Unsubscribe / Precedence:bulk — смягчение score",
            )
        )
    return parts


