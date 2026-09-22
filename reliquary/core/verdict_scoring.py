"""Per-category verdict scorers."""

from __future__ import annotations

import re
from pathlib import Path

from reliquary.core.content_signals import analyze_content_signals
from reliquary.core.lookalike import load_brands, scan_lookalikes
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
    # Best finding per severity tier (avoid N× same weight)
    best: dict[Severity, str] = {}
    counts: dict[Severity, int] = {}
    for h in result.headers:
        if h.severity not in tier_weight:
            continue
        counts[h.severity] = counts.get(h.severity, 0) + 1
        if h.severity not in best:
            best[h.severity] = h.note or h.name
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
        "office_hyperlink",
        "nested_archive",
        "archive_double_extension",
        "script_attachment",
        "script_url",
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
        if i.ioc_type.value == "url" and re.search(r"https?://\d+\.\d+\.\d+\.\d+", i.value)
    ]
    if ip_urls:
        parts.append(
            ScoreContribution(
                "urls",
                cfg.weight_url_raw_ip,
                "URL ведёт на сырой IP-адрес",
            )
        )

    suspicious_tlds = (".xyz", ".top", ".club", ".gq", ".tk", ".ml", ".cf", ".ga", ".zip", ".mov")
    for ioc in result.iocs:
        if ioc.ioc_type.value in ("domain", "url"):
            val = ioc.value.lower()
            if any(val.endswith(tld) or f"{tld}/" in val for tld in suspicious_tlds):
                parts.append(
                    ScoreContribution(
                        "urls",
                        cfg.weight_suspicious_tld,
                        f"Подозрительная зона в индикаторе: {ioc.value}",
                    )
                )
                break
    return _apply_cap(parts, cfg.cap_urls, "urls")


def _score_content(
    result: AnalysisResult, cfg: VerdictConfig
) -> tuple[int, list[ScoreContribution]]:
    parts: list[ScoreContribution] = []
    blob = f"{result.subject}\n{result.raw_text_preview}"
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
    if has_urls and has_att and result.source_kind == "email":
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
    signals = analyze_content_signals(
        result.raw_text_preview,
        result.html_preview,
        has_qr=has_qr,
        has_urls=has_urls,
        has_attachments=has_att,
        has_encrypted_archive=has_enc,
    )
    # Persist kinds on result for export / corpus
    if signals and not result.content_signals:
        result.content_signals = [s.kind for s in signals]

    weight_map = {
        "weight_credential_harvest": cfg.weight_credential_harvest,
        "weight_bec_payment": cfg.weight_bec_payment,
        "weight_href_mismatch": cfg.weight_href_mismatch,
        "weight_hidden_text": cfg.weight_hidden_text,
        "weight_html_form": cfg.weight_html_form,
        "weight_qr_only": cfg.weight_qr_only,
        "weight_qr_present": cfg.weight_qr_present,
        "weight_url_shortener": cfg.weight_url_shortener,
        "weight_messenger_only": cfg.weight_messenger_only,
        "weight_archive_password": cfg.weight_archive_password,
        "weight_archive_password_match": cfg.weight_archive_password_match,
        "weight_oob_delivery": cfg.weight_oob_delivery,
        "weight_cloud_lure": cfg.weight_cloud_lure,
    }
    for sig in signals:
        pts = weight_map.get(sig.weight_key, 8)
        parts.append(ScoreContribution("content", pts, sig.detail))

    return _apply_cap(parts, cfg.cap_content, "content")


def _score_lookalike(
    result: AnalysisResult,
    cfg: VerdictConfig,
    *,
    brands_path: str | Path | None = None,
) -> tuple[int, list[ScoreContribution]]:
    parts: list[ScoreContribution] = []
    brands = load_brands(brands_path)
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
        text=result.raw_text_preview,
        domains=domains,
        brands=brands,
    )
    seen_kinds: set[str] = set()
    for hit in hits:
        if hit.kind in seen_kinds and hit.kind != "levenshtein":
            continue
        seen_kinds.add(hit.kind)
        if hit.kind == "idn":
            pts = cfg.weight_idn
        elif hit.kind == "display_spoof":
            pts = cfg.weight_display_spoof
        else:
            pts = cfg.weight_lookalike
        parts.append(ScoreContribution("lookalike", pts, hit.detail))
        if len(parts) >= 3:
            break
    return _apply_cap(parts, cfg.cap_lookalike, "lookalike")


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
        "office_hyperlink",
        "nested_archive",
        "archive_double_extension",
        "script_attachment",
        "script_url",
        "disk_image",
    }
    has_high_att = any(high_att.intersection(a.risk_flags) for a in result.attachments)
    bad_content = {
        "href_mismatch",
        "credential_harvest",
        "bec_payment",
        "qr_only",
        "hidden_text",
        "archive_password_match",
        "oob_delivery",
        "cloud_lure",
    }
    has_bad_content = bool(bad_content.intersection(result.content_signals or []))
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

    # Benign operational markers — apply unless clear attack surface
    if not has_high_att and not has_bad_content and not has_display_spoof:
        parts.extend(_benign_marker_parts(result, cfg))

    if mid is None:
        return _apply_mitigation_floor(parts, cfg.cap_mitigation) if parts else (0, [])

    if has_high_att or has_bad_content or has_display_spoof:
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

    hop = mid.first_received or ""
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
_CALENDAR_RE = re.compile(
    r"(?i)(BEGIN:VCALENDAR|text/calendar|meeting request|meeting:|"
    r"you are invited|calendar invite|приглашение|запрос на собрание|"
    r"план[её]рк)"
)
_CORP_SIG_RE = re.compile(
    r"(?i)(с уважением|best regards|kind regards|confidentiality notice|"
    r"это сообщение и любые вложения|disclaimer|юридическ\w+\s+оговорк)"
)


def _benign_marker_parts(
    result: AnalysisResult, cfg: VerdictConfig
) -> list[ScoreContribution]:
    parts: list[ScoreContribution] = []
    mid = result.mail_identity
    subj = (result.subject or (mid.subject if mid else "") or "").strip()
    blob = f"{subj}\n{result.raw_text_preview or ''}\n{result.html_preview or ''}"

    auto = ((mid.auto_submitted if mid else "") or "").lower()
    if (auto and auto not in ("no", "")) or _AUTO_REPLY_SUBJ.search(subj):
        parts.append(
            ScoreContribution(
                "mitigation",
                cfg.weight_auto_reply,
                "Автоответ / Out-of-Office — смягчение score",
            )
        )
    if _CALENDAR_RE.search(blob) or any(
        (a.mime_guess or "").lower() == "text/calendar"
        or a.filename.lower().endswith((".ics", ".ical"))
        for a in result.attachments
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
    if mid and (mid.in_reply_to or mid.references):
        if re.match(r"(?i)^(re|fw|fwd|отв|пересл)\s*:", subj):
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
    if list_hdr or prec in ("bulk", "list", "junk"):
        parts.append(
            ScoreContribution(
                "mitigation",
                cfg.weight_mailing_list,
                "Рассылка / List-Unsubscribe / Precedence:bulk — смягчение score",
            )
        )
    return parts


