"""Mail-triage heuristics (fully offline) — primary product output.

Applied to email artifacts (.eml / .msg). Weights are built-in constants
with optional local JSON override (``verdict_extra.json`` / ``--verdict``).

Score uses per-category caps so stacking identical flags does not inflate
malicious on noisy mail.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from reliquary.core.content_signals import analyze_content_signals
from reliquary.core.lookalike import load_brands, scan_lookalikes
from reliquary.core.models import (
    AnalysisResult,
    ScoreContribution,
    Severity,
    Verdict,
    VerdictLevel,
)
from reliquary.core.paths import app_dir

URGENCY_RE = re.compile(
    r"(?i)\b("
    r"urgent|immediately|verify your account|password.{0,10}expir|"
    r"confirm your identity|suspend|locked|invoice attached|"
    r"срочно|немедленно|подтвердите|пароль.{0,15}истек|"
    r"заблокир|счёт|счет|оплатите|выписка|безопасность аккаунта"
    r")\b"
)

_EXTRA_NAME = "verdict_extra.json"


@dataclass
class VerdictConfig:
    threshold_malicious: int = 60
    threshold_suspicious: int = 30
    threshold_unknown: int = 10
    weight_header_critical: int = 35
    weight_header_high: int = 25
    weight_header_medium: int = 12
    weight_header_low: int = 4
    weight_attachment_flag: int = 20
    weight_attachment_soft: int = 8
    weight_encrypted_archive: int = 22
    weight_url_rewrite: int = 5
    weight_url_raw_ip: int = 18
    weight_suspicious_tld: int = 10
    weight_urgency: int = 15
    weight_links_and_attachments: int = 10
    weight_credential_harvest: int = 14
    weight_bec_payment: int = 20
    weight_href_mismatch: int = 18
    weight_hidden_text: int = 10
    weight_html_form: int = 8
    weight_qr_only: int = 16
    weight_qr_present: int = 8
    weight_lookalike: int = 22
    weight_idn: int = 12
    weight_attachment_iso: int = 18
    weight_attachment_lnk: int = 16
    weight_attachment_onenote: int = 14
    # Mitigating (negative) signals — reduce score when auth/path looks trusted
    weight_dmarc_pass_aligned: int = -12
    weight_auth_full_pass: int = -6
    weight_internal_relay: int = -8
    weight_auto_reply: int = -10
    weight_calendar_invite: int = -8
    weight_corp_signature: int = -5
    weight_thread_reply: int = -4
    # Per-category caps (evidence stacking without score explosion)
    cap_headers: int = 45
    cap_attachments: int = 40
    cap_urls: int = 30
    cap_content: int = 40
    cap_lookalike: int = 30
    # Max absolute mitigation (floor on how much score can be reduced)
    cap_mitigation: int = 30


_CONFIG_KEYS = frozenset(f.name for f in fields(VerdictConfig))


def default_extra_verdict_path() -> Path:
    return app_dir() / _EXTRA_NAME


def resolve_verdict_path(explicit: str | Path | None = None) -> Path | None:
    """Explicit path wins; otherwise ``verdict_extra.json`` next to app if present."""
    if explicit is not None and str(explicit).strip():
        return Path(str(explicit).strip())
    candidate = default_extra_verdict_path()
    return candidate if candidate.is_file() else None


def parse_verdict_overrides(data: dict) -> dict[str, int]:
    """Keep only known VerdictConfig int fields from a JSON object."""
    out: dict[str, int] = {}
    for key, raw in data.items():
        if key.startswith("_") or key not in _CONFIG_KEYS:
            continue
        try:
            out[key] = int(raw)
        except (TypeError, ValueError):
            continue
    return out


def validate_verdict_extra(data: dict) -> list[str]:
    """Lightweight schema check for ``verdict_extra.json`` (no external jsonschema).

    Returns human-readable warnings; empty list means OK. Unknown keys under
    ``_`` prefix are ignored (comments). Integer fields must be in a sane range.
    """
    warnings: list[str] = []
    if not isinstance(data, dict):
        return ["корень должен быть объектом JSON"]
    for key, raw in data.items():
        if key.startswith("_"):
            continue
        if key not in _CONFIG_KEYS:
            warnings.append(f"неизвестный ключ: {key}")
            continue
        try:
            val = int(raw)
        except (TypeError, ValueError):
            warnings.append(f"{key}: ожидалось целое, получено {raw!r}")
            continue
        if key.startswith("threshold_"):
            if not 0 <= val <= 100:
                warnings.append(f"{key}: порог вне 0..100 ({val})")
        elif key.startswith("cap_"):
            if not 0 <= val <= 100:
                warnings.append(f"{key}: cap вне 0..100 ({val})")
        elif key.startswith("weight_"):
            if not -50 <= val <= 100:
                warnings.append(f"{key}: вес вне −50..100 ({val})")
    return warnings


def load_verdict_overrides(path: str | Path | None) -> dict[str, int]:
    if path is None:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    # Soft-validate; ignore bad keys via parse_verdict_overrides
    _ = validate_verdict_extra(raw)
    return parse_verdict_overrides(raw)


def load_verdict_config(path: str | Path | None = None) -> VerdictConfig:
    """Built-in weights merged with optional JSON override file."""
    cfg = VerdictConfig()
    resolved = resolve_verdict_path(path)
    overrides = load_verdict_overrides(resolved)
    if overrides:
        base = asdict(cfg)
        base.update(overrides)
        return VerdictConfig(**base)
    return cfg


def default_verdict_config() -> VerdictConfig:
    return load_verdict_config()


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
        "shortcut_lnk",
        "onenote_attachment",
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
            if "iso_image" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_attachment_iso,
                        f"ISO/IMG-образ «{att.filename}»",
                    )
                )
                rest.discard("iso_image")
                rest.discard("dangerous_extension")
            if "shortcut_lnk" in rest:
                parts.append(
                    ScoreContribution(
                        "attachments",
                        cfg.weight_attachment_lnk,
                        f"Ярлык LNK «{att.filename}»",
                    )
                )
                rest.discard("shortcut_lnk")
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
            if rest:
                pts = cfg.weight_attachment_flag * min(2, len(rest))
                parts.append(
                    ScoreContribution(
                        "attachments",
                        pts,
                        f"Вложение «{att.filename}»: {', '.join(sorted(rest))}",
                    )
                )
        elif (
            not soft_noted
            and ("archive" in att.risk_flags or "office_macro_capable" in att.risk_flags)
        ):
            soft_noted = True
            parts.append(
                ScoreContribution(
                    "attachments",
                    cfg.weight_attachment_soft,
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
    signals = analyze_content_signals(
        result.raw_text_preview,
        result.html_preview,
        has_qr=has_qr,
        has_urls=has_urls,
        has_attachments=has_att,
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
        pts = cfg.weight_idn if hit.kind == "idn" else cfg.weight_lookalike
        parts.append(ScoreContribution("lookalike", pts, hit.detail))
        if len(parts) >= 3:
            break
    return _apply_cap(parts, cfg.cap_lookalike, "lookalike")


_INTERNAL_RELAY_RE = re.compile(
    r"(?i)\b("
    r"mail\.internal|intranet|"
    r"outlook\.office365\.com|mail\.protection\.outlook\.com|"
    r"protection\.outlook\.com|mail\.google\.com|googlemail\.com"
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
    result: AnalysisResult, cfg: VerdictConfig
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
        "onenote_attachment",
    }
    has_high_att = any(high_att.intersection(a.risk_flags) for a in result.attachments)
    bad_content = {
        "href_mismatch",
        "credential_harvest",
        "bec_payment",
        "qr_only",
        "hidden_text",
    }
    has_bad_content = bool(bad_content.intersection(result.content_signals or []))

    parts: list[ScoreContribution] = []

    # Benign operational markers — apply unless clear attack surface
    if not has_high_att and not has_bad_content:
        parts.extend(_benign_marker_parts(result, cfg))

    if mid is None:
        return _apply_mitigation_floor(parts, cfg.cap_mitigation) if parts else (0, [])

    if has_high_att or has_bad_content:
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
    return parts


def render_verdict(
    result: AnalysisResult,
    cfg: VerdictConfig | None = None,
    *,
    brands_path: str | Path | None = None,
) -> Verdict | None:
    """Mail triage score — primary output for email artifacts."""
    if result.source_kind != "email":
        return None

    cfg = cfg or load_verdict_config()
    breakdown: list[ScoreContribution] = []
    score = 0

    for scorer in (
        lambda r, c: _score_headers(r, c),
        lambda r, c: _score_attachments(r, c),
        lambda r, c: _score_urls(r, c),
        lambda r, c: _score_content(r, c),
        lambda r, c: _score_lookalike(r, c, brands_path=brands_path),
        lambda r, c: _score_mitigations(r, c),
    ):
        part, parts = scorer(result, cfg)
        score += part
        breakdown.extend(parts)

    reasons = [b.reason for b in breakdown if b.points != 0]
    seen: set[str] = set()
    uniq_reasons: list[str] = []
    for r in reasons:
        # Strip [cap] marker for display reasons dedupe key
        key = r.replace(" [cap]", "")
        if key not in seen:
            seen.add(key)
            uniq_reasons.append(key)

    score = min(100, max(0, score))
    if score >= cfg.threshold_malicious:
        level = VerdictLevel.MALICIOUS
        summary = "Высокая вероятность вредоносной активности / фишинга"
    elif score >= cfg.threshold_suspicious:
        level = VerdictLevel.SUSPICIOUS
        summary = "Подозрительные признаки — требуется углублённый разбор"
    elif score >= cfg.threshold_unknown:
        level = VerdictLevel.UNKNOWN
        summary = "Слабые сигналы — вердикт неоднозначен"
    else:
        level = VerdictLevel.BENIGN
        summary = "Существенных индикаторов компрометации не выявлено"

    if not uniq_reasons:
        uniq_reasons.append("Эвристики не сработали на явные red flags")

    return Verdict(
        level=level,
        score=score,
        summary=summary,
        reasons=uniq_reasons[:12],
        breakdown=breakdown,
    )
