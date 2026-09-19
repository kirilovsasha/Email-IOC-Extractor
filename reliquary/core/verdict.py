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
    ActionRecommendation,
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
    weight_url_rewrite: int = 5
    weight_url_raw_ip: int = 18
    weight_suspicious_tld: int = 10
    weight_urgency: int = 15
    weight_links_and_attachments: int = 10
    weight_credential_harvest: int = 14
    weight_href_mismatch: int = 18
    weight_hidden_text: int = 10
    weight_html_form: int = 8
    weight_qr_only: int = 16
    weight_qr_present: int = 8
    weight_lookalike: int = 22
    weight_idn: int = 12
    # Per-category caps (evidence stacking without score explosion)
    cap_headers: int = 45
    cap_attachments: int = 40
    cap_urls: int = 30
    cap_content: int = 35
    cap_lookalike: int = 30


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
    }
    # Unique flags across all attachments (cap stacking)
    seen_flags: set[str] = set()
    soft_noted = False
    for att in result.attachments:
        hit = high_flags.intersection(att.risk_flags) - seen_flags
        if hit:
            seen_flags |= hit
            # Charge once per unique flag type, not per attachment×flag
            pts = cfg.weight_attachment_flag * min(2, len(hit))
            parts.append(
                ScoreContribution(
                    "attachments",
                    pts,
                    f"Вложение «{att.filename}»: {', '.join(sorted(hit))}",
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
        parts.append(
            ScoreContribution(
                "urls",
                cfg.weight_url_rewrite,
                "Обнаружены URL rewrite (SafeLinks/Proofpoint/…) — развёрнуты локально",
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


def build_actions(level: VerdictLevel, result: AnalysisResult) -> list[ActionRecommendation]:
    actions: list[ActionRecommendation] = []

    if level in (VerdictLevel.MALICIOUS, VerdictLevel.SUSPICIOUS):
        actions.append(
            ActionRecommendation(
                1,
                "Изолировать артефакты",
                "Не открывать вложения и ссылки на рабочей станции; работать в песочнице/VM",
            )
        )
        actions.append(
            ActionRecommendation(
                2,
                "Заблокировать IOC",
                "Добавить домены/URL/хеши/IP в EDR, почтовый шлюз и DNS sinkhole по процедуре SOC",
            )
        )
        actions.append(
            ActionRecommendation(
                3,
                "Проверить получателей",
                "Найти других адресатов того же письма/кампании в SIEM и почтовом журнале",
            )
        )

    if any(a.risk_flags for a in result.attachments):
        actions.append(
            ActionRecommendation(
                4,
                "Разобрать вложения",
                "Посчитать хеши уже извлечены — сверить с локальным TIP/MISP офлайн-выгрузкой; при macro/EXE — детонация в sandbox",
            )
        )

    if any(h.severity.value in ("high", "critical") for h in result.headers):
        actions.append(
            ActionRecommendation(
                5,
                "Зафиксировать spoofing",
                "Сохранить Authentication-Results и цепочку Received; эскалация на email security",
            )
        )

    if result.url_rewrites:
        actions.append(
            ActionRecommendation(
                6,
                "Использовать развёрнутые URL",
                "В детектах применять unwrapped URL, а не обёртку SafeLinks/Proofpoint",
            )
        )

    actions.append(
        ActionRecommendation(
            7,
            "Сохранить отчёт",
            "Экспортировать JSON или CSV с вердиктом и IOC",
        )
    )

    if level == VerdictLevel.BENIGN:
        actions = [
            ActionRecommendation(
                1,
                "Закрыть как FP / инфо",
                "Явных признаков компрометации не найдено — при сомнении оставьте на peer-review",
            ),
            ActionRecommendation(
                2,
                "Сохранить отчёт",
                "Экспортируйте JSON или CSV для аудита triage",
            ),
        ]

    actions.sort(key=lambda a: a.priority)
    return actions


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
    ):
        part, parts = scorer(result, cfg)
        score += part
        breakdown.extend(parts)

    reasons = [b.reason for b in breakdown if b.points > 0]
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

    verdict = Verdict(
        level=level,
        score=score,
        summary=summary,
        reasons=uniq_reasons[:12],
        actions=[],
        breakdown=breakdown,
    )
    verdict.actions = build_actions(level, result)
    return verdict
