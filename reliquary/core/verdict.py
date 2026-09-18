"""Optional phishing / mail-triage heuristics (fully offline).

Only applied to email artifacts (.eml / .msg). IOC extraction remains primary.
"""

from __future__ import annotations

import re

from reliquary.core.models import (
    ActionRecommendation,
    AnalysisResult,
    Severity,
    Verdict,
    VerdictLevel,
)

URGENCY_RE = re.compile(
    r"(?i)\b("
    r"urgent|immediately|verify your account|password.{0,10}expir|"
    r"confirm your identity|suspend|locked|invoice attached|"
    r"срочно|немедленно|подтвердите|пароль.{0,15}истек|"
    r"заблокир|счёт|счет|оплатите|выписка|безопасность аккаунта"
    r")\b"
)


def _score_headers(result: AnalysisResult) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    for h in result.headers:
        if h.severity == Severity.CRITICAL:
            score += 35
            reasons.append(h.note or h.name)
        elif h.severity == Severity.HIGH:
            score += 25
            reasons.append(h.note or h.name)
        elif h.severity == Severity.MEDIUM:
            score += 12
            reasons.append(h.note or h.name)
        elif h.severity == Severity.LOW:
            score += 4
    return score, reasons


def _score_attachments(result: AnalysisResult) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    high_flags = {
        "double_extension",
        "dangerous_extension",
        "ole_macros_suspected",
        "ooxml_vba",
        "mime_mismatch",
        "macro_enabled_office",
    }
    for att in result.attachments:
        hit = high_flags.intersection(att.risk_flags)
        if hit:
            score += 20 * len(hit)
            reasons.append(f"Вложение «{att.filename}»: {', '.join(sorted(hit))}")
        elif "archive" in att.risk_flags or "office_macro_capable" in att.risk_flags:
            score += 8
            reasons.append(f"Вложение «{att.filename}» требует ручной проверки")
    return score, reasons


def _score_urls(result: AnalysisResult) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if any(u.changed for u in result.url_rewrites):
        score += 5
        reasons.append("Обнаружены URL rewrite (SafeLinks/Proofpoint/…) — развёрнуты локально")

    ip_urls = [
        i for i in result.iocs if i.ioc_type.value == "url" and re.search(r"https?://\d+\.\d+\.\d+\.\d+", i.value)
    ]
    if ip_urls:
        score += 18
        reasons.append("URL ведёт на сырой IP-адрес")

    suspicious_tlds = (".xyz", ".top", ".club", ".gq", ".tk", ".ml", ".cf", ".ga", ".zip", ".mov")
    for ioc in result.iocs:
        if ioc.ioc_type.value in ("domain", "url"):
            val = ioc.value.lower()
            if any(val.endswith(tld) or f"{tld}/" in val for tld in suspicious_tlds):
                score += 10
                reasons.append(f"Подозрительная зона в индикаторе: {ioc.value}")
                break
    return score, reasons


def _score_content(result: AnalysisResult) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    blob = f"{result.subject}\n{result.raw_text_preview}"
    if URGENCY_RE.search(blob):
        score += 15
        reasons.append("В теме/тексте маркеры срочности / social engineering")

    # External sender + links + attachment combo
    has_urls = any(i.ioc_type.value == "url" for i in result.iocs)
    has_att = bool(result.attachments)
    if has_urls and has_att and result.source_kind == "email":
        score += 10
        reasons.append("Письмо содержит и ссылки, и вложения")
    return score, reasons


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
                "Сохранить Authentication-Results и цепочку Received в тикет; эскалация на email security",
            )
        )

    if result.url_rewrites:
        actions.append(
            ActionRecommendation(
                6,
                "Использовать развёрнутые URL",
                "В детектах и блокировках применять unwrapped URL, а не обёртку SafeLinks/Proofpoint",
            )
        )

    actions.append(
        ActionRecommendation(
            7,
            "Экспортировать STIX/CSV",
            "Выгрузить индикаторы в STIX 2.1 или CSV для передачи в TIP / соседние смены",
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
                "Экспортируйте CSV для аудита triage",
            ),
        ]

    actions.sort(key=lambda a: a.priority)
    return actions


def render_verdict(result: AnalysisResult) -> Verdict | None:
    """Phishing / mail triage score — only for email artifacts."""
    if result.source_kind != "email":
        return None

    score = 0
    reasons: list[str] = []

    for scorer in (_score_headers, _score_attachments, _score_urls, _score_content):
        part, part_reasons = scorer(result)
        score += part
        reasons.extend(part_reasons)

    # Deduplicate reasons preserving order
    seen: set[str] = set()
    uniq_reasons: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            uniq_reasons.append(r)

    score = min(100, score)
    if score >= 60:
        level = VerdictLevel.MALICIOUS
        summary = "Высокая вероятность вредоносной активности / фишинга"
    elif score >= 30:
        level = VerdictLevel.SUSPICIOUS
        summary = "Подозрительные признаки — требуется углублённый разбор"
    elif score >= 10:
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
    )
    verdict.actions = build_actions(level, result)
    return verdict
