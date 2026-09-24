"""Русские подписи уровней вердикта и UI-кодов."""

from __future__ import annotations

from reliquary.core.models import VerdictLevel

VERDICT_RU: dict[str, str] = {
    "benign": "безопасный",
    "unknown": "неясный",
    "suspicious": "подозрительный",
    "malicious": "вредоносный",
}

# Принимаем и коды, и русские названия при override
VERDICT_PARSE: dict[str, str] = {
    **{k: k for k in VERDICT_RU},
    **{v: k for k, v in VERDICT_RU.items()},
    "безопасно": "benign",
    "ок": "benign",
    "ok": "benign",
    "фишинг": "malicious",
    "malware": "malicious",
}


def verdict_label_ru(level: str | VerdictLevel | None) -> str:
    if level is None:
        return "—"
    key = level.value if isinstance(level, VerdictLevel) else str(level).strip().lower()
    return VERDICT_RU.get(key, key)


# Short words used on the Russian verdict card (same set as the analyst runbook).
VERDICT_CARD_RU: dict[str, str] = {
    "benign": "безопасно",
    "unknown": "неясно",
    "suspicious": "подозрительно",
    "malicious": "вредоносно",
}

CONFIDENCE_RU: dict[str, str] = {
    "high": "высокая",
    "medium": "средняя",
    "low": "низкая",
}


def verdict_card_label(level: str | VerdictLevel | None) -> str:
    if level is None:
        return "—"
    key = level.value if isinstance(level, VerdictLevel) else str(level).strip().lower()
    return VERDICT_CARD_RU.get(key, verdict_label_ru(key))


def confidence_label_ru(confidence: str | None) -> str:
    key = (confidence or "").strip().lower()
    return CONFIDENCE_RU.get(key, key)


def parse_verdict_level(text: str) -> VerdictLevel | None:
    raw = (text or "").strip().lower()
    code = VERDICT_PARSE.get(raw)
    if not code:
        return None
    try:
        return VerdictLevel(code)
    except ValueError:
        return None
