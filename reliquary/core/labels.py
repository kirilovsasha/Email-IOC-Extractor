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


def parse_verdict_level(text: str) -> VerdictLevel | None:
    raw = (text or "").strip().lower()
    code = VERDICT_PARSE.get(raw)
    if not code:
        return None
    try:
        return VerdictLevel(code)
    except ValueError:
        return None
