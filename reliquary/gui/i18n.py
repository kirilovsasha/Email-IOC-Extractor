"""Minimal UI string catalog (RU / EN) for analyst chrome."""

from __future__ import annotations

from typing import Any

_STRINGS: dict[str, dict[str, str]] = {
    "ru": {
        "tab_verdict": "Вердикт",
        "tab_ioc": "IOC",
        "tab_att": "Вложения",
        "tab_url": "URL",
        "tab_batch": "Пакет",
        "tab_err": "Ошибки",
        "btn_open": "Открыть",
        "btn_folder": "Папка",
        "btn_cancel": "Стоп",
        "btn_export": "Экспорт",
        "btn_handoff": "Handoff",
        "btn_allowlist": "В allowlist",
        "btn_override": "Override вердикта",
        "btn_copy_enc_note": "Заметка: encrypted archive",
        "status_ready": "Готово",
        "status_analyzing": "Разбор…",
        "status_cancelled": "Отменено",
        "batch_need_two": "Нужно ≥2 файла для пакетной таблицы",
        "batch_diff": "diff vs peer",
        "about_title": "О программе",
        "lang_toggle": "EN",
        "high_contrast": "Контраст",
        "update_available": "Доступна новая версия (локальный манифест)",
        "update_ok": "Версия актуальна (манифест)",
    },
    "en": {
        "tab_verdict": "Verdict",
        "tab_ioc": "IOC",
        "tab_att": "Attachments",
        "tab_url": "URL",
        "tab_batch": "Batch",
        "tab_err": "Errors",
        "btn_open": "Open",
        "btn_folder": "Folder",
        "btn_cancel": "Stop",
        "btn_export": "Export",
        "btn_handoff": "Handoff",
        "btn_allowlist": "Allowlist",
        "btn_override": "Override verdict",
        "btn_copy_enc_note": "Note: encrypted archive",
        "status_ready": "Ready",
        "status_analyzing": "Analyzing…",
        "status_cancelled": "Cancelled",
        "batch_need_two": "Need ≥2 files for the batch table",
        "batch_diff": "diff vs peer",
        "about_title": "About",
        "lang_toggle": "RU",
        "high_contrast": "Contrast",
        "update_available": "Newer version flagged (local manifest)",
        "update_ok": "Version current (manifest)",
    },
}

_current = "ru"


def set_ui_lang(lang: str) -> None:
    global _current
    low = (lang or "ru").strip().lower()
    _current = "en" if low.startswith("en") else "ru"


def get_ui_lang() -> str:
    return _current


def t(key: str, **kwargs: Any) -> str:
    table = _STRINGS.get(_current) or _STRINGS["ru"]
    text = table.get(key) or _STRINGS["ru"].get(key) or key
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, ValueError):
            return text
    return text
