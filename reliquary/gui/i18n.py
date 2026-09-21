"""Каталог строк UI (только русский)."""

from __future__ import annotations

from typing import Any

_STRINGS: dict[str, str] = {
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
    "btn_copy_enc_note": "Заметка: шифрованный архив",
    "status_ready": "Готово",
    "status_analyzing": "Разбор…",
    "status_cancelled": "Отменено",
    "batch_need_two": "Нужно ≥2 файла для пакетной таблицы",
    "batch_diff": "diff vs peer",
    "about_title": "О программе",
    "high_contrast": "Контраст",
    "update_available": "Доступна новая версия (локальный манифест)",
    "update_ok": "Версия актуальна (манифест)",
}


def t(key: str, **kwargs: Any) -> str:
    text = _STRINGS.get(key) or key
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, ValueError):
            return text
    return text
