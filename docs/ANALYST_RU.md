# Analyst runbook (RU) — Email IOC Extractor

Офлайн triage писем `.eml` / `.msg`. Сеть не используется.

## Быстрый цикл

1. Откройте письмо / папку / вставьте RFC822 (Ctrl+Enter).
2. Вкладка **Вердикт** — уровень, score, разбор весов.
3. При шуме: фильтры «к разбору», SafeLinks, allowlist.
4. ПКМ по IOC → **В allowlist** или **Override вердикта**.
5. Handoff (Ctrl+H) / JSON / CSV / Batch CSV (Ctrl+E).
6. Пакет: таблица файлов; двойной клик при peers → diff кампании.

## Горячие клавиши

| Клавиши | Действие |
|---------|----------|
| Ctrl+O | Открыть письмо |
| Ctrl+Enter | Разбор текста слева |
| Ctrl+H | Handoff |
| Ctrl+E | Экспорт |
| Ctrl+L | Тема |
| Ctrl+D | Плотность IOC |
| Ctrl+F | Поиск IOC |
| 1–6 | Вкладки |

## Encrypted archive

Если вложение с паролем — содержимое не извлекается. ПКМ → «Заметка: encrypted archive» для ITSM. Пароль запрашивайте out-of-band; не открывайте на рабочей станции без песочницы.

## Overrides рядом с EXE

- `allowlist_extra.txt`, `verdict_extra.json`, `org_profile/`
- `ui_prefs.json` — prefs (язык `ui_lang`, контраст `high_contrast`, hook…)
- `update.json` — локальный манифест версии (без сети): `{"latest":"2.6.0"}`

См. также `docs/TUNING.md`, `SECURITY.md`, `docs/SIGNING.md`.
