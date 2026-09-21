# Analyst runbook (RU) — Email IOC Extractor

Офлайн triage писем `.eml` / `.msg`. Сеть не используется.
Деплой: **1 EXE** + опциональные конфиги рядом. Без базы данных.

## Быстрый цикл

1. Откройте письмо / папку / вставьте RFC822 (Ctrl+Enter).
2. Вкладка **Вердикт** — уровень, score, разбор весов.
3. При шуме: фильтры «к разбору», SafeLinks, allowlist.
4. ПКМ по IOC → **В allowlist** или **Override вердикта**.
5. Тикет (Ctrl+H) / JSON / CSV / Batch CSV (Ctrl+E).
6. Пакет: таблица файлов; Ctrl+N/P — следующее письмо; peers → diff кампании.
7. Ctrl+Shift+V — компактный режим (только вердикт, без панели исходника).
8. **Калибр.** — отчёт FP/FN по папке inbox (без БД).
9. Ctrl+R — копировать причины вердикта; вкладка «Ошибки» → [L] каталог журнала.
10. ПКМ → Feedback FP/FN; пароль архива и переразбор; Watch / A/B в тулбаре.
11. Настройки → импорт org_profile; watch-inbox; YARA (extra).

## Горячие клавиши

| Клавиши | Действие |
|---------|----------|
| Ctrl+O | Открыть письмо |
| Ctrl+Enter | Разбор текста слева |
| Ctrl+H | Тикет (handoff) |
| Ctrl+E | Экспорт |
| Ctrl+Shift+V | Компактный вердикт |
| Ctrl+N / Ctrl+P | Следующее / предыдущее в пакете |
| Ctrl+L | Тема |
| Ctrl+D | Плотность IOC |
| Ctrl+F | Поиск IOC |
| 1–6 | Вкладки |

## Encrypted archive

Если вложение с паролем — содержимое не извлекается. ПКМ → «Заметка: шифрованный архив» для ITSM. Пароль запрашивайте out-of-band; не открывайте на рабочей станции без песочницы.

## Экспорт SIEM / TI

- **ECS** — JSON Elastic Common Schema
- **CEF** — ArcSight CEF (строки)
- **STIX** — STIX 2.1 lite bundle
- **MISP** — attribute CSV
- **OpenCTI** — observables JSON lite
- **Кампания** — пакетный handoff по campaign_key (`thread:` / Msg-ID)
- **Тикет** — текстовый блок для ITSM

CLI: `--ecs` / `--cef` / `--stix` / `--misp` / `--opencti` / `--campaign-handoff` / `--handoff`.

UI только на русском. Вердикт: безопасный / неясный / подозрительный / вредоносный.

## Конфиги рядом с EXE

- `allowlist_extra.txt`, `verdict_extra.json`, `org_profile/` или **`org_profile.zip`**
- `ui_prefs.json` — prefs (`verdict_compact`, `high_contrast`, hook…)
- `update.json` — локальный манифест (без сети): `latest` / `channel` lite|full / `sha256`
- «Настройки» в GUI — пути allowlist/verdict/profile, workers, post-export hook + JSON sidecar
- схема весов: `docs/verdict_extra.schema.json`
- при старте: self-check Lite/Full + наличиеждения `verdict_extra`

См. также `docs/TUNING.md`, `SECURITY.md`, `docs/SIGNING.md`.
