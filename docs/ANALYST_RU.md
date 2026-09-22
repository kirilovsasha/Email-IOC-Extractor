# Analyst runbook (RU) — Email IOC Extractor

Офлайн triage писем `.eml` / `.msg` / `.mbox` / `.pst`. Сеть не используется.
Деплой: **1 EXE** + опциональные конфиги рядом. Без базы данных.

## Быстрый цикл

1. Откройте письмо / папку / вставьте RFC822 (Ctrl+Enter).
2. Вкладка **Вердикт** — уровень, score, уверенность, разбор весов.
3. При шуме: фильтры «к разбору», SafeLinks, allowlist.
4. ПКМ по IOC → **В allowlist** или **Override вердикта**.
5. Тикет (Ctrl+H) / JSON / CSV / Batch CSV (Ctrl+E). В GUI других форматов нет.
6. Пакет: таблица файлов; Ctrl+N/P — следующее письмо; peers → diff кампании.
7. Ctrl+Shift+V — компактный режим (только вердикт, без панели исходника).
8. Ctrl+R — копировать причины вердикта; вкладка «Ошибки» → [L] каталог журнала.
9. ПКМ → Feedback FP/FN; пароль архива и переразбор.
10. Настройки → импорт org_profile; YARA (extra) — правила `yara_rules/` рядом с EXE авто.
11. Feedback FP/FN → `--feedback-weights` (±2 к весам) / `--feedback-tune` (веса + пороги/caps).
12. `.pst` — MVP: нужен `pip install .[pst]` (libratom) или pypff; иначе RU-пропуск без краша.

## Пороги вердикта

| Уровень | Score |
|---------|-------|
| безопасный (benign) | 0–9 |
| неясный (unknown) | 10–29 |
| подозрительный (suspicious) | 30–59 |
| вредоносный (malicious) | ≥ 60 |

Тюнинг весов/caps: `verdict_extra.json` + [`docs/TUNING.md`](TUNING.md).

## Горячие клавиши

| Клавиши | Действие |
|---------|----------|
| Ctrl+O | Открыть письмо |
| Ctrl+Enter | Разбор текста слева |
| Ctrl+H | Тикет (handoff) |
| Ctrl+E | Экспорт (JSON / CSV / Batch CSV / Тикет) |
| Ctrl+R | Копировать причины вердикта |
| Ctrl+C / Ctrl+Shift+C | IOC / defanged |
| Ctrl+Shift+V | Компактный вердикт |
| Ctrl+N / Ctrl+P | Следующее / предыдущее в пакете |
| Ctrl+Shift+N / Ctrl+Shift+P | Следующее / предыдущее suspicious или malicious |
| Ctrl+L | Тема |
| Ctrl+D | Плотность IOC |
| Ctrl+F | Поиск IOC |
| 1–6 | Вкладки |

## Encrypted archive

Если вложение с паролем — содержимое не извлекается. ПКМ → «Заметка: шифрованный архив» для ITSM. Пароль запрашивайте out-of-band; не открывайте на рабочей станции без песочницы.

## Экспорт

**GUI (выпадающий список):** JSON · CSV · Batch CSV · Тикет.

**CLI SIEM / кампания** (в GUI нет; для пайплайнов):

- `--ecs` — Elastic Common Schema JSON
- `--cef` — ArcSight CEF
- `--stix` — STIX 2.1 lite bundle
- `--misp` — attribute CSV
- `--opencti` — observables JSON lite
- `--campaign-handoff` / `--campaign-pack` — пакет по campaign_key

UI только на русском. Вердикт: безопасный / неясный / подозрительный / вредоносный.

## Конфиги рядом с EXE

- `allowlist_extra.txt`, `verdict_extra.json`, `org_profile/` или **`org_profile.zip`**
- пресеты: `m365` / `google` / `banking` / `ru_gov` / `by_gov` / `kz_gov` / `ua_gov` / …
- `ui_prefs.json` — prefs (`verdict_compact`, `high_contrast`, hook…)
- `update.json` — локальный манифест (без сети): `latest` / `sha256` / `notes`
- «Настройки» в GUI — пути allowlist/verdict/profile, workers, post-export hook + JSON sidecar
- схема весов: `docs/verdict_extra.schema.json`
- при старте: self-check (EXE + QR) + предупреждения `verdict_extra`

См. также `docs/TUNING.md`, `SECURITY.md`, `docs/SIGNING.md`.
