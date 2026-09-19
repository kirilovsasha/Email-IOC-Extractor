# Email IOC Extractor

**Mail. Extract. Decide.** · v2.3.0

Офлайн-приложение для triage электронных писем (`.eml` / `.msg`):
заголовки, вложения, URL rewrite, IOC как доказательства и **вердикт** фишинга/вредоносности.

Экспорт: JSON, CSV, Batch CSV (по письмам), Handoff (текст для тикета).

## Быстрый старт (Windows)

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

run_gui.bat
```

Для тестов и сборки EXE: `pip install -r requirements-dev.txt`

CLI:

```bash
reliquary mail.eml
reliquary mail.eml --csv out.csv
reliquary mail.eml --handoff ticket.txt
reliquary ./inbox --json report.json --batch-csv triage.csv --workers 4
reliquary mail.eml --allowlist allowlist_extra.txt
reliquary mail.eml --verdict verdict_extra.json
reliquary mail.eml --full-ioc-types
reliquary mail.eml --handoff-template handoff_extra.txt --handoff out.txt
reliquary mail.eml --profile org_profile/
```

Фильтры CLI по умолчанию **как в GUI** (шум скрыт, «к разбору» включён, legacy IOC скрыты).
Снять: `--no-actionable`, `--no-hide-rewriter`, …, `--full-ioc-types`.

При ошибке запуска смотрите `email_ioc_extractor_error.log` рядом с bat/exe.

## Analyst runbook

1. Откройте письмо (`.eml` / `.msg`), папку или вставьте RFC822.
2. Смотрите **Вердикт** (score / причины / действия).
3. При необходимости ослабьте фильтры («к разбору», SafeLinks, allowlist) или включите **все типы**.
4. Скопируйте **Handoff** в тикет или экспортируйте JSON / CSV / Batch CSV.
5. Для пакета — вкладка **Пакет**: файл · вердикт · score · top reason.

## GUI

| Шаг | Действие |
|-----|----------|
| Письмо | `.eml` / `.msg` / папка / RFC822 / drag-drop |
| Вердикт | score · причины · действия |
| Доказательства | вложения · URL rewrite · IOC |
| Буфер | Msg-ID · **Handoff** (тикет) · копирование IOC |
| Экспорт | JSON / CSV / Batch CSV / Handoff |

Фильтры по умолчанию: SafeLinks / известный CDN-шум / локальные IP скрыты, «к разбору» включён,
крипто и host-legacy (registry/mutex/…) скрыты.

## Allowlist / verdict / handoff overrides

Локальные файлы рядом с exe/проектом (без пересборки):

| Файл | Назначение |
|------|------------|
| `allowlist_extra.txt` | доп. домены/IP (см. `allowlist_extra.example.txt`) |
| `verdict_extra.json` | веса/пороги вердикта (см. `verdict_extra.example.json`) |
| `handoff_extra.txt` | шаблон ITSM с `{verdict}` `{score}` `{msg_id}` … (см. `handoff_extra.example.txt`) |
| `handoff_{level}.txt` | шаблон по вердикту (`malicious` / `suspicious` / …) |
| `org_profile/` или `.zip` | пакет: allowlist + verdict + handoff + `brands.txt` |

Также: CLI `--allowlist` / `--verdict` / `--handoff-template` / `--profile`, prefs в `ui_prefs.json`.

Горячие клавиши GUI: `Ctrl+O` открыть · `Ctrl+H` handoff · `Ctrl+E` экспорт · `Ctrl+L` тема · `Ctrl+D` плотность IOC.

## Что анализируется

Только письма. Внутри письма разбираются вложения (Office, ZIP/7z/RAR*, nested `.eml`/`.msg`, OLE/macros, QR*).

\* RAR и QR — optional extras (`pip install '.[rar]'` / `'.[qr]'`); lite EXE их не включает.

| Сигнал | Примеры |
|--------|---------|
| Заголовки | SPF/DKIM/DMARC, spoofing, цепочка Received |
| Тело | urgency / social engineering, URL (в т.ч. SafeLinks unwrap) |
| Вложения | double ext, macros, encrypted archives, nested mail |
| IOC | IP, домены, URL, хеши вложений — как evidence |

Веса вердикта встроены в код (`verdict.py`), override — JSON выше.

Golden-корпус: `samples/corpus/` + `expected.json` (см. README там).

## Сборка EXE

```bash
pip install -r requirements-dev.txt
python build/sync_version_info.py
pyinstaller build/reliquary.spec
```

или `bash build/build.sh`.

`dist/EmailIOCExtractor.exe` — без консоли, без UPX. Лог — `email_ioc_extractor_error.log`.
Подпись: `build/sign_exe.ps1`. Версия берётся из `reliquary/__init__.py` → `version_info.txt`.

## Структура

```
reliquary/
  core/     # pipeline, verdict, IOC, export, handoff, allowlist
  gui/      # app + analysis/clipboard mixins, result_panels, ioc_table
samples/    # phishing_sample.eml, corpus/, nested_mail_sample.zip
tests/
```

Python-пакет по-прежнему называется `reliquary` (импорты / CLI). Пользовательское имя продукта — **Email IOC Extractor**.

## Лицензия

Внутренний инструмент SOC.
