# Email IOC Extractor

**Mail. Extract. Decide.** · v2.3.0

🔒 Офлайн-инструмент SOC для triage электронных писем (`.eml` / `.msg`):
заголовки, вложения, URL rewrite, IOC как доказательства и **вердикт**
(benign / unknown / suspicious / malicious) со score, разбором весов и рекомендуемыми действиями.

📡 Сеть не используется. Пакет Python — `reliquary`; пользовательское имя — **Email IOC Extractor**.

📦 Экспорт: JSON · CSV · Batch CSV · Handoff (текст для ITSM).

| 🖥️ GUI | ⌨️ CLI | 📁 Batch | 🎫 Handoff | 🧩 Org profile |

---

## 🚀 Быстрый старт (Windows)

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

run_gui.bat
```

🧪 Тесты и сборка EXE: `pip install -r requirements-dev.txt`

Опционально:

```bash
pip install -e ".[rar]"   # RAR-архивы во вложениях
pip install -e ".[qr]"    # QR в изображениях/архивах
```

⚠️ При ошибке GUI смотрите `email_ioc_extractor_error.log` рядом с bat/exe.

---

## 📋 Analyst runbook

1. 📧 Откройте письмо (`.eml` / `.msg`), папку или вставьте RFC822 (слева / Ctrl+Enter).
2. ⚖️ Смотрите вкладку **Вердикт**: уровень, score, **разбор score** (+N по категориям), действия.
3. 🔎 При необходимости ослабьте фильтры («к разбору», SafeLinks, allowlist) или включите **все типы** IOC.
4. 🎫 Скопируйте **Handoff** (Ctrl+H) в тикет или экспортируйте JSON / CSV / Batch CSV (Ctrl+E).
5. 📁 Пакет писем → вкладка **Пакет**: файл · вердикт · score · top reason · связанные кампании.

---

## 🖥️ GUI

| | Область | Содержание |
|---|---------|------------|
| 📧 | Письмо | `.eml` / `.msg` / папка / RFC822 / drag-drop |
| ⚖️ | Вердикт | score · разбор весов · причины · действия |
| 📎 | Доказательства | вложения · URL rewrite · IOC-таблица |
| 📁 | Пакет | сводка по файлам + группировка кампаний |
| 📋 | Буфер | Msg-ID · Handoff · копирование IOC |
| 💾 | Экспорт | JSON / CSV / Batch CSV / Handoff |

**Фильтры по умолчанию:** SafeLinks / CDN-шум / локальные IP скрыты; «к разбору» включён;
крипто и legacy host-IOC (registry / mutex / …) скрыты.

### ⌨️ Горячие клавиши

| Клавиши | Действие |
|---------|----------|
| Ctrl+O | 📂 Открыть письмо |
| Ctrl+Enter | ▶ Разбор RFC822 из левой панели |
| Ctrl+H | 🎫 Копировать Handoff |
| Ctrl+E | 💾 Экспорт (выбранный формат) |
| Ctrl+L | 🌓 Тема light / dark |
| Ctrl+D | 📏 Плотность IOC (compact / normal / comfortable) |
| Ctrl± | 🔍 Масштаб UI |
| 1–6 | 📑 Вкладки (Вердикт … Ошибки) |
| Ctrl+F | 🔎 Поиск по IOC |

Prefs сохраняются в `ui_prefs.json` рядом с приложением.

---

## ⌨️ CLI

```bash
# одно письмо — вердикт в stderr, краткий JSON в stdout
reliquary mail.eml

# экспорт
reliquary mail.eml --csv out.csv
reliquary mail.eml --handoff ticket.txt
reliquary mail.eml --json report.json

# папка / пакет
reliquary ./inbox --json report.json --batch-csv triage.csv --workers 4

# overrides / org profile
reliquary mail.eml --allowlist allowlist_extra.txt
reliquary mail.eml --verdict verdict_extra.json
reliquary mail.eml --handoff-template handoff_extra.txt --handoff out.txt
reliquary mail.eml --profile org_profile/
reliquary mail.eml --profile org_pack.zip

# IOC
reliquary mail.eml --full-ioc-types
reliquary mail.eml --no-actionable --no-hide-rewriter
```

Фильтры CLI по умолчанию совпадают с GUI. Снять: `--no-actionable`, `--no-hide-rewriter`, …
Полный отчёт в stdout: `--stdout-json`. Только IOC-массив: `--iocs-only`.

---

## 🔬 Что анализируется

Корневой вход — **только письма** (`.eml` / `.msg`).
Внутри письма разбираются вложения: Office, ZIP / 7z / RAR\*, nested `.eml` / `.msg`, OLE / macros, QR\*.

\* RAR и QR — optional extras; lite EXE их не включает.

| | Сигнал | Примеры |
|---|--------|---------|
| 📨 | Заголовки | SPF / DKIM / DMARC (fail vs softfail), alignment, ARC, Reply-To / Return-Path mismatch, display-name spoof, Received |
| 📝 | Тело | urgency / social engineering, credential / OWA login, href≠видимый текст, скрытый HTML, формы |
| 🔗 | URL | SafeLinks / Proofpoint / Barracuda / Mimecast / … unwrap (офлайн) |
| 🎭 | Lookalike | IDN / punycode, homoglyph, Levenshtein к брендам (`brands.txt`) |
| 📎 | Вложения | double ext, macros, encrypted archives, nested mail, QR-URL |
| 🎯 | IOC | IP, домены, URL, хеши вложений — как evidence для экспорта / handoff |

**Вердикт (score 0–100)** с caps по категориям (headers / attachments / urls / content / lookalike),
чтобы одинаковые флаги не раздували malicious. Пороги по умолчанию:

| | Уровень | Score |
|---|---------|-------|
| ✅ | benign | 0–9 |
| ❔ | unknown | 10–29 |
| ⚠️ | suspicious | 30–59 |
| 🛑 | malicious | ≥ 60 |

Веса встроены в `reliquary/core/verdict.py`; override — `verdict_extra.json`.

---

## 🧩 Overrides и org profile

Файлы рядом с exe / проектом (без пересборки) или через CLI / prefs:

| | Файл / путь | Назначение |
|---|-------------|------------|
| ✅ | `allowlist_extra.txt` | доп. домены / IP (см. `allowlist_extra.example.txt`) |
| ⚖️ | `verdict_extra.json` | веса, пороги, caps (см. `verdict_extra.example.json`) |
| 🎫 | `handoff_extra.txt` | шаблон ITSM по умолчанию |
| 🏷️ | `handoff_{level}.txt` | шаблон для `malicious` / `suspicious` / `unknown` / `benign` |
| 🏛️ | `brands.txt` | доп. бренды для lookalike |
| 📦 | `org_profile/` или `.zip` | пакет всего выше сразу |

CLI: `--allowlist` · `--verdict` · `--handoff-template` · `--profile`  
Prefs: `allowlist_path`, `verdict_path`, `handoff_template_path`, `profile_dir`, `brands_path`, …

Подробности пакета: [`org_profile.example/README.md`](org_profile.example/README.md).

### ✏️ Плейсхолдеры handoff

`{product}` `{version}` `{verdict}` `{score}` `{summary}` `{reasons}` `{breakdown}`  
`{file}` `{from}` `{subject}` `{msg_id}` `{auth}` `{iocs}` `{batch}`

Порядок выбора шаблона: явный путь → `handoff_{level}.txt` (profile / рядом с app) → `handoff_extra.txt` → встроенный блок.

В JSON-отчёте и meta: `app_version`, `overrides_loaded`, `profile_dir` — для аудита triage.

---

## 🧪 Корпус и тесты

Golden-корпус: `samples/corpus/` + `expected.json` (~15 писем: ✅ benign / ❔ unknown / ⚠️ suspicious / 🛑 malicious).

```bash
pip install -r requirements-dev.txt
pip install -e ".[dev]"

pytest -q
python scripts/corpus_metrics.py          # accuracy уровней + drift score
python scripts/gen_corpus.py              # пересобрать sample .eml (dev)
```

См. также `samples/corpus/README.md`.

---

## 🏗️ Сборка EXE

```bash
pip install -r requirements-dev.txt
python build/sync_version_info.py
pyinstaller build/reliquary.spec
```

или `bash build/build.sh`.

- 📦 Артефакт: `dist/EmailIOCExtractor.exe` (без консоли, без UPX)
- 🏷️ Версия: `reliquary/__init__.py` → `build/version_info.txt`
- ✍️ Подпись: `build/sign_exe.ps1`
- 📜 Лог runtime: `email_ioc_extractor_error.log`

CI (GitHub Actions): pytest на Windows + Ubuntu; на push в `main` — сборка EXE + smoke; на тег `v*` — GitHub Release с changelog.

---

## 📂 Структура репозитория

```
reliquary/
  core/     # pipeline, verdict, lookalike, content_signals, IOC, export,
            # handoff, allowlist, org_profile, analysis_options, batch
  gui/      # app + layout / analysis / clipboard / result_panels / ioc_table
samples/
  corpus/   # golden verdict EMLs + expected.json
tests/
scripts/    # gen_corpus.py, corpus_metrics.py
build/      # PyInstaller spec, version sync, sign
org_profile.example/
```

---

## 📄 Лицензия

Внутренний инструмент SOC.
