# Email IOC Extractor

**Mail. Extract. Decide.** · v2.10.0

🔒 Офлайн-инструмент SOC для triage писем (`.eml` / `.msg`): заголовки, вложения,
URL rewrite, IOC как доказательства и **вердикт**
(`benign` / `unknown` / `suspicious` / `malicious`) со score и разбором весов
(включая mitigations).

📡 Сеть не используется. Пакет Python — `reliquary`; продукт — **Email IOC Extractor**.
Деплой: **один EXE** + опциональные конфиги рядом (без БД).

📦 Экспорт: JSON (`schema_version` **2**) · CSV · Batch CSV · Тикет · Кампания · ECS · CEF · STIX · MISP · OpenCTI.

| 🖥️ GUI | ⌨️ CLI | 📁 Batch | 🎫 Тикет | 🧩 Org profile | 🏗️ EXE |

---

## 🚀 Быстрый старт (Windows)

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .

run_gui.bat
```

Требуется **Python ≥ 3.10**. CLI без GUI:

```bash
reliquary mail.eml
# или
python -m reliquary.cli mail.eml
```

🧪 Тесты: `pip install -r requirements-dev.txt` → `pytest -q`  
🏗️ Сборка EXE: `build_exe.bat` (см. раздел «Сборка EXE» ниже).

Опциональные extras:

```bash
pip install -e ".[rar]"   # RAR во вложениях
pip install -e ".[qr]"    # QR в изображениях/архивах
pip install -e ".[rar,qr]"
```

### 📦 Lite vs Full

| Сборка | Что внутри |
|--------|------------|
| **Lite** — `EmailIOCExtractor.exe` из CI / GitHub Release / `build_exe.bat` | Базовый разбор; без rarfile / pyzbar |
| **Full** — `build_exe.bat --full` или source с extras | RAR inventory + QR decode |

В Release notes публикуется **SHA256** Lite EXE.

⚠️ При ошибке GUI смотрите `email_ioc_extractor_error.log` рядом с bat/exe.

---

## 📋 Analyst runbook

1. 📧 Откройте письмо (`.eml` / `.msg`), папку или вставьте RFC822 слева (Ctrl+Enter).
2. ⚖️ Вкладка **Вердикт**: уровень, score, **разбор** (`+N` risk / `−N` mitigation), причины.
3. 🔎 При шуме ослабьте фильтры («к разбору», SafeLinks, allowlist) или включите **все типы** IOC.
4. 🎫 **Тикет** (Ctrl+H) → буфер для ITSM; либо JSON / CSV / Batch CSV (Ctrl+E).
5. 📁 Пакет писем → вкладка **Пакет**: файл · вердикт · score · причина · кампании;
   Ctrl+N/P — следующее письмо; клик **`[diff vs peer]`** — сравнение с peer кампании.
6. Ctrl+Shift+V — компактный режим (только вердикт, без панели исходника).

---

## 🖥️ GUI

| | Область | Содержание |
|---|---------|------------|
| 📧 | Письмо | `.eml` / `.msg` / папка / RFC822 / drag-drop |
| ⚖️ | Вердикт | score · breakdown (+/−) · причины |
| 📎 | Доказательства | вложения · URL rewrite · IOC-таблица |
| 📁 | Пакет | сводка + кампании + diff peer |
| 📋 | Буфер | Msg-ID · Тикет · копирование IOC |
| 💾 | Экспорт | JSON / CSV / Batch CSV / Тикет |

**Фильтры по умолчанию:** SafeLinks / CDN / локальные IP скрыты; «к разбору» включён;
крипто и legacy host-IOC (registry / mutex / …) скрыты.

### ⌨️ Горячие клавиши

| Клавиши | Действие |
|---------|----------|
| Ctrl+O | 📂 Открыть письмо |
| Ctrl+Enter | ▶ Разбор RFC822 из левой панели |
| Ctrl+H | 🎫 Копировать тикет |
| Ctrl+E | 💾 Экспорт (выбранный формат) |
| Ctrl+Shift+V | 📐 Компактный вердикт |
| Ctrl+N / Ctrl+P | 📁 Следующее / предыдущее письмо пакета |
| Ctrl+L | 🌓 Тема light / dark |
| Ctrl+D | 📏 Плотность IOC (compact / normal / comfortable) |
| Ctrl± | 🔍 Масштаб UI |
| 1–6 | 📑 Вкладки результатов (Вердикт … Ошибки) |
| Ctrl+F | 🔎 Поиск по IOC |

Prefs: `ui_prefs.json` рядом с EXE
(`appearance_mode`, `ioc_density`, `verdict_compact`, пути overrides, …). Без БД.

---

## ⌨️ CLI

```bash
# одно письмо — вердикт в stderr, краткий JSON в stdout
reliquary mail.eml

# экспорт
reliquary mail.eml --csv out.csv
reliquary mail.eml --handoff ticket.txt
reliquary mail.eml --json report.json
reliquary mail.eml --ecs report.ecs.json
reliquary mail.eml --cef report.cef
reliquary mail.eml --stix report.stix.json
reliquary mail.eml --misp attrs.csv
reliquary mail.eml --opencti opencti.json
reliquary ./inbox --campaign-handoff campaign.txt

# папка / пакет
reliquary ./inbox --json report.json --batch-csv triage.csv --workers 4

# overrides / org profile
reliquary mail.eml --allowlist allowlist_extra.txt
reliquary mail.eml --verdict verdict_extra.json
reliquary mail.eml --handoff-template handoff_extra.txt --handoff out.txt
reliquary mail.eml --profile org_profile/
reliquary mail.eml --profile org_profile.example/m365
reliquary mail.eml --profile org_pack.zip

# IOC-фильтры (по умолчанию как в GUI)
reliquary mail.eml --full-ioc-types
reliquary mail.eml --no-actionable --no-hide-rewriter

# после экспорта — локальная команда; путь к файлу добавляется последним argv
reliquary mail.eml --json out.json --post-export-hook "python scripts/my_hook.py"
```

Снять фильтры: `--no-actionable`, `--no-hide-rewriter`, `--no-hide-allowlisted`, `--no-hide-private`.  
Полный отчёт в stdout: `--stdout-json`. Только IOC-массив: `--iocs-only`.

JSON содержит top-level **`schema_version`** (сейчас `2`) — см. [`docs/TUNING.md`](docs/TUNING.md)
и [`docs/schema_report_v2.json`](docs/schema_report_v2.json).

---

## 🔬 Что анализируется

Корневой вход — **только письма** (`.eml` / `.msg`).
Внутри письма: Office, ZIP / 7z / RAR\*, nested `.eml` / `.msg`, OLE / macros, QR\*.

\* RAR и QR — optional extras; Lite EXE их не включает.

| | Сигнал | Примеры |
|---|--------|---------|
| 📨 | Заголовки | SPF / DKIM / DMARC (fail vs softfail), alignment, ARC, Reply-To / Return-Path, display-name spoof, Received |
| 📝 | Тело | urgency / SE, credential / OWA, href≠label, скрытый HTML, формы |
| 🔗 | URL | SafeLinks / Proofpoint / Barracuda / Mimecast / … unwrap (офлайн) |
| 🎭 | Lookalike | IDN / punycode, homoglyph, Levenshtein к брендам (`brands.txt`) |
| 📎 | Вложения | double ext, macros, encrypted archives, nested mail, QR-URL |
| 🎯 | IOC | IP, домены, URL, хеши — evidence для экспорта / handoff |

### ⚖️ Вердикт (score 0–100)

Сумма вкладов по категориям с **caps** (headers / attachments / urls / content / lookalike)
и **mitigations** (отрицательные веса: DMARC+DKIM pass, trusted Received hop).
Mitigations не применяются при auth fail/softfail/none, HIGH-атаках в заголовках,
опасных вложениях или content signals (href mismatch, credential harvest, …).

| | Уровень | Score |
|---|---------|-------|
| ✅ | benign | 0–9 |
| ❔ | unknown | 10–29 |
| ⚠️ | suspicious | 30–59 |
| 🛑 | malicious | ≥ 60 |

Веса: `reliquary/core/verdict.py`. Override: `verdict_extra.json`
(схема: [`docs/verdict_extra.schema.json`](docs/verdict_extra.schema.json)).  
Калибровка FP/FN: [`docs/TUNING.md`](docs/TUNING.md).

---

## 🧩 Конфиги рядом с EXE (без БД)

Файлы рядом с exe / проектом (без пересборки) или через CLI / prefs:

| | Файл / путь | Назначение |
|---|-------------|------------|
| ✅ | `allowlist_extra.txt` | доп. домены / IP (`allowlist_extra.example.txt`) |
| ⚖️ | `verdict_extra.json` | веса, пороги, caps, mitigations (`verdict_extra.example.json`) |
| 🎫 | `handoff_extra.txt` | шаблон ITSM по умолчанию |
| 🏷️ | `handoff_{level}.txt` | шаблон для `malicious` / `suspicious` / `unknown` / `benign` |
| 🏛️ | `brands.txt` | бренды для lookalike |
| 📦 | `org_profile/` или `.zip` | пакет всего выше |

**Пресеты:** [`org_profile.example/m365`](org_profile.example/m365) ·
[`google`](org_profile.example/google) ·
[`banking`](org_profile.example/banking) ·
[`proxysg`](org_profile.example/proxysg) ·
[`kaspersky`](org_profile.example/kaspersky) ·
[`drweb`](org_profile.example/drweb) ·
[`local_mx`](org_profile.example/local_mx) —
см. [`org_profile.example/README.md`](org_profile.example/README.md).

CLI: `--allowlist` · `--verdict` · `--handoff-template` · `--profile` · `--post-export-hook`  
Prefs: `allowlist_path`, `verdict_path`, `handoff_template_path`, `profile_dir`, `brands_path`,
`post_export_hook`, `post_export_hook_allow_external`, `disable_post_export_hook`, …

### ✏️ Плейсхолдеры handoff

`{product}` `{version}` `{verdict}` `{score}` `{summary}` `{reasons}` `{breakdown}`  
`{file}` `{from}` `{subject}` `{msg_id}` `{auth}` `{iocs}` `{batch}`

Порядок шаблона: явный путь → `handoff_{level}.txt` (profile / app dir) → `handoff_extra.txt` → встроенный блок.

В JSON / meta: `schema_version`, `app_version`, `overrides_loaded`, `profile_dir`.

---

## 🧪 Корпус и тесты

Golden corpus: `samples/corpus/` + `expected.json` (**~46** писем по всем уровням).

```bash
pip install -r requirements-dev.txt
pip install -e ".[dev]"

pytest -q
python scripts/corpus_metrics.py                        # accuracy + drift
python scripts/corpus_metrics.py --inbox path/to/emls   # калибровка на локальном inbox
python scripts/gen_corpus.py                            # пересобрать sample .eml
python scripts/regen_expected.py                        # обновить expected.json (dev)
```

См. [`samples/corpus/README.md`](samples/corpus/README.md) и [`docs/TUNING.md`](docs/TUNING.md).

---

## 🏗️ Сборка EXE (Windows)

Один клик / из корня репозитория:

```bat
build_exe.bat
```

или напрямую:

```bat
build\build.bat
```

**Full** (RAR + QR extras перед упаковкой):

```bat
build_exe.bat --full
```

Скрипт сам:

1. Берёт `.venv\Scripts\python.exe`, если есть, иначе `python` из PATH  
2. Ставит `requirements.txt` + PyInstaller + пакет  
3. Синхронизирует `build\version_info.txt`  
4. Запускает PyInstaller (`build\reliquary.spec`)  
5. Пишет `dist\EmailIOCExtractor.exe.sha256`

Ручная сборка (эквивалент):

```bash
pip install -r requirements-dev.txt
python build/sync_version_info.py
python -m PyInstaller build/reliquary.spec --noconfirm
```

Linux/macOS: `bash build/build.sh`.

| | |
|--|--|
| 📦 Артефакт | `dist/EmailIOCExtractor.exe` (Lite, без консоли, без UPX) + `.sha256` |
| 🏷️ Версия | `reliquary/__init__.py` → `build/version_info.txt` + `pyproject.toml` |
| ✍️ Подпись | `build/sign_exe.ps1` / [`docs/SIGNING.md`](docs/SIGNING.md) (опционально) |
| 📜 Лог | `email_ioc_extractor_error.log` |
| 🧊 Smoke | `EmailIOCExtractor.exe --cli sample.eml --json out.json` |

CI: pytest Windows + Ubuntu, **Python 3.10–3.13**; push в `main` → EXE + frozen `--cli` smoke + SHA256;
тег `v*` → GitHub Release с changelog и хешем. История: [`CHANGELOG.md`](CHANGELOG.md).
Безопасность: [`SECURITY.md`](SECURITY.md). Схема JSON: [`docs/schema_report_v1.json`](docs/schema_report_v1.json).

---

## 📂 Структура репозитория

```
reliquary/
  core/     # pipeline, verdict (+ mitigations), lookalike, content_signals,
            # IOC, diff, export / export_hook, handoff, allowlist, org_profile, batch
  gui/      # app + mixins: layout, analysis, clipboard, result_panels,
            # hotkeys, prefs_actions, about, ioc_table
samples/corpus/          # golden EMLs + expected.json
org_profile.example/     # README + пресеты m365 / google / banking
docs/TUNING.md           # калибровка verdict_extra.json
tests/                   # corpus + доменные тесты
scripts/                 # gen_corpus, regen_expected, corpus_metrics
build/                   # build.bat, build.sh, PyInstaller, version sync, sign
build_exe.bat            # Windows: обёртка → build\build.bat
run_gui.bat              # Windows: запуск GUI
```

---

## 📄 Лицензия

Внутренний инструмент SOC — см. [`LICENSE`](LICENSE). Контрибут: [`CONTRIBUTING.md`](CONTRIBUTING.md).
