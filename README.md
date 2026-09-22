# Email IOC Extractor

**Mail. Extract. Decide.** · v2.14.1

🔒 Офлайн-инструмент SOC для triage писем (`.eml` / `.msg`): заголовки, вложения,
URL rewrite, IOC как доказательства и **вердикт**
(`benign` / `unknown` / `suspicious` / `malicious`) со score и разбором весов
(включая mitigations).

📡 Сеть не используется. Пакет Python — `reliquary`; продукт — **Email IOC Extractor**.
Деплой: **один EXE** + опциональные конфиги рядом (без БД).

📦 Экспорт: JSON (`schema_version` **2**) · CSV · Batch CSV · Тикет · Кампания · Campaign pack · ECS · CEF · STIX · MISP · OpenCTI.

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
| **Full** — `EmailIOCExtractor.exe` из CI / Release / `build_exe.bat` (по умолчанию) | RAR inventory + QR decode |
| **Lite** — `build_exe.bat --lite` / `EmailIOCExtractor-Lite.exe` | Базовый разбор; без rarfile / pyzbar |

В Release notes публикуется **SHA256** Full EXE (основной артефакт флота).

⚠️ При ошибке GUI смотрите `email_ioc_extractor_error.log` рядом с bat/exe.

---

## 📋 Analyst runbook

1. 📧 Откройте письмо (`.eml` / `.msg`), папку или вставьте RFC822 слева (Ctrl+Enter).
2. ⚖️ Вкладка **Вердикт**: уровень, score, **разбор** (`+N` risk / `−N` mitigation), причины.
3. 🔎 При шуме ослабьте фильтры («к разбору», SafeLinks, allowlist) или включите **все типы** IOC.
4. 🎫 **Тикет** (Ctrl+H) → буфер для ITSM; либо JSON / CSV / Batch CSV / Campaign pack (Ctrl+E).
5. 📁 Пакет писем → вкладка **Пакет**: файл · вердикт · score · причина · кампании;
   сортировка по колонкам, фильтр, чипы **подозр.+** / **вред.**, «Экспорт среза»;
   Ctrl+N/P — следующее письмо; diff peer → «← К пакету».
6. 🧭 **Настройки** (шапка) — пути allowlist/verdict/profile, workers, post-export hook,
   тема / compact / фильтры IOC. **Калибр.** — FP/FN по папке inbox (без БД).
7. Ctrl+Shift+V — компактный режим (только вердикт, без панели исходника).
8. **О программе** — self-check Lite/Full + `update.json` (канал / SHA256), без сети.

---

## 🖥️ GUI

| | Область | Содержание |
|---|---------|------------|
| 📧 | Письмо | `.eml` / `.msg` / папка / RFC822 / drag-drop |
| ⚖️ | Вердикт | score · breakdown (+/−) · причины |
| 📎 | Доказательства | вложения · URL rewrite · IOC-таблица |
| 📁 | Пакет | сортировка / фильтр / чипы вердикта / экспорт среза / diff peer |
| 📋 | Буфер | В тикет · копирование IOC |

| 💾 | Экспорт | JSON / CSV / Batch CSV / Тикет / Кампания / Campaign pack / SIEM |
| ⚙️ | Настройки | пути · workers · hook · тема · фильтры (→ `ui_prefs.json`) |

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
(`appearance_mode`, `ioc_density`, `verdict_compact`, `high_contrast`, пути overrides,
`post_export_hook` / JSON sidecar, `batch_sort_*`, …). Диалог **Настройки** в GUI. Без БД.

---

## ⌨️ CLI

```bash
# одно письмо — вердикт в stderr, краткий JSON в stdout
reliquary mail.eml

# флот / smoke (без GUI)
reliquary --self-check
reliquary --calibrate ./inbox

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
reliquary ./inbox --campaign-pack campaign.ndjson

# папка / пакет
reliquary ./inbox --json report.json --batch-csv triage.csv --workers 4

# overrides / org profile
reliquary mail.eml --allowlist allowlist_extra.txt
reliquary mail.eml --verdict verdict_extra.json
reliquary mail.eml --handoff-template handoff_extra.txt --handoff out.txt
reliquary mail.eml --profile org_profile/
reliquary mail.eml --profile org_profile.example/ru_gov
reliquary mail.eml --profile org_pack.zip

# IOC-фильтры (по умолчанию как в GUI)
reliquary mail.eml --full-ioc-types
reliquary mail.eml --no-actionable --no-hide-rewriter

# после экспорта — локальная команда; путь (+ опционально JSON sidecar schema_version:2)
reliquary mail.eml --json out.json --post-export-hook "python scripts/my_hook.py"
```

Снять фильтры: `--no-actionable`, `--no-hide-rewriter`, `--no-hide-allowlisted`, `--no-hide-private`.  
Полный отчёт в stdout: `--stdout-json`. Только IOC-массив: `--iocs-only`.

JSON содержит top-level **`schema_version`** (сейчас `2`) — см. [`docs/TUNING.md`](docs/TUNING.md)
и [`docs/schema_report_v2.json`](docs/schema_report_v2.json).

---

## 🔬 Что анализируется

Корневой вход — **только письма** (`.eml` / `.msg`).
Внутри письма: Office (текст + гиперссылки), ZIP / 7z / RAR\*, CAB, ISO / VHD / WIM,
TNEF (`winmail.dat`), nested `.eml` / `.msg` (в т.ч. из архива), скрипты HTA/JS/VBS,
LNK-цель, PDF `/JS`·`/URI`, HTML/SVG smuggling, QR\* (файл / CID / `data:image` / PDF-растр).

\* RAR и QR — optional extras; Lite EXE их не включает.

| | Сигнал | Примеры |
|---|--------|---------|
| 📨 | Заголовки | SPF / DKIM / DMARC, alignment, ARC, Reply-To / Return-Path, display-name spoof (Сбер / Госуслуги / ФНС / ЦБ / Почта / …), Received |
| 📝 | Тело | urgency / SE, credential / OWA, BEC, href≠label, скрытый HTML, формы, пароль архива, OOB (Telegram/SMS), cloud lure (Я.Диск / Mail.ru Cloud) |
| 🔗 | URL | SafeLinks / Proofpoint / ProxySG / Kaspersky / Dr.Web / Mail.ru / Yandex / VK / OK / Bitrix24 / amoCRM / 1C unwrap (офлайн) |
| 🎭 | Lookalike | IDN / punycode, homoglyph, Levenshtein + `weight_display_spoof` (`brands.txt`) |
| 📎 | Вложения | double ext, macros, encrypted ZIP+пароль в теле, nested mail/archive, ISO+LNK, VHD/WIM, TNEF, script URL, QR |
| 🎯 | IOC | IP, домены, URL, хеши — evidence для экспорта / handoff |

### ⚖️ Вердикт (score 0–100)

Сумма вкладов по категориям с **caps** (headers / attachments / urls / content / lookalike)
и **mitigations** (DMARC+DKIM pass, internal MX, allowlist-From, auto-reply / calendar / bulk).
Mitigations **не** применяются при auth fail/softfail/none, HIGH-атаках в заголовках,
опасных вложениях, content signals (credential / BEC / OOB / cloud lure / …)
или **display-spoof** (allowlist-From не смягчает поддельное имя).

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
| 📦 | `org_profile/` или `.zip` | пакет всего выше (zip приоритетнее папки) |
| 🔄 | `update.json` | офлайн-манифест версии: `latest` / `channel` lite\|full / `sha256` |
| 📘 | `docs/ANALYST_RU.md` | runbook (также внутри Full/Lite datas) |

**Пресеты:** [`m365`](org_profile.example/m365) ·
[`google`](org_profile.example/google) ·
[`banking`](org_profile.example/banking) ·
[`proxysg`](org_profile.example/proxysg) ·
[`kaspersky`](org_profile.example/kaspersky) ·
[`drweb`](org_profile.example/drweb) ·
[`local_mx`](org_profile.example/local_mx) ·
[`ru_mail`](org_profile.example/ru_mail) ·
[`ru_gov`](org_profile.example/ru_gov) —
см. [`org_profile.example/README.md`](org_profile.example/README.md).

CLI: `--allowlist` · `--verdict` · `--handoff-template` · `--profile` · `--post-export-hook` ·
`--self-check` · `--calibrate` · `--campaign-pack`  
Prefs: `allowlist_path`, `verdict_path`, `handoff_template_path`, `profile_dir`, `brands_path`,
`post_export_hook`, `post_export_hook_json_sidecar`, `post_export_hook_allow_external`,
`disable_post_export_hook`, …

### ✏️ Плейсхолдеры handoff

`{product}` `{version}` `{verdict}` `{score}` `{summary}` `{reasons}` `{breakdown}`  
`{file}` `{from}` `{subject}` `{msg_id}` `{auth}` `{iocs}` `{batch}`

Порядок шаблона: явный путь → `handoff_{level}.txt` (profile / app dir) → `handoff_extra.txt` → встроенный блок.

В JSON / meta: `schema_version`, `app_version`, `overrides_loaded`, `profile_dir`.

---

## 🧪 Корпус и тесты

Golden corpus: `samples/corpus/` + `expected.json` (**85** писем по всем уровням).

```bash
pip install -r requirements-dev.txt
pip install -e ".[dev]"

pytest -q
python scripts/corpus_metrics.py                        # accuracy + drift
python scripts/corpus_metrics.py --inbox path/to/emls   # калибровка на локальном inbox
reliquary --calibrate path/to/emls                      # то же через CLI
python scripts/gen_corpus.py                            # пересобрать sample .eml
python scripts/regen_expected.py                        # обновить expected.json (dev)
```

См. [`samples/corpus/README.md`](samples/corpus/README.md), [`docs/TUNING.md`](docs/TUNING.md),
[`docs/ANALYST_RU.md`](docs/ANALYST_RU.md), [`docs/PACKAGING.md`](docs/PACKAGING.md).

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

По умолчанию — **Full** (RAR + QR extras). Lite:

```bat
build_exe.bat --lite
```

Скрипт сам:

1. Берёт `.venv\Scripts\python.exe`, если есть, иначе `python` из PATH  
2. Ставит `requirements.txt` + PyInstaller + пакет (+ `.[rar,qr]` для Full)  
3. Синхронизирует `build\version_info.txt`  
4. Запускает PyInstaller (`build\reliquary.spec`)  
5. Пишет `dist\EmailIOCExtractor.exe.sha256`

Ручная сборка (эквивалент Full):

```bash
pip install -r requirements-dev.txt
pip install -e ".[rar,qr]"
RELIQUARY_FULL=1 python build/sync_version_info.py
RELIQUARY_FULL=1 python -m PyInstaller build/reliquary.spec --noconfirm
```

Linux/macOS: `bash build/build.sh` (Full) / `bash build/build.sh --lite`.

| | |
|--|--|
| 📦 Артефакт | `dist/EmailIOCExtractor.exe` (**Full** по умолчанию, без консоли, без UPX) + `.sha256` |
| 🏷️ Версия | `reliquary/__init__.py` → `build/version_info.txt` + `pyproject.toml` |
| ✍️ Подпись | `build/sign_exe.ps1` / [`docs/SIGNING.md`](docs/SIGNING.md) (опционально) |
| 📜 Лог | `email_ioc_extractor_error.log` |
| 🧊 Smoke | `EmailIOCExtractor.exe --cli sample.eml --json out.json` |

CI: pytest Windows + Ubuntu, **Python 3.10–3.13**; push в `main` → Full EXE + frozen `--cli` smoke + SHA256;
тег `v*` → GitHub Release с changelog и хешем. История: [`CHANGELOG.md`](CHANGELOG.md).
Безопасность: [`SECURITY.md`](SECURITY.md). Схема JSON: [`docs/schema_report_v2.json`](docs/schema_report_v2.json).

---

## 📂 Структура репозитория

```
reliquary/
  core/     # pipeline, verdict (+ mitigations), lookalike, content_signals,
            # attachment_inspector, tnef, url_rewrite, calibration, self_check,
            # update_check, IOC, diff, export_hook, handoff, allowlist, org_profile
  gui/      # app + mixins: layout, analysis, clipboard, result_panels,
            # settings_dialog, prefs_actions, hotkeys, about, ioc_table
samples/corpus/          # golden EMLs/MSG + expected.json (85)
org_profile.example/     # пресеты m365 / google / banking / ru_mail / ru_gov / …
docs/                    # TUNING, ANALYST_RU, PACKAGING, SIGNING, schema
tests/                   # corpus + доменные тесты (в т.ч. schema drift-gate)
scripts/                 # gen_corpus, regen_expected, corpus_metrics
build/                   # build.bat, build.sh, PyInstaller, version sync, sign
build_exe.bat            # Windows: обёртка → build\build.bat
run_gui.bat              # Windows: запуск GUI
update.json.example      # офлайн-манифест версии для флота
```

---

## 📄 Лицензия

Внутренний инструмент SOC — см. [`LICENSE`](LICENSE). Контрибут: [`CONTRIBUTING.md`](CONTRIBUTING.md).
