# Email IOC Extractor

**Mail. Extract. Decide.** · v2.18.0

🔒 Офлайн-инструмент SOC для triage писем (`.eml` / `.msg` / `.mbox` / `.pst`): заголовки,
вложения, URL rewrite, IOC как доказательства и **вердикт**
(`benign` / `unknown` / `suspicious` / `malicious`) со score, разбором весов
(включая mitigations) и **уверенностью** (`high` / `medium` / `low`).

📡 Сеть не используется. Пакет Python — `reliquary`; продукт — **Email IOC Extractor**.
Деплой: **один EXE** + опциональные конфиги рядом (без БД). QR decode встроен.

📦 Экспорт (GUI): JSON (`schema_version` **2**) · CSV · Batch CSV · Тикет.

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
pip install -e ".[yara]"   # offline YARA по вложениям/телу
pip install -e ".[pst]"    # разбор Outlook .pst (libratom)
```

### 📦 Одна EXE-сборка

CI / `build_exe.bat` публикуют **`EmailIOCExtractor.exe`** (core + QR).
Разделения Lite/Full нет. RAR-вложения детектятся без listing членов;
ZIP/7z unlock и опциональный YARA остаются.

В Release notes публикуется **SHA256** одного EXE.

⚠️ При ошибке GUI смотрите `email_ioc_extractor_error.log` рядом с bat/exe.

---

## 📋 Analyst runbook

1. 📧 Откройте письмо (`.eml` / `.msg` / `.mbox` / `.pst`), папку или вставьте RFC822 слева (Ctrl+Enter).
2. ⚖️ Вкладка **Вердикт**: уровень, score, **уверенность**, разбор (`+N` risk / `−N` mitigation), причины.
3. 🔎 При шуме ослабьте фильтры («к разбору», SafeLinks, allowlist) или включите **все типы** IOC.
4. 🎫 **Тикет** (Ctrl+H) → буфер для ITSM; либо JSON / CSV / Batch CSV (Ctrl+E).
5. 📁 Пакет писем → вкладка **Пакет**: файл · вердикт · score · причина · peers кампании;
   Ctrl+N/P — следующее письмо; Ctrl+Shift+N/P — только suspicious/malicious;
   клик **`[сравнить с …]`** или двойной клик по строке — diff с peer.
   На вердикте строка кампании, если From-домены в группе разошлись.
6. Ctrl+Shift+V — компактный режим (только вердикт, без панели исходника).
7. ПКМ по IOC → **В allowlist**, **Сменить вердикт…**, Feedback FP / FN / подтвердить
   (`analyst_feedback.ndjson`); пароль ZIP/7z на сессию. RAR с паролем не расшифровывается.
8. ⚙️ **Настройки** → импорт org profile; тема / contrast / фильтры IOC.

---

## 🖥️ GUI

| | Область | Содержание |
|---|---------|------------|
| 📧 | Письмо | `.eml` / `.msg` / `.mbox` / `.pst` / папка / RFC822 / drag-drop |
| ⚖️ | Вердикт | score · confidence · breakdown (+/−) · причины · строка кампании |
| 📎 | Доказательства | вложения · URL rewrite · IOC-таблица |
| 📁 | Пакет | сводка + peers кампании + diff |
| 📋 | Буфер | В тикет · копирование IOC |
| 💾 | Экспорт | JSON / CSV / Batch CSV / Тикет |

**Фильтры по умолчанию:** rewriter/noise (SafeLinks и т.п.) и локальные IP скрыты;
«к разбору» включён; крипто и legacy host-IOC (registry / mutex / …) скрыты.

### ⌨️ Горячие клавиши

| Клавиши | Действие |
|---------|----------|
| Ctrl+O | 📂 Открыть письмо |
| Ctrl+Enter | ▶ Разбор RFC822 из левой панели |
| Ctrl+H | 🎫 Копировать тикет |
| Ctrl+E | 💾 Экспорт (выбранный формат) |
| Ctrl+R | 📝 Копировать причины вердикта |
| Ctrl+C / Ctrl+Shift+C | 📋 IOC / defanged |
| Ctrl+Shift+V | 📐 Компактный вердикт |
| Ctrl+N / Ctrl+P | 📁 Следующее / предыдущее письмо пакета |
| Ctrl+Shift+N / Ctrl+Shift+P | 📁 Следующее / предыдущее suspicious или malicious |
| Ctrl+L | 🌓 Тема light / dark |
| Ctrl+D | 📏 Плотность IOC (compact / normal / comfortable) |
| Ctrl± | 🔍 Масштаб UI |
| 1–6 | 📑 Вердикт, Вложения, URL, IOC, Пакет, Ошибки (клавиша действует и если вкладка скрыта) |
| Ctrl+F | 🔎 Поиск по IOC, причинам вердикта и именам вложений |

Prefs: `ui_prefs.json` рядом с EXE
(`appearance_mode`, `ioc_density`, `verdict_compact`, пути overrides, …). Без БД.

---

## ⌨️ CLI

```bash
# одно письмо — вердикт в stderr, краткий JSON в stdout
reliquary mail.eml

# повседневный экспорт (как в GUI)
reliquary mail.eml --json report.json
reliquary mail.eml --csv out.csv
reliquary mail.eml --handoff ticket.txt
reliquary ./inbox --json report.json --batch-csv triage.csv --workers 4

# overrides / org profile
reliquary mail.eml --allowlist allowlist_extra.txt
reliquary mail.eml --verdict verdict_extra.json
reliquary mail.eml --handoff-template handoff_extra.txt --handoff out.txt
reliquary mail.eml --profile org_profile/
reliquary mail.eml --profile org_profile.example/m365
reliquary mail.eml --profile org_profile.example/by_gov
reliquary mail.eml --profile org_pack.zip

# архив ZIP/7z (RAR не расшифровывается) / YARA (2.16+: bundled yara_rules/default.yar, auto if yara installed)
reliquary mail.eml --archive-password 'secret'
reliquary mail.eml --enable-yara --yara-rules rules.yar

# самопроверка / feedback
reliquary --self-check
reliquary --feedback-summary
reliquary --feedback-weights suggested.json   # ±2 к весам по сегментам FP/FN
reliquary --feedback-tune suggested.json      # веса + пороги/caps

# IOC-фильтры (по умолчанию как в GUI)
reliquary mail.eml --full-ioc-types
reliquary mail.eml --no-actionable --no-hide-rewriter

# после экспорта — локальная команда; путь к файлу — последний argv
reliquary mail.eml --json out.json --post-export-hook "python scripts/my_hook.py"
```

Снять фильтры: `--no-actionable`, `--no-hide-rewriter`, `--no-hide-allowlisted`, `--no-hide-private`.  
Полный отчёт в stdout: `--stdout-json`. Только IOC-массив: `--iocs-only`.

JSON содержит top-level **`schema_version`** (сейчас `2`) и поля вердикта
`confidence` / `confidence_note` — см. [`docs/TUNING.md`](docs/TUNING.md)
и [`docs/schema_report_v2.json`](docs/schema_report_v2.json).

Калибровка на локальном inbox (не CLI-флаг):  
`python scripts/corpus_metrics.py --inbox path/to/emls`

### 🔌 CLI SIEM / кампания (не в GUI)

В выпадающем списке GUI этих форматов **нет** (legacy prefs мапятся на JSON/CSV/Тикет).
Для пайплайнов флаги CLI сохранены:

```bash
reliquary mail.eml --ecs report.ecs.json
reliquary mail.eml --cef report.cef
reliquary mail.eml --stix report.stix.json
reliquary mail.eml --misp attrs.csv
reliquary mail.eml --opencti opencti.json
reliquary ./inbox --campaign-handoff campaign.txt
reliquary ./inbox --campaign-pack pack.ndjson
```

---

## 🔬 Что анализируется

Корневой вход — **письма** (`.eml` / `.msg` / `.mbox` / `.pst`\*).
Внутри письма: Office, ZIP / 7z / RAR\*\* , nested `.eml` / `.msg`, OLE / macros,
TNEF / ISO / VHD, скрипты (JS/VBS/HTA/…), QR, messenger/QR lure, HTML polyglot,
remote template, опционально YARA\*\*\*.

\* PST — MVP: `pip install -e ".[pst]"` (libratom; также подходит pypff); без lib — RU-пропуск, без краша.  
\*\* RAR — `rar_archive` + эвристический scrape имён (без rarfile/UnRAR).  
\*\*\* YARA — `pip install -e ".[yara]"`; `yara_rules/` рядом с EXE / `--yara-rules` (авто).

| | Сигнал | Примеры |
|---|--------|---------|
| 📨 | Заголовки | SPF / DKIM / DMARC, alignment, ARC, Reply-To / Return-Path, Resent-From, Message-ID ≠ From, display-name spoof (RU/BY/KZ/UA), Received |
| 📝 | Тело | urgency, credential / OWA, BEC / ЕРИП, href≠label, скрытый HTML, формы, cloud lure, ClickFix, image-only HTML, поддельный Authentication-Results |
| 🔗 | URL | SafeLinks / Proofpoint / Barracuda / Mimecast / Mail.ru / Yandex / VK / Bitrix / amoCRM / 1C / gov RU·BY unwrap (офлайн) |
| 🎭 | Lookalike | IDN / punycode, homoglyph, Levenshtein к брендам (`brands.txt`) |
| 📎 | Вложения | double ext, macros, Excel 4.0/XLM, encrypted ZIP/7z (session password; RAR не расшифровывается), encrypted Office + пароль в теле, nested mail, TNEF, ISO+LNK, QR-URL |
| 🎯 | IOC | IP, домены, URL, хеши — evidence для экспорта / тикета |

### ⚖️ Вердикт (score 0–100)

Сумма вкладов по категориям с **caps** (headers / attachments / urls / content / lookalike)
и **mitigations** (DMARC+DKIM pass, trusted Received hop, allowlisted From,
auto-reply / calendar / …).
Календарная митигация не применяется, если в ICS есть URL или `ATTACH`.
Auth/allowlist-смягчения не копятся при auth fail/softfail/none или HIGH-заголовках;
при опасных вложениях, BEC/credential/cloud lure или display-spoof смягчения в целом
не применяются (allowlisted From — никогда при display-spoof).

| | Уровень | Score |
|---|---------|-------|
| ✅ | benign | 0–9 |
| ❔ | unknown | 10–29 |
| ⚠️ | suspicious | 30–59 |
| 🛑 | malicious | ≥ 60 |

Веса и пороги: `reliquary/core/verdict_config.py` (+ scoring / confidence).
Фасад API: `reliquary/core/verdict.py`.
Override: `verdict_extra.json`
(схема: [`docs/verdict_extra.schema.json`](docs/verdict_extra.schema.json)).  
Калибровка FP/FN: [`docs/TUNING.md`](docs/TUNING.md).

---

## 🧩 Конфиги рядом с EXE (без БД)

| | Файл / путь | Назначение |
|---|-------------|------------|
| ✅ | `allowlist_extra.txt` | доп. домены / IP (`allowlist_extra.example.txt`) |
| ⚖️ | `verdict_extra.json` | веса, пороги, caps, mitigations (`verdict_extra.example.json`) |
| 🎫 | `handoff_extra.txt` | шаблон ITSM по умолчанию |
| 🏷️ | `handoff_{level}.txt` | шаблон для `malicious` / `suspicious` / `unknown` / `benign` |
| 🏛️ | `brands.txt` | бренды для lookalike |
| 📦 | `org_profile/` или `.zip` | пакет всего выше |
| 📝 | `analyst_feedback.ndjson` | FP/FN от аналитика (GUI ПКМ) |
| 🔬 | `yara_rules.yar` / `yara_rules/` | optional YARA (extra) |
| 🎛️ | `ui_prefs.json` | тема, фильтры, пути, workers, hook |
| 🔄 | `update.json` | локальный манифест версии (без сети; см. `update.json.example`) |

**Пресеты:** [`m365`](org_profile.example/m365) ·
[`google`](org_profile.example/google) ·
[`banking`](org_profile.example/banking) ·
[`proxysg`](org_profile.example/proxysg) ·
[`kaspersky`](org_profile.example/kaspersky) ·
[`drweb`](org_profile.example/drweb) ·
[`local_mx`](org_profile.example/local_mx) ·
[`ru_mail`](org_profile.example/ru_mail) ·
[`ru_gov`](org_profile.example/ru_gov) ·
[`by_gov`](org_profile.example/by_gov) ·
[`kz_gov`](org_profile.example/kz_gov) ·
[`ua_gov`](org_profile.example/ua_gov) —
см. [`org_profile.example/README.md`](org_profile.example/README.md).

CLI: `--allowlist` · `--verdict` · `--handoff-template` · `--profile` ·
`--post-export-hook` · `--archive-password` · `--enable-yara` · `--yara-rules` ·
`--feedback-weights` · `--feedback-tune`  
Prefs: `allowlist_path`, `verdict_path`, `handoff_template_path`, `profile_dir`, `brands_path`,
`post_export_hook`, `post_export_hook_allow_external`, `disable_post_export_hook`,
`enable_yara`, `yara_rules_path`, …

### ✏️ Плейсхолдеры тикета (handoff)

`{product}` `{version}` `{verdict}` `{score}` `{summary}` `{reasons}` `{actions}` `{breakdown}`  
`{file}` `{from}` `{subject}` `{msg_id}` `{auth}` `{iocs}` `{batch}`  
`{chains}` `{att_flags}` `{campaign}` `{spoof}`

Порядок шаблона: явный путь → `handoff_by_level` (org profile) → `handoff_{level}.txt` (profile / app dir) → `handoff_extra.txt` → встроенный блок.

В JSON / meta: `schema_version`, `app_version`, `overrides_loaded`, `profile_dir`.

---

## 🧪 Корпус и тесты

Golden corpus: `samples/corpus/` + `expected.json` (**103** кейса: `.eml` / `.msg`;
узкие score windows ±8/±10). Включает FP-кейсы, RU/BY/KZ/UA display-spoof, BEC/ЕРИП,
wrap-lure / ARC / DDE / polyglot / CID.

```bash
pip install -r requirements-dev.txt
pip install -e ".[dev]"

pytest -q --cov=reliquary/core --cov-fail-under=75
python scripts/corpus_metrics.py                        # accuracy + drift
python scripts/corpus_metrics.py --inbox path/to/emls   # калибровка на локальном inbox
python scripts/gen_corpus.py                            # пересобрать sample .eml
python scripts/regen_expected.py                        # обновить expected.json (dev)
```

См. [`samples/corpus/README.md`](samples/corpus/README.md), [`docs/TUNING.md`](docs/TUNING.md),
[`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## 🏗️ Сборка EXE (Windows)

```bat
build_exe.bat
```

или напрямую: `build\build.bat`

Скрипт:

1. Берёт `.venv\Scripts\python.exe`, если есть, иначе `python` из PATH  
2. Ставит `requirements.txt` + PyInstaller + пакет (включая `pyzbar`)  
3. Синхронизирует `build\version_info.txt`  
4. Запускает PyInstaller (`build\reliquary.spec`)  
5. Пишет `dist\EmailIOCExtractor.exe.sha256`

Ручная сборка:

```bash
pip install -r requirements-dev.txt
pip install -e .
python build/sync_version_info.py
python -m PyInstaller build/reliquary.spec --noconfirm
```

Linux/macOS: `bash build/build.sh`.

| | |
|--|--|
| 📦 Артефакт | `dist/EmailIOCExtractor.exe` (core + QR) + `.sha256` |
| 🏷️ Версия | `reliquary/__init__.py` → `build/version_info.txt` + `pyproject.toml` |
| ✍️ Подпись | `build/sign_exe.ps1` / [`docs/SIGNING.md`](docs/SIGNING.md) (опционально) |
| 📜 Лог | `email_ioc_extractor_error.log` |
| 🧊 Smoke | `EmailIOCExtractor.exe --cli sample.eml --json out.json` |

CI: pytest Windows + Ubuntu, **Python 3.10–3.13**; coverage gate **75%** (core);
push в `main` → один EXE + frozen `--cli` smoke + SHA256;
тег `v*` → GitHub Release с changelog и хешем. История: [`CHANGELOG.md`](CHANGELOG.md).
Безопасность: [`SECURITY.md`](SECURITY.md). Схема JSON: [`docs/schema_report_v2.json`](docs/schema_report_v2.json).
Справка аналитика: [`docs/ANALYST_RU.md`](docs/ANALYST_RU.md).

---

## 📂 Структура репозитория

```
reliquary/
  core/     # pipeline, verdict_config / scoring / confidence,
            # lookalike, content_signals, IOC, archive_unlock, yara_scan,
            # feedback, mbox_ingest, pst_ingest, diff, exporters, handoff,
            # allowlist, org_profile, batch, calibration
  gui/      # app + mixins: layout, analysis, clipboard, result_panels,
            # hotkeys, filters_actions, export_actions, analyst_actions,
            # prefs_actions, settings_dialog, about, ioc_table, tabs
samples/corpus/          # golden EMLs + expected.json (103)
org_profile.example/     # m365 / google / banking / ru_gov / by_gov / kz_gov / ua_gov / …
docs/TUNING.md           # калибровка verdict_extra.json
docs/ANALYST_RU.md       # runbook
tests/                   # corpus + доменные / GUI smoke / BY
scripts/                 # gen_corpus, regen_expected, corpus_metrics
build/                   # build.bat, build.sh, PyInstaller, version sync, sign
build_exe.bat
run_gui.bat
```

---

## 📄 Лицензия

Внутренний инструмент SOC — см. [`LICENSE`](LICENSE). Контрибут: [`CONTRIBUTING.md`](CONTRIBUTING.md).
