# Changelog

## 2.13.0

### Детекция
- Вложенные `.eml`/`.msg` из ZIP/RAR → разбор URL/IOC (не только флаг)
- Связка «пароль архива» в теле + `encrypted_archive` (`archive_password_match`)
- Out-of-band доставка: пароль/файл через Telegram / SMS / шортенер / облако
- TNEF / `winmail.dat` — офлайн-извлечение вложений
- Inventory ISO: LNK/EXE/HTML внутри образа (`iso_contains_lnk`)
- QR Full: CID / inline / `data:image` + растр PDF-страниц
- MSG: transport-заголовки + вложения во вложенных MSG
- Display-spoof: ФНС, ЦБ, Почта России, Госключ, МВД, мос.ру

### Продукт / EXE
- Allowlist → mitigation вердикта для доверенного From (`weight_allowlisted_from`)
- `update.json`: SHA256 EXE + канал Lite/Full + RU-строки в About/self-check
- Диалог «Настройки»: пути, workers, post-export hook, Campaign pack
- Post-export hook: JSON sidecar `schema_version:2` вторым argv
- Пакет: сортировка/фильтр по вердикту·score + «← К пакету» после diff

### Качество
- Калибровка: сегменты `tnef` / `iso` / `archive_password` / `oob_delivery` / `nested_mail`
- Corpus: password-zip match, nested-mail-in-zip, OOB, FNS spoof, MSG, ISO+LNK, TNEF
- Schema/example: новые веса verdict_extra

## 2.12.0

### Детекция
- Веса для уже эмитируемых флагов: CAB, LNK dangerous/http, PDF `/URI`, `unrar_missing`, nested archive, zip-bomb
- Отдельный `weight_display_spoof` (Сбер/Госуслуги не растворяются в lookalike)
- LNK-цель → IOC + флаги `lnk_dangerous` / `lnk_http_target`
- OOXML-гиперссылки first-class (`office_hyperlink` + IOC tags)
- RU unwrap: VK/OK away, расширенные Mail.ru/Yandex, gov/sber redirect hosts
- Internal relay mitigation: corp.local / RU on-prem MX patterns

### Продукт / EXE
- Self-check: сверка SHA256 EXE, проверка `org_profile.zip`, громче `unrar_missing`
- `ANALYST_RU.md` (+ schema v2) в datas PyInstaller; About ищет runbook рядом с EXE
- Богаче дефолтный handoff: campaign, display-spoof, unwrap chains, attachment flags
- `--campaign-pack` / GUI «Campaign pack» — offline NDJSON или CEF по пакету писем
- Пресет `org_profile.example/ru_mail/`; усилен `local_mx`

### Качество
- Калибровка: сегменты display_spoof / shortener / messenger / html_smuggling / cab
- Corpus: SVG, OneNote, 7z, RAR double-ext, shortener-only, VK away, PDF URI, local MX RU
- Docs: README corpus/schema drift; TUNING + verdict_extra schema/example

## 2.11.0

### Детекция
- Spoof display-name From («Сбербанк / Госуслуги / Microsoft» при чужом `@`)
- Текст OOXML (`office_extract`) в pipeline → IOC / content signals
- RAR: double-ext / nested mail / `unrar_missing`; CAB listing; цель LNK офлайн
- Сигналы `url_shortener` и `messenger_only` (bit.ly / t.me …)

### Продукт / EXE
- Вкладка «Ошибки»: путь к журналу, [L] открыть каталог, [R]/Ctrl+R причины вердикта
- Prefs `last_inbox_dir` для калибровки; CLI help/статусы на русском
- Self-check: rarfile ≠ UnRAR.exe
- `docs/PACKAGING.md` и `docs/SIGNING.md` на русском + чеклист флота

### Качество
- Corpus: display-spoof, messenger-only, LNK, CAB
- MSG из bytes (temp-файл); узкие `except` в `document_parser`

## 2.10.0

### Детекция
- HTML/HTM/MHT/SVG вложения: офлайн-разбор + флаги `html_attachment` / `html_smuggling` / `svg_script`
- PDF-эвристики: `/JS` · `/OpenAction` · `/URI` (`pdf_javascript`, `pdf_uri_action`)
- RU unwrap: Mail.ru away/click, Яндекс clck/redir
- Benign: `List-Unsubscribe` / `List-Id` / `Precedence: bulk` (`weight_mailing_list`)
- Веса: `weight_pdf_javascript`, `weight_html_smuggling`, `weight_html_attachment`

### Продукт / один EXE
- Self-check при старте и в «О программе» (Lite/Full, конфиги рядом с EXE)
- Предупреждения битого `verdict_extra.json` в статусе / About
- Кнопка «Калибр.» — отчёт сегментов FP/FN без БД (`calibration_inbox_report.txt`)
- Автоподхват `org_profile.zip` рядом с EXE (приоритетнее папки)
- Дочистка EN в UI (Балл, ДОВЕР/ПРОКСИ, Фокус, тикет)

### Качество
- Corpus: mailing-list, HTML-att, PDF JS, Mail.ru/Yandex wraps
- `reliquary.core.calibration` / `self_check`

## 2.9.0

### Детекция / triage
- Benign-маркеры: автоответ / OOO, календарь/ICS, корпоративная подпись, ответ в треде (`In-Reply-To` / `References`)
- `MailIdentity`: `in_reply_to`, `references`, `auto_submitted`; `thread_root_id()`
- Ключ кампании: `thread:<root>` (затем Msg-ID / вложения / subject)
- Вложенные `.eml` до глубины 2; URL unwrap через registry
- `cap_mitigation` по умолчанию 30; веса `weight_auto_reply` / `weight_calendar_invite` / `weight_corp_signature` / `weight_thread_reply`

### Продукт / один EXE
- Компактный вердикт (Ctrl+Shift+V): скрыть исходник, фокус на вердикте; prefs `verdict_compact`
- Навигация пакета Ctrl+N / Ctrl+P (+ сравнение с peer)
- Экспорт «Тикет»; About / пакет — только RU
- Калибровка inbox: сегменты FP/FN в `corpus_metrics.py --inbox` (без БД)
- Схема `docs/verdict_extra.schema.json` + `validate_verdict_extra`
- Деплой: **1 EXE** + опциональные конфиги рядом (`ui_prefs.json`, `verdict_extra.json`, org profile) — без базы данных

### Качество
- Corpus: автоответ, ответ в треде, nested depth-2
- Узкие `except` в hotkeys / layout resize / nested mail

## 2.8.0

### Detection
- BEC / платёжные маркеры (RU+EN): `bec_payment`, вес `weight_bec_payment`
- Вложенные URL-цепочки unwrap (SafeLinks→ProxySG→…) + поле `chain`
- Href≠label после полного unwrap
- Флаги вложений: `iso_image`, `shortcut_lnk`, `onenote_attachment` + веса
- Баннер QR для Lite / без pyzbar

### Product / RU
- Русские подписи вердикта в GUI; override принимает RU и EN коды
- «В тикет» / «Сменить вердикт» / «сравнить с peer»
- Пакетный handoff кампаний (`--campaign-handoff`, GUI «Кампания»)
- Крупнее hero-шрифт вердикта

### Integrations
- `schema_version: 2` — `unwrap_chains`, `campaign`, `analyst_override`
- Экспорт MISP CSV и OpenCTI lite JSON
- Опциональная Authenticode-подпись в release CI (`SIGNING_PFX_*` secrets)

### Quality
- Corpus: BEC RU, nested unwrap, ISO; property-тесты unwrap
- Coverage / mypy без регресса

## 2.7.0

### Product / RU-only
- UI только на русском: убран EN-каталог и prefs `ui_lang`
- Экспорт SIEM: ECS JSON, ArcSight CEF, STIX 2.1 lite (CLI `--ecs` / `--cef` / `--stix`, GUI)
- Org profile пресеты: ProxySG, Kaspersky, Dr.Web, local MX
- Заметка о шифрованном архиве и About — на русском

### Detection / unwrap
- URL unwrap: ProxySG (`/*,N,/`), Kaspersky click, Dr.Web link
- Отдельный вес `weight_encrypted_archive` + явная причина в вердикте
- Расширен FP/FN corpus (RU HR/calendar, BEC, Kaspersky/Dr.Web wraps)

### Hardening / DX
- Post-export hook: блок shell/bash/node/perl/ruby и метасимволов
- CI Release: Lite + Full EXE с SHA256
- mypy шире; тесты переименованы с versioned → доменные

## 2.6.0

### Hardening / core
- Zip-bomb inflate-ratio + declared-size guards in attachment ZIP inventory
- Source EML/MSG size cap (`MAX_SOURCE_BYTES`); shared `_enrich_parsed_result` in pipeline
- URL unwrap: Cisco Umbrella / Trend, Google `/url`, Defender ATP / aka.ms
- Lookalike: stricter short-brand levenshtein to cut FP
- Allowlist append API; encrypted-archive handoff note helper
- Offline `update.json` manifest check

### GUI / analyst workflow
- Batch tab Treeview (select → focus; double-click → campaign diff)
- ПКМ: allowlist host, verdict override, encrypted-archive note
- Cancel applies to single-mail text analysis; Stop button shared
- Prefs `ui_lang` / `high_contrast`; i18n catalog; About shows update + runbook path

### Quality / DX
- FP corpus samples + drift gate (`CORPUS_MAX_DRIFT`); more unwrap snapshots
- Docs: `ANALYST_RU.md`, `PACKAGING.md`, `update.json.example`
- CI: optional Full EXE artifact; broader mypy; coverage floor raised

## 2.5.0

### Security / hardening
- Org profile zip: zip-slip–safe extract (`UnsafeZipError`); temp profiles cleaned in CLI/GUI
- Post-export hook: block downloader/shell patterns; prefer scripts under app dir; prefs `post_export_hook_allow_external` / `disable_post_export_hook`; env `RELIQUARY_DISABLE_EXPORT_HOOK`
- Prefs load coerces types (scale, workers, booleans, enums)
- Docs: `SECURITY.md`, `LICENSE`, `docs/SIGNING.md`

### Packaging / CI
- Full EXE: auto-bundle `rarfile`/`pyzbar` when installed; `RELIQUARY_FULL=1` / `build_exe.bat --full`
- Frozen `--cli` mode for headless smoke; CI tag `v*` pushes build Release
- Single version source: `reliquary/__init__.py` → `version_info.txt` + `pyproject.toml`
- Coverage gate on `reliquary/core` (≥60%); Python 3.13 in matrix
- App icon `build/app.ico`; `build/build.sh --full` + SHA256

### Product / DX
- GUI: `filters_actions` mixin; unified `defang`/`refang` in `core/defang.py`
- CLI `--verbose` (error log note); soft-rotate error log at ~2MB
- JSON Schema: `docs/schema_report_v1.json`; `CONTRIBUTING.md`

## 2.4.0

### Detection / verdict
- Mitigations: отрицательные веса (DMARC+DKIM pass, trusted Received hop) с `cap_mitigation`
- Расширенный golden corpus (~40 писем) + `scripts/regen_expected.py`

### Product / UX
- Diff кампании во вкладке «Пакет» (`[diff vs peer]`)
- Org profile presets: M365 / Google / banking
- Post-export hook: prefs `post_export_hook` / CLI `--post-export-hook`
- JSON `schema_version` для стабильных интеграций
- GUI: mixins `hotkeys` / `prefs_actions` / `about` (тонкий `app.py`)

### Quality / DX
- CI: Python 3.10–3.12; mypy на pipeline / ioc_extractor / header_analyzer / attachment_inspector
- Release: SHA256 рядом с EXE + Lite/Full в notes
- Узкие except в office/attachment с классом ошибки в notes
- Тесты по доменам (`test_verdict_scoring`, `test_content_lookalike`, …) вместо v21/v22/v23
- Docs: `docs/TUNING.md`, калибровка `--inbox`

## 2.3.0

### Detection / verdict
- Lookalike / IDN / homoglyph (бренды + `brands.txt` в org profile)
- Калибровка score: caps по категориям, breakdown (`verdict.breakdown`)
- Content signals: credential harvest, href≠label, hidden HTML, forms, QR
- Auth nuance: SPF/DKIM fail vs softfail, DKIM alignment, ARC

### Product / UX
- Org profile pack: папка или `.zip` (`--profile` / `org_profile/`)
- `AnalysisOptions` — единые пути для CLI/GUI/batch
- Handoff по уровню: `handoff_{malicious|suspicious|…}.txt` + `{version}` `{breakdown}`
- Batch: группировка кампаний (Msg-ID / тема / хеш вложения)
- GUI: разбор score, Ctrl+H/E/L/D, тема light/dark, плотность IOC
- Meta: `overrides_loaded` + версия в отчёте / About

### Quality / DX
- Corpus ~15 писем + `scripts/corpus_metrics.py`
- URL unwrap fuzz; mypy на pipeline / lookalike / content / org profile
- GUI: `layout.py` mixin (тонкий `app.py`)
- CI: Windows+Ubuntu, smoke после PyInstaller, release notes на тег `v*`

### Tests
- `test_v23_improvements.py`, расширенный corpus / unwrap fuzz

## 2.2.0

### Product
- Override весов вердикта: `verdict_extra.json` / `--verdict` / prefs `verdict_path`
- Handoff ITSM-шаблон: `handoff_extra.txt` / `--handoff-template` (плейсхолдеры `{verdict}` `{score}` …)
- Email-mode IOC: по умолчанию скрыты registry/mutex/command_line; крипто выкл.; GUI «все типы» / `--full-ioc-types`
- Batch summary: таблица файл · вердикт · score · top reason; Batch CSV колонка `top_reason`
- Golden corpus `samples/corpus/` + snapshot-тесты URL unwrap (SafeLinks/Proofpoint/…)

### Quality / DX
- Runtime ошибки GUI → append в `email_ioc_extractor_error.log`
- GUI split: `analysis_actions` + `clipboard_actions` mixins
- Mypy на verdict / url_rewrite / error_log (+ прежние helpers)
- Единый источник версии: `build/sync_version_info.py`
- CI: artifact `EmailIOCExtractor.exe` на push в main
- Docs: analyst runbook, optional rar/qr extras

### Tests
- Corpus verdicts, URL unwrap snapshots, verdict/handoff/filter 2.2 unit tests

## 2.1.0

### Product
- Локальный allowlist override (`allowlist_extra.txt` / `--allowlist` / prefs)
- Handoff: текстовый блок для ITSM (GUI «Handoff», CLI `--handoff`, экспорт)
- Batch CSV + JSON `batch[]` — triage по письмам в пакете
- CLI-фильтры по умолчанию как в GUI (`--no-actionable` / `--no-hide-*` чтобы снять)
- Единый каталог категорий IOC (`IOC_GROUPS` в `filter_state`)

### Cleanup / DX
- Убраны хвосты denylist / root PDF-HTML-ticket parsers / case-pack комментарии
- Убрана зависимость `pypdf` (PDF больше не корневой вход)
- `requirements.txt` = runtime; `requirements-dev.txt` = pytest/pyinstaller/ruff/mypy
- CI: ruff на `reliquary/`; mypy на typed helpers (models, filters, export…)
- GUI: `result_panels` mixin; дешевле refresh при поиске/фильтрах; skip rebuild IOC-таблицы
- GUI: нет кнопки «Вложения» — дамп файлов на диск убран; вкладка показывает хеши/флаги
- GUI: нет постоянной нижней полосы — Стоп/Повтор только во время разбора или при ошибках
- GUI: вкладки Вердикт / Вложения / URL читаются крупнее (14–18pt вместо 12pt Consolas)
- GUI: панель «Детали» IOC больше не сжимает значение; типы в таблице окрашены по-разному
- GUI: окно открывается по центру экрана, если сохранённая позиция уехала за монитор

### Tests
- `.msg` sample, allowlist extra, handoff/batch export, header/verdict edges

## 2.0.2

### Product
- Пользовательское имя: **Email IOC Extractor** (пакет `reliquary` без изменений)

### GUI
- Единый шрифт UI (Segoe UI) и моноширинный (Consolas / Cascadia Mono)
- Тулбар, сводка вердикта и панель IOC переносятся на узком окне вместо обрезки
- Короткие подписи вкладок на узкой панели; таблица IOC масштабируется вместе с UI
- Подсказки в статусбаре читаемые (не сливаются с фоном)
- IOC-таблица уплотнена (11pt / ряд ~24px) — больше строк на экран
- Фильтры: «к разбору» всегда на виду; типы и шум — в компактной панели «Ещё»

## 2.0.1

### Cleanup
- Убраны внешние конфиги: `allowlist.txt`, `denylist.txt`, `verdict.ini`, `ticket.ini`
- Встроенный allowlist (CDN/mail) и веса вердикта в коде
- Экспорт только JSON / CSV (без STIX / MISP / OpenCTI / YARA / case pack)
- Удалены шаблоны тикетов и импорт списков из GUI/CLI

## 2.0.0

### Product
- Фокус: **только email** (`.eml` / `.msg`) → **вердикт** triage
- Пользовательский бренд: **Email IOC Extractor** (пакет `reliquary`)
- IOC остаются как доказательства и для экспорта / handoff
- PDF / HTML / txt / Office / архивы больше не принимаются как корневой вход
  (вложения внутри письма по-прежнему разбираются)

### GUI (EXE UX)
- Вердикт — hero в шапке результатов; вкладка «Вердикт» по умолчанию после разбора
- Тулбар: Письмо · Буфер (Msg-ID) · Экспорт
- Фильтры по умолчанию: шум скрыт, «к разбору» и скрытие локальных IP включены
- Статусы/диалоги без наследия «извлечение IOC» / PDF/Office
- Класс `ExtractorApp` (alias `ReliquaryApp`); лог `email_ioc_extractor_error.log`

### CLI
- Primary: `reliquary` (alias `ioc-extractor` deprecated)
- Вердикт печатается в stderr по умолчанию
- Default stdout: `{verdict, iocs, errors}`

## 1.8.0

### CLI
- Пакетная папка / несколько файлов, `--workers`, skip broken по умолчанию
- Фильтры: `--actionable`, `--hide-rewriter|allowlisted|private`, `--only-denylisted`, `--search`, `--types`
- `--case-pack`, `--case-pack-multi`, `--ticket` (файл или `-`)

### GUI / архитектура
- Вынесены `FilterState`, `batch` runner, `export_actions`; единый `formats`
- Progress bar + ETA на пакетном разборе; колонка «Откуда» + 2×клик к фрагменту
- Prefs: `max_workers`, `skip_broken`

### Извлечение
- PPTX/PPTM и глубже DOCM/XLSM: текст + гиперссылки
- ZIP nest depth 4; явные ошибки «защищён паролем»
- Меньше RAM: payload вложений только nested email / мелкие (<2 МБ), large nested сбрасывается после разбора
- Тихие сбои OLE/QR/prefs чаще попадают в `result.errors`

### Качество
- CI: ruff + mypy (core) + pytest
- Тесты: filters, batch, pptx, CLI, nested zip sample

## 1.7.0

### GUI
- Таблица IOC (тип / значение / теги / файл) вместо текстового дампа
- Тулбар по шагам: Источник → Буфер → Экспорт
- Фильтры: **Скрыть шум** и **Фокус** с подсказками
- Чип «Фокус файла» со снятием в один клик
- Debounce поиска; параллельная обработка папки (до 4 потоков)
- Предупреждение при большом числе файлов в папке
- Prefs: геометрия окна, типы IOC, язык тикета, последний каталог экспорта

### Извлечение
- Меньше FP: GUID/однородный hex не считаются хешами
- Частные IP: CGNAT 100.64/10, IPv6 ULA/link-local
- Bitcoin: Base58Check / Bech32
- Command-line только при подозрительных флагах
