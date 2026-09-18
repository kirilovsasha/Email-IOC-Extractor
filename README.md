# IOC Extractor

**Extract. Normalize. Export.** · v1.8.0

Офлайн-приложение для извлечения IOC из писем, тикетов, PDF, HTML, Office (в т.ч. PPTX/macro) и ZIP/7z/RAR.
Экспорт: CSV (UTF-8 BOM), STIX 2.1, JSON, MISP, OpenCTI, YARA, Case pack.

## Быстрый старт (Windows)

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

run_gui.bat
```

CLI:

```bash
ioc-extractor mail.eml --csv out.csv --actionable
ioc-extractor ./inbox --case-pack case.zip --workers 4
ioc-extractor ticket.txt --ticket - --hide-rewriter
```

При ошибке запуска смотрите `ioc_extractor_error.log` рядом с bat/exe.

## GUI

| Шаг | Действие |
|-----|----------|
| Источник | Файл / папка / буфер / drag-drop |
| Таблица IOC | тип · значение · теги · файл · **откуда**; клик = copy, 2×клик = к фрагменту |
| Фильтры | Скрыть шум (прокси/allowlist/private) · Фокус (denylist / к разбору) · Ctrl+F |
| Экспорт | CSV / STIX / JSON / MISP / OpenCTI / YARA / Case pack |

**Горячие клавиши:** `Ctrl+O` файл · `Ctrl+Enter` извлечь · `Ctrl+C` / `Ctrl+Shift+C` value / defanged · `1–6` вкладки · `Ctrl+F` поиск · `Ctrl+/−` масштаб.

Prefs рядом с exe: `ui_prefs.json` (`max_workers`, `skip_broken`, фильтры, геометрия).
Конфиги: `allowlist.txt`, `denylist.txt`, `verdict.ini`, `ticket.ini`.

Пакетный разбор: progress bar + ETA, Стоп / Повтор failed; битые файлы пропускаются по умолчанию.

## Что извлекает

| Тип | Примеры |
|-----|---------|
| Сеть | IPv4/IPv6, `ip:port`, домены (широкие TLD / punycode), URL, email |
| Хеши | MD5, SHA1, SHA256 (GUID/однородный hex отсекаются) |
| Host | Windows-пути, UNC, registry, mutex, `command_line` |
| Crypto / IM | Bitcoin (checksum), Monero, Telegram, Discord |
| Прочее | CVE, имена вложений / членов ZIP, QR (опционально) |

Письма (`.eml` / `.msg`): тело, URL rewrite, вложения (вложенные `.eml`/`.msg`, OLE), вердикт triage, сырые заголовки.
Office: `.docx/.docm`, `.xlsx/.xlsm`, `.pptx/.pptm` — текст и гиперссылки.
Архивы: inventory до 4 уровней вложенности ZIP; парольные помечаются явно в ошибках/вердикте.

Единый каталог форматов: `reliquary.core.formats` (GUI + CLI + parser).

## Сборка EXE

```bash
pip install -r requirements.txt
pyinstaller build/reliquary.spec
```

`dist/IOC_Extractor.exe` — без консоли, без UPX. Рядом: списки и ini. Лог — `ioc_extractor_error.log`.

## Структура

```
reliquary/
  core/     # pipeline, IOC, formats, batch, filter_state, office, export
  gui/      # app + ioc_table, tabs, export_actions, batch_runner re-exports
samples/
tests/
```

## Лицензия

Внутренний инструмент SOC.
