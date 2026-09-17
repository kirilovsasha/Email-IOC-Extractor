# Reliquary

**Extract. Normalize. Export.**

Офлайн-приложение для извлечения IOC из писем, тикетов, PDF и HTML.
Экспорт: CSV, STIX 2.1, JSON, MISP, OpenCTI, **YARA**.

## Что извлекает

| Тип | Примеры |
|-----|---------|
| Сеть | IPv4/IPv6, `ip:port`, домены (в т.ч. punycode), URL, email |
| Хеши | MD5, SHA1, SHA256 (в т.ч. вложений) |
| Host | Windows-пути, UNC, registry, mutex, `command_line` |
| Crypto / IM | Bitcoin, Monero, Telegram, Discord |
| Прочее | CVE, имена вложений |

Письма (`.eml` / `.msg`): тело, URL rewrite, вложения, карточка identity
(From / Return-Path / SPF·DKIM·DMARC / hops), сырые заголовки.

Шум: теги `private`, `url_rewriter`, `allowlisted` — скрываются фильтрами в GUI.
Свои списки: [`allowlist.txt`](allowlist.txt), [`denylist.txt`](denylist.txt).

## Быстрый старт (Windows)

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

run_gui.bat
```

При ошибке запуска смотрите `reliquary_error.log` рядом с bat.

CLI:

```bash
python -m reliquary.cli samples/ticket_sample.txt --csv out.csv --stix out.json
python -m reliquary.cli samples/phishing_sample.eml --iocs-only
```

## GUI

- Открыть несколько файлов / папку, drag-and-drop
- Фильтры: Сеть / Хеши / Хост / Крипто + скрытие private / rewriter / allowlist
- Копировать IOC, сохранить вложения
- Экспорт: CSV · STIX · JSON · MISP · OpenCTI · YARA

## Сборка EXE

```bash
pip install -r requirements.txt
pyinstaller build/reliquary.spec
```

`dist/Reliquary.exe` — без консоли; лог ошибок — `reliquary_error.log` рядом с exe.

## Структура

```
reliquary/
  core/          # парсеры, IOC, allowlist, экспорт
  gui/           # desktop UI
samples/
allowlist.txt
denylist.txt
run_gui.bat
run_reliquary.py
```

## Лицензия

Внутренний инструмент SOC.
