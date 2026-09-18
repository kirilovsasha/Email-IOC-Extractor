# IOC Extractor

**Extract. Normalize. Export.** · v1.4.0

Офлайн-приложение для извлечения IOC из писем, тикетов, PDF, HTML, Office и ZIP.
Экспорт: CSV (UTF-8 BOM для Excel), STIX 2.1, JSON, MISP, OpenCTI, **YARA**.

## Что извлекает

| Тип | Примеры |
|-----|---------|
| Сеть | IPv4/IPv6, `ip:port`, домены (широкие TLD / punycode), URL, email |
| Хеши | MD5, SHA1, SHA256 (в т.ч. вложений) |
| Host | Windows-пути, UNC, registry, mutex, `command_line` |
| Crypto / IM | Bitcoin, Monero, Telegram, Discord |
| Прочее | CVE, имена вложений / членов ZIP |

Письма (`.eml` / `.msg`): тело, URL rewrite, вложения, карточка identity,
вердикт triage, сырые заголовки.

Шум: теги `private`, `url_rewriter`, `allowlisted` — скрываются фильтрами в GUI.
`denylist.txt` → тег `denylisted` + фильтр «Только denylist».
Списки рядом с exe: [`allowlist.txt`](allowlist.txt), [`denylist.txt`](denylist.txt)
(кнопка **Конфиги** в GUI).

## Быстрый старт (Windows)

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

run_gui.bat
```

При ошибке запуска смотрите `ioc_extractor_error.log` рядом с bat/exe.

CLI:

```bash
python -m reliquary.cli samples/ticket_sample.txt --csv out.csv --stix out.json
python -m reliquary.cli samples/phishing_sample.eml --iocs-only --phishing
python -m reliquary.cli samples/ticket_sample.txt --misp misp.json --yara rules.yar
```

## GUI

- Несколько файлов / папка **рекурсивно**, drag-and-drop
- Прогресс `N/M`, ошибки на отдельной вкладке (битый файл не валит пакет)
- Вердикт triage + рекомендуемые действия
- Клик по IOC → копировать; форматы `value` / `type|value` / `csv`
- Экспорт по кнопке (не при смене пункта меню)
- Фильтры: Сеть / Хеши / Хост / Крипто + шум / denylist

## Сборка EXE

```bash
pip install -r requirements.txt
pyinstaller build/reliquary.spec
```

`dist/IOC_Extractor.exe` — без консоли, **без UPX**, с FileDescription в свойствах.
Рядом с exe появятся/ожидаются `allowlist.txt` и `denylist.txt`.
Лог ошибок — `ioc_extractor_error.log`.

## Структура

```
reliquary/
  core/          # парсеры, IOC, allowlist, экспорт, paths
  gui/           # desktop UI
samples/
allowlist.txt
denylist.txt
run_gui.bat
run_reliquary.py
```

## Лицензия

Внутренний инструмент SOC.
