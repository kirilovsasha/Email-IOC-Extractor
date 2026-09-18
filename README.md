# IOC Extractor

**Extract. Normalize. Export.** · v1.5.0

Офлайн-приложение для извлечения IOC из писем, тикетов, PDF, HTML, Office и ZIP/7z/RAR.
Экспорт: CSV (UTF-8 BOM для Excel), STIX 2.1, JSON, MISP, OpenCTI, **YARA**, **Case pack**.

## Что извлекает

| Тип | Примеры |
|-----|---------|
| Сеть | IPv4/IPv6, `ip:port`, домены (широкие TLD / punycode), URL, email |
| Хеши | MD5, SHA1, SHA256 (в т.ч. вложений) |
| Host | Windows-пути, UNC, registry, mutex, `command_line` |
| Crypto / IM | Bitcoin, Monero, Telegram, Discord |
| Прочее | CVE, имена вложений / членов ZIP, QR из картинок (если доступен декодер) |

Письма (`.eml` / `.msg`): тело, URL rewrite, вложения (в т.ч. вложенные `.eml`/`.msg`, OLE-потоки),
карточка identity, **вердикт triage** (`verdict.ini`), сырые заголовки.
Пакет файлов — вкладка **Пакет** (файл → вердикт → топ IOC → ошибки).

Шум: теги `private`, `url_rewriter`, `allowlisted` — скрываются фильтрами в GUI.
`denylist.txt` → тег `denylisted` + фильтр «Только denylist».
Списки рядом с exe: [`allowlist.txt`](allowlist.txt), [`denylist.txt`](denylist.txt),
[`verdict.ini`](verdict.ini) (кнопка **Конфиги**). Wildcards (`*.corp.local`) и комментарии `# INC-…`.
Импорт CSV / MISP JSON в списки — кнопка **Импорт списков**.

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

- Компактный chrome: действия слева (открыть), справа (копировать / экспорт / тикет)
- Копирование: `type|value`, `value`, `csv`, **defanged**, **defanged|type**
- **Тикет** — шаблон handoff в буфер; **Msg-ID** — Message-ID / campaign
- Фильтры одной полосой; список IOC — главная область
- Вердикт писем — бейдж в шапке + вкладка **Письмо**; пакет — вкладка **Пакет**
- Горячие клавиши: `Ctrl+O`, `Ctrl+Enter`; клик по IOC копирует значение
- Папка рекурсивно, прогресс `N/M`, вкладка **Ошибки**
- Экспорт **Case pack** (ZIP: JSON + CSV + ticket + вложения)
- Дата обновления allow/deny в шапке

## Сборка EXE

```bash
pip install -r requirements.txt
pyinstaller build/reliquary.spec
```

`dist/IOC_Extractor.exe` — без консоли, **без UPX**, с FileDescription в свойствах.
Рядом с exe: `allowlist.txt`, `denylist.txt`, `verdict.ini`.
Лог ошибок — `ioc_extractor_error.log`.

Подпись Authenticode (рекомендуется для корпоративного AV):

```powershell
.\build\sign_exe.ps1 -ExePath .\dist\IOC_Extractor.exe
# или -PfxPath .\certs\code.pfx
```

## Структура

```
reliquary/
  core/          # парсеры, IOC, allowlist, экспорт, paths
  gui/           # desktop UI
samples/
allowlist.txt
denylist.txt
verdict.ini
run_gui.bat
run_reliquary.py
build/sign_exe.ps1
```

## Лицензия

Внутренний инструмент SOC.
