# IOC Extractor

**Extract. Normalize. Export.** · v1.7.1

Офлайн-приложение для извлечения IOC из писем, тикетов, PDF, HTML, Office и ZIP/7z/RAR.
Экспорт: CSV (UTF-8 BOM для Excel), STIX 2.1, JSON, MISP, OpenCTI, **YARA**, **Case pack**.

## GUI (удобство)

- Таблица IOC (тип / значение / теги / файл); клик копирует значение
- Контекстные вкладки со счётчиками; **Пакет** только при ≥2 файлах
- Поиск IOC (`Ctrl+F`), фильтры **Скрыть шум** / **Фокус** (к разбору, denylist)
- Тулбар: Источник → Буфер → Экспорт
- `Ctrl+C` / `Ctrl+Shift+C` — value / defanged; `1–6` — вкладки; `Ctrl+/−` — масштаб
- ПКМ по IOC: copy / defang / allowlist / denylist (+ комментарий тикета)
- **Тикет** полный/короткий (`ticket.ini`: ru/en); клик в **Пакет** → фокус файла
- Case pack и **Case pack (по файлам)**; Стоп / Повтор failed в статус-баре
- Папка: параллельный разбор, предупреждение при большом числе файлов
- Prefs рядом с exe: `ui_prefs.json` (окно, папка, форматы, масштаб, фильтры, типы)

## Что извлекает

| Тип | Примеры |
|-----|---------|
| Сеть | IPv4/IPv6, `ip:port`, домены (широкие TLD / punycode), URL, email |
| Хеши | MD5, SHA1, SHA256 (в т.ч. вложений; GUID/однородный hex отсекаются) |
| Host | Windows-пути, UNC, registry, mutex, `command_line` (с сигналами) |
| Crypto / IM | Bitcoin (checksum), Monero, Telegram, Discord |
| Прочее | CVE, имена вложений / членов ZIP (в т.ч. вложенные), QR (опционально) |

Письма (`.eml` / `.msg`): тело, URL rewrite, вложения (в т.ч. вложенные `.eml`/`.msg`, OLE-потоки),
карточка identity, **вердикт triage** (`verdict.ini`), сырые заголовки.
Пакет файлов — вкладка **Пакет** (файл → вердикт → топ IOC → ошибки).

Шум (фильтр **Скрыть шум**): теги `private`, `url_rewriter`, `allowlisted` —
галочка значит «убрать из списка». **Фокус**: `denylist.txt` → только denylisted;
«к разбору» (actionable) — без шума и «голых» имён файлов.
Списки рядом с exe: [`allowlist.txt`](allowlist.txt), [`denylist.txt`](denylist.txt),
[`verdict.ini`](verdict.ini), [`ticket.ini`](ticket.ini) (кнопка **Конфиги**).
Wildcards (`*.corp.local`) и комментарии `# INC-…`.
Импорт CSV / MISP JSON в списки — кнопка **Импорт списков**.

Опционально: `rarfile`+UnRAR для inventory RAR; `pyzbar` для QR.

## Быстрый старт (Windows)

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

run_gui.bat
```

При ошибке запуска смотрите `ioc_extractor_error.log` рядом с bat/exe.

## GUI

- Тулбар: **Источник** → **Буфер** → **Экспорт**
- Копирование: `type|value`, `value`, `csv`, **defanged**, **defanged|type**
- **Тикет** — шаблон handoff (`ticket.ini`); **Msg-ID** — Message-ID / campaign
- Фильтры: типы IOC; **Скрыть шум**; **Фокус**
- Вердикт писем — бейдж + вкладка **Письмо**; пакет — вкладка **Пакет**
- Горячие клавиши: `Ctrl+O`, `Ctrl+Enter`; клик по IOC копирует значение
- Экспорт **Case pack** (ZIP: JSON + CSV + ticket + вложения)

## Сборка EXE

```bash
pip install -r requirements.txt
pyinstaller build/reliquary.spec
```

`dist/IOC_Extractor.exe` — без консоли, **без UPX**.
Рядом с exe: `allowlist.txt`, `denylist.txt`, `verdict.ini`, `ticket.ini`.
Лог ошибок — `ioc_extractor_error.log`.

```powershell
.\build\sign_exe.ps1 -ExePath .\dist\IOC_Extractor.exe
```

## Структура

```
reliquary/
  core/          # парсеры, IOC, allowlist, экспорт, paths
  gui/           # desktop UI (app, ioc_table, tabs, tooltips)
samples/
allowlist.txt
denylist.txt
verdict.ini
ticket.ini
run_gui.bat
run_reliquary.py
build/sign_exe.ps1
CHANGELOG.md
```

## Лицензия

Внутренний инструмент SOC.
