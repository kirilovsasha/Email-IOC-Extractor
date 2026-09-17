# Reliquary

**Extract. Normalize. Decide.**

Офлайн-утилита для аналитика SOC: извлекает IOC из писем, тикетов, PDF/HTML,
нормализует в STIX 2.1 / CSV, разбирает почтовые заголовки, разворачивает URL rewrite,
оценивает вложения и выдаёт вердикт с рекомендуемыми действиями.

> Название: **Reliquary** — «хранилище реликвий». Инструмент вынимает цифровые
> артефакты угроз из сырых улик и складывает их в нормализованный вид для triage.

## Возможности

| Модуль | Что делает |
|--------|------------|
| IOC extractor | IP, домены, URL, email, MD5/SHA1/SHA256, CVE (с учётом defang `hxxp` / `[.]`) |
| Email headers | SPF/DKIM/DMARC, Reply-To/Return-Path mismatch, display-name spoof, Received hops |
| URL rewrite | SafeLinks, Proofpoint v2/v3, Mimecast, Barracuda, FireEye, generic `?url=` — **без сети** |
| Attachments | хеши, MIME, double extension, OLE/VBA, macro-enabled Office |
| Verdict | score + уровень (benign / suspicious / malicious / unknown) + playbook действий |
| Export | CSV, STIX 2.1 Bundle, полный JSON-отчёт |
| GUI | CustomTkinter-консоль для сменного triage |
| CLI | headless-режим для скриптов и CI |

**Сеть не используется.** Все проверки — локальные эвристики.

## Быстрый старт

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# GUI
python run_reliquary.py
# или
python -m reliquary

# CLI
python -m reliquary.cli samples/phishing_sample.eml --csv out.csv --stix out.json
python -m reliquary.cli -t "hxxps://evil[.]xyz/" -o
```

## Сборка EXE (PyInstaller)

На машине аналитика (обычно Windows):

```bash
pip install -r requirements.txt
pyinstaller build/reliquary.spec
```

Готовый бинарник: `dist/Reliquary.exe` (Windows) или `dist/Reliquary` (Linux).
Его можно копировать на изолированные рабочие места SOC — интернет не нужен.

## Структура

```
reliquary/
  core/          # парсеры, IOC, headers, URL unwrap, verdict, export
  gui/           # графический интерфейс
  cli.py         # консольный режим
samples/         # учебные артефакты
tests/           # pytest
build/reliquary.spec
```

## Вердикт — как читать

- **БЕЗОПАСНО** — явных red flags нет
- **НЕОДНОЗНАЧНО** — слабые сигналы, peer-review
- **ПОДОЗРИТЕЛЬНО** — есть признаки фишинга/spoofing/опасных вложений
- **ВРЕДОНОСНО** — высокая суммарная score-оценка; действовать по playbook во вкладке «Действия»

Эвристики не заменяют TIP/sandbox — это ускоритель первичного triage на air-gapped месте.

## Лицензия

Внутренний инструмент SOC. Адаптируйте под свои playbook'и.
