# Reliquary

**IOC. Normalize. Export.**

Офлайн-утилита для аналитика SOC. **Главная задача** — извлечь IOC из писем,
тикетов, PDF/HTML и нормализовать их в STIX 2.1 / CSV.

Проверка письма на фишинг (заголовки, вердикт, рекомендации) — **дополнительный**
модуль: включается автоматически для `.eml`/`.msg`, но не перекрывает работу с IOC.

> **Reliquary** — «хранилище реликвий»: вынимает цифровые артефакты угроз
> из сырых улик и складывает в нормализованный вид.

## Ядро (основное)

| Модуль | Что делает |
|--------|------------|
| **IOC extractor** | IP, домены, URL, email, MD5/SHA1/SHA256, CVE (с учётом defang `hxxp` / `[.]`) |
| **URL rewrite** | SafeLinks, Proofpoint v2/v3, Mimecast, Barracuda, FireEye — разворот **без сети**, чтобы в экспорт попал реальный URL |
| **Attachments** | имя, MIME, MD5/SHA1/SHA256 вложений как IOC |
| **Export** | CSV, STIX 2.1 Bundle, полный JSON |

## Дополнительно (фишинг / письмо)

| Модуль | Что делает |
|--------|------------|
| Email headers | SPF/DKIM/DMARC, Reply-To / Return-Path mismatch, display-name spoof |
| Attachment risk | double extension, OLE/VBA heuristics |
| Verdict | эвристический score + рекомендуемые действия (не замена TIP/sandbox) |

**Сеть не используется.** Все проверки — локальные.

## Быстрый старт

```bash
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt

# GUI — акцент на IOC
python run_reliquary.py

# CLI — по умолчанию печатает сводку IOC; --phishing добавляет вердикт
python -m reliquary.cli samples/ticket_sample.txt --csv out.csv --stix out.json
python -m reliquary.cli samples/phishing_sample.eml --phishing
```

## Сборка EXE (PyInstaller)

```bash
pip install -r requirements.txt
pyinstaller build/reliquary.spec
```

`dist/Reliquary.exe` можно копировать на air-gapped рабочие места SOC.

## Структура

```
reliquary/
  core/          # IOC, parsers, URL unwrap, export (+ optional phishing)
  gui/           # GUI: IOC на первом плане
  cli.py
samples/
tests/
build/reliquary.spec
```

## Лицензия

Внутренний инструмент SOC. Адаптируйте под свои playbook'и.
