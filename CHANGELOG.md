# Changelog

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
- Messenger URL не дублируется как отдельный URL
- Вложенные ZIP: inventory на 2 уровня глубины

### Производительность
- Файл читается один раз (hash + parse)
- Лимиты PDF (80 стр.) и текста (~2M символов)

### Конфиг
- `ticket.ini` — язык ru/en и подписи шаблона тикета

### Прочее
- STIX-паттерны для mutex / registry / cmdline / crypto
- Модули GUI: `tabs`, `tooltips`, `ioc_table`
- Тесты: FP-регрессии, nested zip, HTML sample

## 1.6.0

- Case pack, фильтры actionable/denylist, пакетная вкладка, prefs
