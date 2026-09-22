# Org profile pack

Положите эту папку рядом с exe как `org_profile/` или укажите prefs `profile_dir` / CLI на папку или `.zip`. Файлы — локальные overrides без пересборки.

## Файлы

| Файл | Назначение |
|------|------------|
| `allowlist_extra.txt` | Доп. allowlist хостов/доменов (по строке). Мержится со встроенным. |
| `verdict_extra.json` | Пороги/веса/caps `VerdictConfig`. См. [`docs/TUNING.md`](../docs/TUNING.md). |
| `handoff_extra.txt` | Шаблон ITSM handoff по умолчанию. |
| `handoff_{level}.txt` | Handoff по уровню (`malicious` / `suspicious` / `unknown` / `benign`). |
| `brands.txt` | Бренды для lookalike. |

## Готовые пресеты

| Пресет | Путь | Фокус |
|--------|------|--------|
| Microsoft 365 | [`m365/`](m365/) | SafeLinks / Outlook / Graph / CDN |
| Google Workspace | [`google/`](google/) | Google mail / Drive / CDN |
| Banking / finance | [`banking/`](banking/) | Жёстче пороги + банк-бренды |
| ProxySG / Blue Coat | [`proxysg/`](proxysg/) | rewrite-шум SG, корпоративный proxy |
| Kaspersky | [`kaspersky/`](kaspersky/) | KL click-wrap + RU-бренды |
| Dr.Web | [`drweb/`](drweb/) | Dr.Web link wrap |
| Local MX | [`local_mx/`](local_mx/) | Внутренний MX, сильнее mitigations |
| RU mail stack | [`ru_mail/`](ru_mail/) | Mail.ru/Yandex/VK unwrap + RU brands |
| RU bank / gov | [`ru_gov/`](ru_gov/) | ФНС/ЦБ/Почта/Госуслуги brands + веса spoof/cloud |
| Belarus bank / gov | [`by_gov/`](by_gov/) | Беларусбанк/МНС/ЕРИП/portal.gov.by + веса spoof/BEC |
| Kazakhstan bank / gov | [`kz_gov/`](kz_gov/) | Kaspi/Halyk/egov.kz + messenger/QR lure |
| Ukraine bank / gov | [`ua_gov/`](ua_gov/) | Privat/Monobank/Diia + remote template / polyglot |

Скопируйте пресет в `org_profile/` рядом с exe или: `reliquary mail.eml --profile org_profile.example/m365`

## Порядок шаблонов handoff

1. Явный `handoff_template_path` (CLI / prefs), если задан.
2. Запись из `handoff_by_level` (profile pack).
3. `handoff_{level}.txt` рядом с приложением или в профиле.
4. `handoff_extra.txt`.
5. Встроенный компактный блок.

Примеры в корне: `allowlist_extra.example.txt`, `verdict_extra.example.json`, `handoff_extra.example.txt`, `handoff_malicious.example.txt`.

## Zip-пакеты

В `.zip` файлы могут лежать в корне архива или в одной верхней папке.
