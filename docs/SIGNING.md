# Authenticode-подпись (Windows)

Релизы из CI по умолчанию **без подписи**. SmartScreen / AV могут предупреждать,
пока корпоративный SoftCert / EV не подпишет бинарник.

Опциональная подпись в CI уже поддержана: секреты `SIGNING_PFX_BASE64` и
`SIGNING_PFX_PASSWORD` — job `release` вызывает `build/sign_exe.ps1` для Lite+Full.

## Проверка перед выкладкой

1. Скачайте `EmailIOCExtractor.exe` и `EmailIOCExtractor.exe.sha256`.
2. Сверьте хеш:

```powershell
Get-FileHash .\EmailIOCExtractor.exe -Algorithm SHA256
Get-Content .\EmailIOCExtractor.exe.sha256
```

## Локальная подпись

```powershell
powershell -File build\sign_exe.ps1 -ExePath dist\EmailIOCExtractor.exe
# или с PFX:
powershell -File build\sign_exe.ps1 -ExePath dist\EmailIOCExtractor.exe `
  -PfxPath .\certs\soc.pfx -PfxPassword (Read-Host -AsSecureString)
```

Нужен Windows SDK `signtool.exe`. Сертификаты в репозиторий не класть.

## Чеклист air-gap флота

1. SHA256 совпал.
2. Authenticode (локально или CI).
3. Выбрать **Lite** или **Full** (`EmailIOCExtractor-Full.exe` + UnRAR.exe рядом при RAR).
4. Рядом с EXE: `org_profile.zip` (или `org_profile/`), опционально `verdict_extra.json`, `allowlist_extra.txt`, `ui_prefs.json`.
5. `update.json` с `{"latest":"…"}` для локального баннера версии (без сети).
