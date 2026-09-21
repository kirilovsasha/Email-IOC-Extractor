# Упаковка и выкладка на флот

## Что публикуется

CI публикует **Lite** `EmailIOCExtractor.exe` + `.sha256` на `main` и на тег `v*`.
На теге `v*` в Release также публикуется **Full** `EmailIOCExtractor-Full.exe` (RAR/QR).

Локально Full:

```bat
build_exe.bat --full
```

или CI job `build-exe-full` (артефакт на push в main).

## Деплой без MSI

В дереве нет MSI. Типичная выкладка SOC:

1. Проверить SHA256 (`docs/SIGNING.md`).
2. Подписать Authenticode (`build/sign_exe.ps1` или секреты CI).
3. Скопировать EXE + опционально `org_profile.zip` / prefs в защищённую папку.
4. Для Full: положить `UnRAR.exe` рядом с EXE (иначе RAR inventory недоступен —
   self-check предупредит, вердикт поднимет `unrar_missing`).
5. Опционально скопировать `docs/ANALYST_RU.md` рядом с EXE (или он уже внутри сборки).
6. Опционально — private winget-манифест на внутренний HTTPS URL подписанного EXE.

### Эскиз winget-манифеста

```yaml
PackageIdentifier: SOC.EmailIOCExtractor
PackageVersion: 2.12.0
InstallerType: portable
Installers:
  - Architecture: x64
    InstallerUrl: https://internal.example/EmailIOCExtractor.exe
    InstallerSha256: <sha256>
```

Публикуйте через свой private winget source; на публичный winget для SOC не опирайтесь.

## Офлайн-флаг версии

Положите `update.json` рядом с EXE (`{"latest":"2.12.0","notes":"..."}`).
Диалог «О программе» покажет статус — без сети.

Предпочтительно один файл **`org_profile.zip`** рядом с EXE (подхватывается автоматически);
папка `org_profile/` тоже работает.

Опциональная CI-подпись: секреты `SIGNING_PFX_BASE64` и `SIGNING_PFX_PASSWORD`.
