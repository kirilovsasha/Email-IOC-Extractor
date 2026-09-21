# Packaging / fleet deploy

## Current ship form

CI publishes **Lite** `EmailIOCExtractor.exe` + `.sha256` on `main` and on tag `v*`.
На теге `v*` в Release также публикуется **Full** `EmailIOCExtractor-Full.exe` (RAR/QR).

Локально Full:

```bat
build_exe.bat --full
```

или CI job `build-exe-full` (artifact на push в main).

## Silent / scripted copy

There is no MSI in-tree. Typical enterprise deploy:

1. Verify SHA256 (`docs/SIGNING.md`).
2. Authenticode-sign (`build/sign_exe.ps1`).
3. Copy EXE + optional `org_profile/` + prefs templates to a locked folder.
4. Optional winget private manifest pointing at an internal HTTPS URL of the signed EXE.

### Winget-style manifest sketch

```yaml
PackageIdentifier: SOC.EmailIOCExtractor
PackageVersion: 2.7.0
InstallerType: portable
Installers:
  - Architecture: x64
    InstallerUrl: https://internal.example/EmailIOCExtractor.exe
    InstallerSha256: <sha256>
```

Publish via your private winget source; do not rely on public winget for internal SOC tools.

## Offline version flag

Drop `update.json` next to the EXE (`{"latest":"2.7.0","notes":"..."}`). About dialog shows status — no network.
