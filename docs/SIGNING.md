# Authenticode signing (Windows)

Releases from CI are **unsigned** by default. SmartScreen / AV may warn until a
corporate SoftCert / EV certificate signs the binary.

## Verify before deploy

1. Download `EmailIOCExtractor.exe` and `EmailIOCExtractor.exe.sha256`.
2. Confirm the hash:

```powershell
Get-FileHash .\EmailIOCExtractor.exe -Algorithm SHA256
Get-Content .\EmailIOCExtractor.exe.sha256
```

## Sign locally

```powershell
powershell -File build\sign_exe.ps1 -ExePath dist\EmailIOCExtractor.exe
# or with a PFX:
powershell -File build\sign_exe.ps1 -ExePath dist\EmailIOCExtractor.exe `
  -PfxPath .\certs\soc.pfx -PfxPassword (Read-Host -AsSecureString)
```

Requires Windows SDK `signtool.exe`.

## Optional CI signing

Wire organization secrets (e.g. `SIGNING_PFX_BASE64`, `SIGNING_PFX_PASSWORD`) and
call `build/sign_exe.ps1` after PyInstaller in the `release` job. Do not commit
certificates. Until that exists, publish SHA256 and sign on a locked-down build
host before fleet deployment.
