#Requires -Version 5.1
<#
.SYNOPSIS
  Authenticode-sign EmailIOCExtractor.exe for corporate SoftCert / EV cert.

.DESCRIPTION
  PyInstaller binaries without a signature are often blocked by SmartScreen / AV.
  Run this on the Windows build host after pyinstaller, with a code-signing cert
  in the CurrentUser or LocalMachine "My" store (or via PFX).

.EXAMPLE
  .\build\sign_exe.ps1 -ExePath .\dist\EmailIOCExtractor.exe

.EXAMPLE
  .\build\sign_exe.ps1 -ExePath .\dist\EmailIOCExtractor.exe -PfxPath .\certs\soc.pfx -PfxPassword (Read-Host -AsSecureString)
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$ExePath,

  [string]$CertThumbprint = "",
  [string]$PfxPath = "",
  [SecureString]$PfxPassword,
  [string]$TimestampUrl = "http://timestamp.digicert.com",
  [string]$Description = "Email IOC Extractor — offline email triage with phishing verdict"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $ExePath)) {
  throw "EXE not found: $ExePath"
}

$signtool = @(
  "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
  "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
) | Get-Item -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1

if (-not $signtool) {
  throw "signtool.exe not found. Install Windows SDK Signing Tools."
}

$args = @("sign", "/fd", "SHA256", "/td", "SHA256", "/tr", $TimestampUrl, "/d", $Description)

if ($PfxPath) {
  if (-not (Test-Path -LiteralPath $PfxPath)) { throw "PFX not found: $PfxPath" }
  $args += @("/f", $PfxPath)
  if ($PfxPassword) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword)
    try {
      $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
      $args += @("/p", $plain)
    } finally {
      [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
  }
} elseif ($CertThumbprint) {
  $args += @("/sha1", $CertThumbprint)
} else {
  # Pick first code-signing cert from CurrentUser\My
  $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if (-not $cert) {
    throw "No code-signing certificate found. Pass -CertThumbprint or -PfxPath."
  }
  $args += @("/sha1", $cert.Thumbprint)
  Write-Host "Using cert: $($cert.Subject) [$($cert.Thumbprint)]"
}

$args += $ExePath
Write-Host "Running: $($signtool.FullName) $($args -join ' ')"
& $signtool.FullName @args
if ($LASTEXITCODE -ne 0) { throw "signtool failed with exit $LASTEXITCODE" }

Get-AuthenticodeSignature -FilePath $ExePath | Format-List Status, SignerCertificate, TimeStamperCertificate
Write-Host "Signed OK: $ExePath"
