@echo off
setlocal EnableExtensions
cd /d "%~dp0.."

echo ========================================
echo  Email IOC Extractor — Windows EXE build
echo ========================================
echo.

where python >nul 2>&1
if errorlevel 1 (
  echo [ERROR] python не найден в PATH.
  echo Установите Python 3.10+ или активируйте .venv
  exit /b 1
)

if exist ".venv\Scripts\python.exe" (
  set "PY=.venv\Scripts\python.exe"
  echo Using venv: %PY%
) else (
  set "PY=python"
  echo Using: python from PATH
)

echo.
echo [1/4] Dependencies (requirements + PyInstaller)...
"%PY%" -m pip install -U pip
if errorlevel 1 exit /b 1
"%PY%" -m pip install -r requirements.txt
if errorlevel 1 exit /b 1
"%PY%" -m pip install pyinstaller
if errorlevel 1 exit /b 1
"%PY%" -m pip install -e .
if errorlevel 1 exit /b 1

echo.
echo [2/4] Sync version_info.txt...
"%PY%" build\sync_version_info.py
if errorlevel 1 exit /b 1

echo.
echo [3/4] PyInstaller...
"%PY%" -m PyInstaller build\reliquary.spec --noconfirm
if errorlevel 1 (
  echo [ERROR] PyInstaller failed
  exit /b 1
)

if not exist "dist\EmailIOCExtractor.exe" (
  echo [ERROR] dist\EmailIOCExtractor.exe not found
  dir /s /b dist 2>nul
  exit /b 1
)

echo.
echo [4/4] SHA256...
powershell -NoProfile -Command ^
  "$h=(Get-FileHash 'dist\EmailIOCExtractor.exe' -Algorithm SHA256).Hash.ToLower();" ^
  "Set-Content -Encoding ascii 'dist\EmailIOCExtractor.exe.sha256' ('{0}  EmailIOCExtractor.exe' -f $h);" ^
  "Get-Content 'dist\EmailIOCExtractor.exe.sha256'"

echo.
echo ========================================
echo  OK  dist\EmailIOCExtractor.exe
echo  OK  dist\EmailIOCExtractor.exe.sha256
echo ========================================
echo.
echo Optional signing:
echo   powershell -File build\sign_exe.ps1 -ExePath dist\EmailIOCExtractor.exe
echo.
exit /b 0
