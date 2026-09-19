@echo off
cd /d "%~dp0"

set "LOG=%~dp0email_ioc_extractor_error.log"
set "PYW="
set "PY="

if exist "%~dp0.venv\Scripts\pythonw.exe" (
  set "PYW=%~dp0.venv\Scripts\pythonw.exe"
  set "PY=%~dp0.venv\Scripts\python.exe"
)
if not defined PYW if exist "%LocalAppData%\Python\bin\pythonw.exe" (
  set "PYW=%LocalAppData%\Python\bin\pythonw.exe"
  set "PY=%LocalAppData%\Python\bin\python.exe"
)

if not defined PYW (
  for /f "delims=" %%i in ('where pythonw.exe 2^>nul') do (
    echo %%i | find /i "WindowsApps" >nul
    if errorlevel 1 (
      set "PYW=%%i"
      goto :have_pyw
    )
  )
)

:have_pyw
if not defined PYW (
  echo [Email IOC Extractor] pythonw.exe не найден.
  echo Создайте .venv или установите Python с python.org
  pause
  exit /b 1
)

REM Smoke-import with console python; on failure show log
if defined PY (
  "%PY%" -c "from reliquary.gui.app import run" 1>nul 2>"%LOG%"
  if errorlevel 1 (
    echo [Email IOC Extractor] Ошибка запуска. См. email_ioc_extractor_error.log
    type "%LOG%"
    pause
    exit /b 1
  )
  del "%LOG%" >nul 2>&1
)

start "" "%PYW%" "%~dp0run_reliquary.py"
exit /b 0
