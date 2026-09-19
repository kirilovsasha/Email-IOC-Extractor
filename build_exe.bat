@echo off
REM Convenience wrapper — same as build\build.bat
cd /d "%~dp0"
call "%~dp0build\build.bat" %*
exit /b %ERRORLEVEL%
