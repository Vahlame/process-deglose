@echo off
setlocal
title Process inventory snapshot (no admin)
cd /d "%~dp0"

set "PS64=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS64%" (
  echo ERROR: Windows PowerShell not found at %PS64%
  pause
  exit /b 1
)

echo Running without Administrator. Session-0 command lines and some owners may be blank.
"%PS64%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0snapshot.ps1"
set "ERR=%ERRORLEVEL%"
echo.
if not "%ERR%"=="0" (
  echo Snapshot exited with code %ERR%.
)
pause
exit /b %ERR%
