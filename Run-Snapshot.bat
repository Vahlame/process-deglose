@echo off
setlocal
title Process inventory snapshot
cd /d "%~dp0"

net session >nul 2>&1
if not %errorLevel%==0 (
  echo Requesting Administrator so hidden/session-0 and other-user process data can be read...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set "PS64=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS64%" (
  echo ERROR: Windows PowerShell not found at %PS64%
  pause
  exit /b 1
)

"%PS64%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0snapshot.ps1"
set "ERR=%ERRORLEVEL%"
echo.
if not "%ERR%"=="0" (
  echo Snapshot exited with code %ERR%.
)
pause
exit /b %ERR%
