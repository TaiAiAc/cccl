@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "EXE=%~dp0src-tauri\target\release\ClaudeBall.exe"
if not exist "%EXE%" set "EXE=%~dp0ClaudeBall.exe"
if not exist "%EXE%" set "EXE=%~dp0src-tauri\target\debug\ClaudeBall.exe"

if not exist "%EXE%" (
  echo.
  echo   ClaudeBall.exe not found.
  echo   Build it first:
  echo       npm install
  echo       npm run build
  echo   The exe lands in src-tauri\target\release\
  echo.
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%EXE%' -Verb RunAs"
exit /b 0
