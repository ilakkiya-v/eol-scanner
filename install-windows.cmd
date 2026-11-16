@echo off
rem Double-click to install EOL Scanner (no admin needed). Add -WithBrowser for the headless-browser crawl.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\install-windows.ps1" %*
pause
