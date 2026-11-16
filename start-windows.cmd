@echo off
rem Double-click to start EOL Scanner on http://127.0.0.1:8080 (close this window or press Ctrl+C to stop).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-windows.ps1" %*
pause
