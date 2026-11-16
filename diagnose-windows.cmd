@echo off
rem Double-click to check why EOL Scanner can't be reached. Changes nothing.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\diagnose-windows.ps1" %*
pause
