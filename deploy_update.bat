@echo off
REM Run this as Administrator (right-click -> Run as administrator)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy_update.ps1"
pause
