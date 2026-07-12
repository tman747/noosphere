@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\start_invitation_host.ps1"
if errorlevel 1 pause
