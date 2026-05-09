@echo off
REM Single official entry point (CMD shim around setup.ps1).
REM Forwards any flags (e.g. -NoStart, -SkipInstall) to the PowerShell script.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*
