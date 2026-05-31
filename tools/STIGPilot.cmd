@echo off
:: STIGPilot Government Mode Launcher
:: Runs STIGPilot-Gov.ps1 with process-scoped execution policy bypass
:: Usage: STIGPilot.cmd -Command packet -Old old.xml -New new.xml -OutDir output\packet

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0STIGPilot-Gov.ps1" %*
