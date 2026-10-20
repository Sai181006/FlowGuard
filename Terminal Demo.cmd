@echo off
setlocal
cd /d "%~dp0"
title FlowGuard - Terminal Demonstration
call scripts\python-windows.cmd demo\terminal.py --step
echo.
pause
endlocal
