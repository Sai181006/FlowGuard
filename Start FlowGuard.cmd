@echo off
setlocal
cd /d "%~dp0"
call scripts\python-windows.cmd demo\launch.py
if errorlevel 1 pause
endlocal
