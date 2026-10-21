@echo off
setlocal
set "PYTHONUTF8=1"
rem Use a Windows interpreter, never the macOS/Linux virtual environment.
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,12) else 1)" >nul 2>&1
if not errorlevel 1 (
  py -3 %*
  exit /b
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3,12) else 1)" >nul 2>&1
if not errorlevel 1 (
  python %*
  exit /b
)
echo Python 3.12 or newer was not found. Install Python for Windows before going offline.
echo Then reopen this launcher. No pip packages or Linux installation are needed.
exit /b 1
