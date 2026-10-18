@echo off
setlocal
cd /d "%~dp0"
set "CHAOS_PYTHON=%~dp0.venv\Scripts\python.exe"
if exist "%CHAOS_PYTHON%" goto run
set "CHAOS_PYTHON=%USERPROFILE%\chaos_encryption_cloudflare\.venv\Scripts\python.exe"
if exist "%CHAOS_PYTHON%" goto run
py -3 app.py --role %1
if errorlevel 1 pause
exit /b
:run
"%CHAOS_PYTHON%" app.py --role %1
if errorlevel 1 pause
