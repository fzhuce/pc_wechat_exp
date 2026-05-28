@echo off
chcp 65001 >nul
setlocal

echo.
echo ============================================================
echo   WeChat EXP - PyInstaller Build Script (Optimized)
echo ============================================================
echo.

set VENV=%~dp0build_venv\Scripts
set PYTHON=%VENV%\python.exe
set PIP=%VENV%\pip.exe

if not exist "%PYTHON%" (
    echo [!] Build venv not found, creating...
    python -m venv "%~dp0build_venv"
    "%PIP%" install --upgrade pip
    "%PIP%" install -r "%~dp0requirements-build.txt"
)

echo [*] Installing/updating dependencies...
"%PIP%" install -r "%~dp0requirements-build.txt"

echo.
echo [*] Downloading Whisper model for offline voice transcription...
"%PYTHON%" "%~dp0scripts\download_whisper_model.py"
if %errorlevel% neq 0 (
    echo [!] Model download failed — continuing build (voice transcription will use CDN fallback)
)

echo.
echo [*] Cleaning previous build and stray config files...
if exist "%~dp0build" rmdir /s /q "%~dp0build"
if exist "%~dp0dist" rmdir /s /q "%~dp0dist"
:: Remove .wechat_exp_config.json from src/ so it won't be bundled into the exe
if exist "%~dp0src\.wechat_exp_config.json" del /q "%~dp0src\.wechat_exp_config.json"

echo.
echo [*] Building...
echo.

"%PYTHON%" -m PyInstaller ^
    --onefile ^
    --console ^
    --name wechat_exp ^
    --add-data "src;src" ^
    --add-data "tools\silk_decoder.exe;tools" ^
    --add-data "tools\silk_decoder.c;tools" ^
    --hidden-import Crypto.Cipher.AES ^
    --hidden-import Crypto.Util.Padding ^
    --hidden-import flask ^
    --hidden-import werkzeug ^
    --hidden-import jinja2 ^
    --hidden-import blackboxprotobuf ^
    --hidden-import zstandard ^
    --hidden-import openpyxl ^
    --hidden-import jieba ^
    --hidden-import jieba.posseg ^
    --hidden-import requests ^
    --hidden-import pypinyin ^
    --collect-all jieba ^
    --exclude-module pytest ^
    --exclude-module _pytest ^
    --exclude-module tkinter ^
    --exclude-module _tkinter ^
    --exclude-module turtle ^
    --exclude-module idlelib ^
    --exclude-module ensurepip ^
    --exclude-module pip ^
    --exclude-module setuptools ^
    --exclude-module wheel ^
    --exclude-module pkg_resources ^
    --exclude-module multiprocessing ^
    --exclude-module concurrent.futures.process ^
    --exclude-module lib2to3 ^
    --exclude-module xmlrpc ^
    --exclude-module pydoc ^
    --exclude-module doctest ^
    --exclude-module bdb ^
    --strip ^
    "%~dp0src\main.py"

echo.
echo ============================================================
echo   Build complete!
echo   Output: dist\wechat_exp.exe
echo ============================================================

:: Show file size
for %%F in ("%~dp0dist\wechat_exp.exe") do (
    set /a SIZE=%%~zF
    echo   Size: !SIZE! bytes
)

pause
