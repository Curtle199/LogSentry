@echo off
setlocal
cd /d "%~dp0"

echo [1/4] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo Python was not found on PATH.
    echo Install Python 3.11+ and try again.
    pause
    exit /b 1
)

echo [2/4] Installing packaging tools...
python -m pip install --upgrade pip pyinstaller tkinterdnd2
if errorlevel 1 (
    echo Failed to install packaging dependencies.
    pause
    exit /b 1
)

echo [3/4] Building LogSentry...
python -m PyInstaller --noconfirm --clean LogSentry.spec
if errorlevel 1 (
    echo Build failed.
    pause
    exit /b 1
)

echo [4/4] Done.
echo Output folder: dist\LogSentry
pause
