@echo off
setlocal enabledelayedexpansion

echo === [VindexAV Deployment Engine - Windows] ===

cd /d "%~dp0"

IF NOT EXIST ".venv" (
    echo [*] Initializing virtual environment...
    python -m venv .venv
)

call .venv\Scripts\activate.bat
echo [*] Installing Python requirements...
python -m pip install --upgrade pip
pip install -r requirements.txt

IF EXIST "dashboard" (
    echo [*] Building React dashboard...
    cd dashboard
    IF NOT EXIST "node_modules" (
        call npm install
    )
    call npm run build
    cd ..
)

python make_test_files.py

echo [*] Launching VindexAV Core Engine on http://127.0.0.1:8000 ...
uvicorn server.main:app --host 127.0.0.1 --port 8000
pause