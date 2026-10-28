#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== [VindexAV Deployment Engine - Kali/Unix] ==="

# 1. Setup Python Virtual Environment
if [ ! -d ".venv" ]; then
    echo "[*] Initializing virtual environment in .venv..."
    python3 -m venv .venv
fi

source .venv/bin/activate
echo "[*] Upgrading pip and installing requirements..."
pip install --upgrade pip
pip install -r requirements.txt

# 2. Build Dashboard Frontend
if [ -d "dashboard" ]; then
    echo "[*] Building React/Vite dashboard..."
    cd dashboard
    if [ ! -d "node_modules" ]; then
        npm install
    fi
    npm run build
    cd "$SCRIPT_DIR"
fi

# 3. Initialize fixtures and folders
python3 make_test_files.py

echo "[*] Launching VindexAV Core Engine on http://127.0.0.1:8000 ..."
exec uvicorn server.main:app --host 127.0.0.1 --port 8000