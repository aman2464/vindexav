import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent

# 1. Build the React dashboard first
print("[*] Compiling Dashboard assets...")
subprocess.run(["npm", "run", "build"], cwd=BASE / "dashboard", check=True)

# 2. Package with PyInstaller
print("[*] Creating executable binary...")
pyinstaller_args = [
    "pyinstaller",
    "--noconfirm",
    "--onedir",
    "--windowed",
    "--name", "VindexAV",
    "--add-data", f"{BASE / 'dashboard' / 'dist'}:dashboard/dist",
    "--add-data", f"{BASE / 'rules'}:rules",
    "--add-data", f"{BASE / 'signatures'}:signatures",
    "--add-data", f"{BASE / 'config.json'}:.",
    str(BASE / "server" / "main.py")
]

subprocess.run(pyinstaller_args, check=True)
print("[+] Build complete. Output available in dist/VindexAV")