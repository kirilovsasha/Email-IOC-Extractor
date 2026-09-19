#!/usr/bin/env bash
# Build Email IOC Extractor binary with PyInstaller (run on target OS, usually Windows).
set -euo pipefail
cd "$(dirname "$0")/.."
pip install -r requirements.txt pyinstaller
python build/sync_version_info.py
python -m PyInstaller build/reliquary.spec --noconfirm
echo "Artifact: dist/EmailIOCExtractor (or dist/EmailIOCExtractor.exe on Windows)"
echo "Optional Authenticode signing: build/sign_exe.ps1 -ExePath dist\\EmailIOCExtractor.exe"
echo "Extras: pip install '.[rar,qr]' before build for RAR/QR support (optional; not in lite EXE)."
