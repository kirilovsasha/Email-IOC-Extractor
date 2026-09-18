#!/usr/bin/env bash
# Build IOC Extractor binary with PyInstaller (run on target OS, usually Windows).
set -euo pipefail
cd "$(dirname "$0")/.."
pip install -r requirements.txt pyinstaller
python -m PyInstaller build/reliquary.spec --noconfirm
echo "Artifact: dist/IOC_Extractor (or dist/IOC_Extractor.exe on Windows)"
echo "Place/edit allowlist.txt, denylist.txt and verdict.ini next to the exe."
echo "Optional Authenticode signing: build/sign_exe.ps1 -ExePath dist\\IOC_Extractor.exe"
