#!/usr/bin/env bash
# Build Reliquary binary with PyInstaller (run on target OS, usually Windows).
set -euo pipefail
cd "$(dirname "$0")/.."
python -m pip install -r requirements.txt
python -m PyInstaller build/reliquary.spec --noconfirm
echo "Artifact: dist/Reliquary (or dist/Reliquary.exe on Windows)"
