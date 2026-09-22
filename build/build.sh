#!/usr/bin/env bash
# Build Email IOC Extractor binary with PyInstaller (run on target OS, usually Windows).
# Default = Full (RAR/QR). Pass --lite for a smaller build without extras.
set -euo pipefail
cd "$(dirname "$0")/.."
FULL=1
if [[ "${1:-}" == "--lite" ]]; then
  FULL=0
  shift
elif [[ "${1:-}" == "--full" ]]; then
  # kept for compatibility; Full is already the default
  FULL=1
  shift
fi
pip install -r requirements.txt pyinstaller
pip install -e .
if [[ "$FULL" -eq 1 ]]; then
  pip install -e ".[rar,qr]"
  export RELIQUARY_FULL=1
  echo "Full build (default): rar + qr"
else
  echo "Lite build: no rar/qr extras"
fi
python build/sync_version_info.py
python -m PyInstaller build/reliquary.spec --noconfirm
if [[ -f dist/EmailIOCExtractor.exe ]]; then
  ART=dist/EmailIOCExtractor.exe
elif [[ -f dist/EmailIOCExtractor ]]; then
  ART=dist/EmailIOCExtractor
else
  echo "ERROR: artifact not found under dist/" >&2
  exit 1
fi
python - <<PY
from pathlib import Path
import hashlib
art = Path("${ART}")
digest = hashlib.sha256(art.read_bytes()).hexdigest()
Path(str(art) + ".sha256").write_text(f"{digest}  {art.name}\n", encoding="ascii")
print(f"SHA256 {digest}")
PY
echo "Artifact: ${ART}"
echo "Optional Authenticode signing: build/sign_exe.ps1 -ExePath dist\\EmailIOCExtractor.exe"
if [[ "$FULL" -eq 1 ]]; then
  echo "Full build by default. Lite: build/build.sh --lite"
else
  echo "Lite build. Full (default): build/build.sh"
fi
