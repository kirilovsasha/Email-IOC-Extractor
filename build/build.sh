#!/usr/bin/env bash
# Build Email IOC Extractor binary with PyInstaller (run on target OS, usually Windows).
set -euo pipefail
cd "$(dirname "$0")/.."
FULL=0
if [[ "${1:-}" == "--full" ]]; then
  FULL=1
  shift
fi
pip install -r requirements.txt pyinstaller
pip install -e .
if [[ "$FULL" -eq 1 ]]; then
  pip install -e ".[rar,qr]"
  export RELIQUARY_FULL=1
  echo "Full build: rar + qr"
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
echo "Extras: build/build.sh --full  (or pip install '.[rar,qr]' before build)"
