#!/usr/bin/env python3
"""Sync build/version_info.txt and pyproject.toml version from reliquary.__version__."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reliquary import __version__  # noqa: E402

TEMPLATE = """# UTF-8
#
# PyInstaller VERSIONINFO for Windows File Properties.
# Regenerated from package version by: python build/sync_version_info.py
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({major}, {minor}, {patch}, 0),
    prodvers=({major}, {minor}, {patch}, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          u'040904B0',
          [
            StringStruct(u'CompanyName', u'SOC Tools'),
            StringStruct(u'FileDescription', u'Email IOC Extractor — offline email triage with phishing verdict'),
            StringStruct(u'FileVersion', u'{version}'),
            StringStruct(u'InternalName', u'EmailIOCExtractor'),
            StringStruct(u'LegalCopyright', u''),
            StringStruct(u'OriginalFilename', u'EmailIOCExtractor.exe'),
            StringStruct(u'ProductName', u'Email IOC Extractor'),
            StringStruct(u'ProductVersion', u'{version}'),
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"""


def _sync_pyproject(version: str) -> None:
    path = ROOT / "pyproject.toml"
    text = path.read_text(encoding="utf-8")
    updated, n = re.subn(
        r'(?m)^(version\s*=\s*)"[^"]*"',
        rf'\1"{version}"',
        text,
        count=1,
    )
    if n != 1:
        raise SystemExit(f"Could not update version in {path}")
    if updated != text:
        path.write_text(updated, encoding="utf-8")
        print(f"Updated {path} ({version})")
    else:
        print(f"pyproject.toml already at {version}")


def main() -> None:
    parts = [int(p) for p in re.split(r"[^\d]+", __version__) if p.isdigit()]
    while len(parts) < 3:
        parts.append(0)
    major, minor, patch = parts[0], parts[1], parts[2]
    out = ROOT / "build" / "version_info.txt"
    out.write_text(
        TEMPLATE.format(major=major, minor=minor, patch=patch, version=__version__),
        encoding="utf-8",
    )
    print(f"Wrote {out} ({__version__})")
    _sync_pyproject(__version__)


if __name__ == "__main__":
    main()
