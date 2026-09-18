"""PyInstaller build spec for IOC Extractor (Windows .exe / Linux binary).

Build:
  pyinstaller build/reliquary.spec

The produced binary is fully offline — no network calls in application code.
UPX is disabled to reduce corporate AV false positives.
"""

# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files

block_cipher = None
ROOT = Path(SPECPATH).resolve().parent

ctk_datas, ctk_binaries, ctk_hidden = collect_all("customtkinter")
stix_datas = collect_data_files("stix2")

list_datas = []
for name in ("allowlist.txt", "denylist.txt", "verdict.ini", "ticket.ini"):
    src = ROOT / name
    if src.is_file():
        list_datas.append((str(src), "."))

_version = str(ROOT / "build" / "version_info.txt") if sys.platform == "win32" else None

a = Analysis(
    [str(ROOT / "run_reliquary.py")],
    pathex=[],
    binaries=ctk_binaries,
    datas=ctk_datas + stix_datas + list_datas,
    hiddenimports=ctk_hidden
    + [
        "extract_msg",
        "olefile",
        "filetype",
        "bs4",
        "lxml",
        "pypdf",
        "chardet",
        "stix2",
        "windnd",
        "py7zr",
        "PIL",
        "reliquary",
        "reliquary.gui.app",
        "reliquary.gui.tabs",
        "reliquary.gui.tooltips",
        "reliquary.gui.ioc_table",
        "reliquary.gui.theme",
        "reliquary.cli",
        "reliquary.core.office_extract",
        "reliquary.core.paths",
        "reliquary.core.qr_scan",
        "reliquary.core.ticket",
        "reliquary.core.defang",
        "reliquary.core.prefs",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="IOC_Extractor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    version=_version,
)
