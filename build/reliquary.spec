"""PyInstaller build spec for IOC Extractor (Windows .exe / Linux binary).

Build:
  pyinstaller build/reliquary.spec

The produced binary is fully offline — no network calls in application code.
"""

# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all, collect_data_files

block_cipher = None

ctk_datas, ctk_binaries, ctk_hidden = collect_all("customtkinter")
stix_datas = collect_data_files("stix2")

a = Analysis(
    ["../run_reliquary.py"],
    pathex=[],
    binaries=ctk_binaries,
    datas=ctk_datas + stix_datas,
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
        "reliquary",
        "reliquary.gui.app",
        "reliquary.cli",
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
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI app — no console window on Windows
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
