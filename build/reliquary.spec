"""PyInstaller build spec for Email IOC Extractor (Windows .exe / Linux binary).

Build:
  pyinstaller build/reliquary.spec
"""

# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

block_cipher = None
ROOT = Path(SPECPATH).resolve().parent

ctk_datas, ctk_binaries, ctk_hidden = collect_all("customtkinter")

_version = str(ROOT / "build" / "version_info.txt") if sys.platform == "win32" else None

a = Analysis(
    [str(ROOT / "run_reliquary.py")],
    pathex=[],
    binaries=ctk_binaries,
    datas=ctk_datas,
    hiddenimports=ctk_hidden
    + [
        "extract_msg",
        "olefile",
        "filetype",
        "bs4",
        "lxml",
        "chardet",
        "windnd",
        "py7zr",
        "PIL",
        "reliquary",
        "reliquary.gui.app",
        "reliquary.gui.tabs",
        "reliquary.gui.tooltips",
        "reliquary.gui.ioc_table",
        "reliquary.gui.theme",
        "reliquary.gui.result_panels",
        "reliquary.gui.windowing",
        "reliquary.gui.export_actions",
        "reliquary.gui.analysis_actions",
        "reliquary.gui.clipboard_actions",
        "reliquary.cli",
        "reliquary.core.office_extract",
        "reliquary.core.paths",
        "reliquary.core.qr_scan",
        "reliquary.core.defang",
        "reliquary.core.prefs",
        "reliquary.core.handoff",
        "reliquary.core.filter_state",
        "reliquary.core.error_log",
        "reliquary.core.verdict",
    ],
    # Optional extras (rarfile / pyzbar) are NOT bundled in the lite EXE.
    # For a full build: pip install '.[rar,qr]' then add them to hiddenimports.
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
    name="EmailIOCExtractor",
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
