"""PyInstaller build spec for Email IOC Extractor (Windows .exe / Linux binary).

Build:
  pyinstaller build/reliquary.spec

Full (RAR/QR): install extras first, or set RELIQUARY_FULL=1 after pip install '.[rar,qr]'.
  Hiddenimports for rarfile/pyzbar are added automatically when importable.
"""

# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

block_cipher = None
ROOT = Path(SPECPATH).resolve().parent

ctk_datas, ctk_binaries, ctk_hidden = collect_all("customtkinter")

_version = str(ROOT / "build" / "version_info.txt") if sys.platform == "win32" else None
_icon = ROOT / "build" / "app.ico"
_icon_path = str(_icon) if _icon.is_file() else None

_extra_hidden: list[str] = []
_extra_datas = []
_extra_binaries = []

_want_full = os.environ.get("RELIQUARY_FULL", "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)


def _try_collect(mod: str) -> bool:
    global _extra_datas, _extra_binaries, _extra_hidden
    try:
        __import__(mod)
    except ImportError:
        return False
    try:
        d, b, h = collect_all(mod)
        _extra_datas += d
        _extra_binaries += b
        _extra_hidden += h
    except Exception:
        _extra_hidden.append(mod)
    return True


# Auto-bundle optional extras when present in the build env (Lite = not installed).
_ = _want_full  # documented env; importability is the real gate
if _try_collect("rarfile"):
    _extra_hidden.append("rarfile")
if _try_collect("pyzbar"):
    _extra_hidden.extend(["pyzbar", "pyzbar.pyzbar"])

a = Analysis(
    [str(ROOT / "run_reliquary.py")],
    pathex=[],
    binaries=ctk_binaries + _extra_binaries,
    datas=ctk_datas + _extra_datas,
    hiddenimports=ctk_hidden
    + _extra_hidden
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
        "reliquary.gui.filters_actions",
        "reliquary.gui.layout",
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
        "reliquary.core.lookalike",
        "reliquary.core.content_signals",
        "reliquary.core.analysis_options",
        "reliquary.core.org_profile",
        "reliquary.core.export_hook",
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
    icon=_icon_path,
    version=_version,
)
