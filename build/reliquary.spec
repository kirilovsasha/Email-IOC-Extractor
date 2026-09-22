"""PyInstaller build spec for Email IOC Extractor (Windows .exe / Linux binary).

Build:
  pyinstaller build/reliquary.spec

Single fleet build: core + QR (pyzbar). RAR inventory is not bundled.
Optional yara-python is collected when present in the build env.
"""

# -*- mode: python ; coding: utf-8 -*-
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

# Analyst runbook for frozen EXE (About / fleet)
_runbook = ROOT / "docs" / "ANALYST_RU.md"
if _runbook.is_file():
    _extra_datas.append((str(_runbook), "docs"))
_schema = ROOT / "docs" / "schema_report_v2.json"
if _schema.is_file():
    _extra_datas.append((str(_schema), "docs"))


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


# QR decode is a required dependency — bundle when importable at build time.
if _try_collect("pyzbar"):
    _extra_hidden.extend(["pyzbar", "pyzbar.pyzbar"])
# Optional offline YARA
if _try_collect("yara"):
    _extra_hidden.append("yara")

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
        "pyzbar",
        "pyzbar.pyzbar",
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
        "reliquary.core.archive_unlock",
        "reliquary.core.yara_scan",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["rarfile"],
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
