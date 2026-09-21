"""Offline self-check for one-EXE deployment (no network, no DB)."""

from __future__ import annotations

import shutil
from pathlib import Path

from reliquary import __version__
from reliquary.core.paths import app_dir
from reliquary.core.qr_scan import qr_decoder_available
from reliquary.core.verdict import default_extra_verdict_path, resolve_verdict_path


def _unrar_tool_available() -> tuple[bool, str]:
    """rarfile may import while UnRAR.exe is still missing on PATH / next to EXE."""
    try:
        import rarfile  # type: ignore[import-untyped]
    except ImportError:
        return False, "rarfile не установлен"

    root = app_dir()
    candidates = [
        root / "UnRAR.exe",
        root / "unrar.exe",
        root / "unrar",
    ]
    for c in candidates:
        if c.is_file():
            return True, str(c.name)
    which = shutil.which("UnRAR") or shutil.which("unrar") or shutil.which("UnRAR.exe")
    if which:
        return True, Path(which).name
    tool = getattr(rarfile, "UNRAR_TOOL", "") or ""
    if tool and Path(tool).is_file():
        return True, Path(tool).name
    return False, "UnRAR.exe не найден (рядом с EXE или в PATH)"


def build_self_check_lines(
    *,
    profile_dir: str | Path | None = None,
    verdict_path: str | Path | None = None,
    verdict_warnings: list[str] | None = None,
) -> list[str]:
    """Return short RU status lines for About / startup status."""
    root = app_dir()
    lines: list[str] = [f"Версия {__version__} · каталог: {root.name}/"]

    rar_mod = False
    try:
        import rarfile  # noqa: F401

        rar_mod = True
    except ImportError:
        pass
    unrar_ok, unrar_note = _unrar_tool_available() if rar_mod else (False, "нет rarfile")
    qr_ok = qr_decoder_available()

    if rar_mod and unrar_ok and qr_ok:
        lines.append("Сборка: Full (RAR + UnRAR + QR)")
    elif rar_mod and qr_ok and not unrar_ok:
        lines.append(f"Сборка: Full без UnRAR — {unrar_note}")
    elif rar_mod or qr_ok:
        parts = []
        if rar_mod:
            parts.append("RAR-модуль" + ("+UnRAR" if unrar_ok else " без UnRAR"))
        else:
            parts.append("без RAR")
        parts.append("QR" if qr_ok else "без QR")
        lines.append("Сборка: частичная (" + ", ".join(parts) + ")")
    else:
        lines.append("Сборка: Lite (без rarfile / pyzbar)")

    allow = root / "allowlist_extra.txt"
    verdict = resolve_verdict_path(verdict_path)
    prefs = root / "ui_prefs.json"
    update = root / "update.json"
    zip_prof = root / "org_profile.zip"
    dir_prof = root / "org_profile"

    cfg_bits: list[str] = []
    if allow.is_file():
        cfg_bits.append("allowlist")
    if verdict is not None and Path(verdict).is_file():
        cfg_bits.append("verdict_extra")
    elif default_extra_verdict_path().is_file():
        cfg_bits.append("verdict_extra")
    if prefs.is_file():
        cfg_bits.append("prefs")
    if update.is_file():
        cfg_bits.append("update.json")
    if profile_dir:
        cfg_bits.append(f"профиль={Path(str(profile_dir)).name}")
    elif zip_prof.is_file():
        cfg_bits.append("org_profile.zip")
    elif dir_prof.exists():
        cfg_bits.append("org_profile/")
    lines.append(
        "Конфиги рядом с EXE: " + (", ".join(cfg_bits) if cfg_bits else "нет (встроенные веса)")
    )

    sha = root / "EmailIOCExtractor.exe.sha256"
    if not sha.is_file():
        sha = root / "SHA256SUMS"
    if sha.is_file():
        lines.append(f"Контрольная сумма: {sha.name}")

    if verdict_warnings:
        lines.append("⚠ verdict_extra: " + "; ".join(verdict_warnings[:4]))

    return lines


def format_self_check(
    *,
    profile_dir: str | Path | None = None,
    verdict_path: str | Path | None = None,
    verdict_warnings: list[str] | None = None,
) -> str:
    return "\n".join(
        build_self_check_lines(
            profile_dir=profile_dir,
            verdict_path=verdict_path,
            verdict_warnings=verdict_warnings,
        )
    )
