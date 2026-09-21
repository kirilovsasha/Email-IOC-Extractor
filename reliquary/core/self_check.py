"""Offline self-check for one-EXE deployment (no network, no DB)."""

from __future__ import annotations

from pathlib import Path

from reliquary import __version__
from reliquary.core.paths import app_dir
from reliquary.core.qr_scan import qr_decoder_available
from reliquary.core.verdict import default_extra_verdict_path, resolve_verdict_path


def build_self_check_lines(
    *,
    profile_dir: str | Path | None = None,
    verdict_path: str | Path | None = None,
    verdict_warnings: list[str] | None = None,
) -> list[str]:
    """Return short RU status lines for About / startup status."""
    root = app_dir()
    lines: list[str] = [f"Версия {__version__} · каталог: {root.name}/"]

    # Lite vs Full extras
    rar_ok = False
    try:
        import rarfile  # noqa: F401

        rar_ok = True
    except ImportError:
        pass
    qr_ok = qr_decoder_available()
    if rar_ok and qr_ok:
        lines.append("Сборка: Full (RAR + QR)")
    elif rar_ok or qr_ok:
        parts = []
        parts.append("RAR" if rar_ok else "без RAR")
        parts.append("QR" if qr_ok else "без QR")
        lines.append("Сборка: частичная (" + ", ".join(parts) + ")")
    else:
        lines.append("Сборка: Lite (без rarfile / pyzbar)")

    # Configs next to EXE
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
