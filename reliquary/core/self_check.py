"""Offline self-check for one-EXE deployment (no network, no DB)."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from reliquary import __version__
from reliquary.core.paths import app_dir
from reliquary.core.qr_scan import qr_decoder_available
from reliquary.core.verdict import default_extra_verdict_path, resolve_verdict_path


def _verify_exe_sha256(root: Path) -> str | None:
    """Compare EmailIOCExtractor.exe to sibling .sha256 if both exist."""
    exe = root / "EmailIOCExtractor.exe"
    sha_file = root / "EmailIOCExtractor.exe.sha256"
    if not sha_file.is_file():
        sha_file = root / "SHA256SUMS"
    if not exe.is_file() or not sha_file.is_file():
        return None
    try:
        expected_line = sha_file.read_text(encoding="utf-8", errors="replace").strip().splitlines()[0]
        expected = expected_line.split()[0].lower()
        if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            return f"⚠ SHA256: неверный формат в {sha_file.name}"
        h = hashlib.sha256()
        with exe.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        digest = h.hexdigest()
        if digest == expected:
            return f"SHA256 EXE OK ({sha_file.name})"
        return f"⚠ SHA256 НЕ СОВПАЛ: {exe.name} ≠ {sha_file.name}"
    except OSError as exc:
        return f"⚠ SHA256: ошибка чтения ({exc})"


def _check_org_profile_zip(path: Path) -> str | None:
    """Zip-slip / readable check for org_profile.zip beside EXE."""
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            if not names:
                return "⚠ org_profile.zip пуст"
            for name in names:
                # Reject absolute / parent traversal
                p = Path(name)
                if p.is_absolute() or ".." in p.parts:
                    return f"⚠ org_profile.zip: опасный путь «{name}»"
            # Touch central directory + first member
            zf.testzip()
            return f"org_profile.zip OK ({len(names)} файлов)"
    except zipfile.BadZipFile:
        return "⚠ org_profile.zip повреждён (не ZIP)"
    except OSError as exc:
        return f"⚠ org_profile.zip: {exc}"


def build_self_check_lines(
    *,
    profile_dir: str | Path | None = None,
    verdict_path: str | Path | None = None,
    verdict_warnings: list[str] | None = None,
) -> list[str]:
    """Return short RU status lines for About / startup status."""
    root = app_dir()
    lines: list[str] = [f"Версия {__version__} · каталог: {root.name}/"]

    qr_ok = qr_decoder_available()
    if qr_ok:
        lines.append("Сборка: EXE + QR decode")
    else:
        lines.append(
            "Сборка: EXE · ⚠ QR decode недоступен (нет pyzbar / libzbar)"
        )

    allow = root / "allowlist_extra.txt"
    verdict = resolve_verdict_path(verdict_path)
    prefs = root / "ui_prefs.json"
    update = root / "update.json"
    zip_prof = root / "org_profile.zip"
    dir_prof = root / "org_profile"
    runbook = root / "docs" / "ANALYST_RU.md"
    if not runbook.is_file():
        runbook = root / "ANALYST_RU.md"

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
    if runbook.is_file():
        cfg_bits.append("ANALYST_RU")
    lines.append(
        "Конфиги рядом с EXE: " + (", ".join(cfg_bits) if cfg_bits else "нет (встроенные веса)")
    )

    if zip_prof.is_file() and not profile_dir:
        znote = _check_org_profile_zip(zip_prof)
        if znote:
            lines.append(znote)

    sha_note = _verify_exe_sha256(root)
    if sha_note:
        lines.append(sha_note)
    else:
        sha = root / "EmailIOCExtractor.exe.sha256"
        if not sha.is_file():
            sha = root / "SHA256SUMS"
        if sha.is_file():
            lines.append(f"Контрольная сумма: {sha.name} (EXE не найден для сверки)")

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
