"""Install org_profile.zip/folder next to the EXE with a dry-run self-check."""

from __future__ import annotations

import shutil
from pathlib import Path

from reliquary.core.org_profile import load_org_profile, safe_extract_zip
from reliquary.core.paths import app_dir
from reliquary.core.pipeline import analyze_file


def install_org_profile(
    source: str | Path,
    *,
    dest_name: str = "org_profile",
    as_zip: bool | None = None,
) -> tuple[Path, list[str]]:
    """Copy/extract profile beside EXE. Returns (dest, notes)."""
    src = Path(source)
    notes: list[str] = []
    root = app_dir()
    if not src.exists():
        raise FileNotFoundError(f"Профиль не найден: {src}")

    if src.is_file() and src.suffix.lower() == ".zip":
        if as_zip is None or as_zip:
            dest = root / "org_profile.zip"
            shutil.copy2(src, dest)
            notes.append(f"Скопирован {dest.name}")
            return dest, notes
        dest_dir = root / dest_name
        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)
        dest_dir.mkdir(parents=True, exist_ok=True)
        import zipfile

        with zipfile.ZipFile(src, "r") as zf:
            safe_extract_zip(zf, dest_dir)
        notes.append(f"Распакован в {dest_dir.name}/")
        return dest_dir, notes

    if src.is_dir():
        dest_dir = root / dest_name
        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)
        shutil.copytree(src, dest_dir)
        notes.append(f"Скопирован каталог → {dest_dir.name}/")
        return dest_dir, notes

    raise ValueError(f"Ожидался .zip или папка профиля: {src}")


def verify_org_profile(
    profile_path: str | Path | None = None,
    *,
    sample_eml: str | Path | None = None,
) -> list[str]:
    """Load profile and optionally smoke-analyze one .eml. Returns RU notes."""
    notes: list[str] = []
    profile = load_org_profile(profile_path)
    if profile is None:
        return ["Профиль не загружен (нет org_profile.zip / org_profile/)"]
    try:
        notes.append(f"Профиль: {profile.root}")
        for label, path in (
            ("allowlist", profile.allowlist_path),
            ("verdict", profile.verdict_path),
            ("brands", profile.brands_path),
            ("handoff", profile.handoff_template_path),
        ):
            if path and path.is_file():
                notes.append(f"  ✓ {label}: {path.name}")
            else:
                notes.append(f"  · {label}: нет")
        if sample_eml and Path(sample_eml).is_file():
            from reliquary.core.analysis_options import AnalysisOptions

            opts = AnalysisOptions(profile_dir=profile.root).with_profile(profile)
            result = analyze_file(sample_eml, options=opts)
            level = result.verdict.level.value if result.verdict else "—"
            score = result.verdict.score if result.verdict else "—"
            notes.append(f"Пробный разбор: {Path(sample_eml).name} → {level} score={score}")
    finally:
        profile.cleanup()
    return notes
