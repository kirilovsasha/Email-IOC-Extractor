"""Org profile pack — folder or zip with local overrides (no rebuild)."""

from __future__ import annotations

import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from reliquary.core.paths import app_dir

_PROFILE_FILES = (
    "allowlist_extra.txt",
    "verdict_extra.json",
    "handoff_extra.txt",
    "brands.txt",
    "org_domains.txt",
    # Per-verdict handoff templates (optional)
    "handoff_malicious.txt",
    "handoff_suspicious.txt",
    "handoff_unknown.txt",
    "handoff_benign.txt",
)


class UnsafeZipError(ValueError):
    """Raised when a profile zip contains path-traversal or absolute members."""


@dataclass
class OrgProfile:
    root: Path
    allowlist_path: Path | None = None
    verdict_path: Path | None = None
    handoff_template_path: Path | None = None
    brands_path: Path | None = None
    org_domains_path: Path | None = None
    handoff_by_level: dict[str, Path] | None = None
    _tmpdir: Path | None = None

    def cleanup(self) -> None:
        if self._tmpdir and self._tmpdir.is_dir():
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None

    def __enter__(self) -> OrgProfile:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.cleanup()


def default_profile_dir() -> Path:
    return app_dir() / "org_profile"


def resolve_default_profile_path() -> Path | None:
    """Prefer ``org_profile.zip`` next to EXE, else ``org_profile/`` folder."""
    root = app_dir()
    zip_path = root / "org_profile.zip"
    if zip_path.is_file():
        return zip_path
    folder = root / "org_profile"
    if folder.exists():
        return folder
    return None


def _pick(root: Path, name: str) -> Path | None:
    p = root / name
    return p if p.is_file() else None


def _is_unsafe_zip_member(name: str) -> bool:
    """Reject absolute paths, drive letters, and ``..`` traversal."""
    raw = name.replace("\\", "/")
    if not raw or raw.endswith("/"):
        # Directories alone are fine; files checked below when extracted
        pass
    if raw.startswith("/") or raw.startswith("//"):
        return True
    if len(raw) >= 2 and raw[1] == ":":
        return True
    parts = [p for p in raw.split("/") if p and p != "."]
    return any(p == ".." for p in parts)


def safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract zip members under ``dest`` only (zip-slip safe)."""
    dest = dest.resolve()
    for info in zf.infolist():
        name = info.filename
        if _is_unsafe_zip_member(name):
            raise UnsafeZipError(f"unsafe zip member: {name!r}")
        target = (dest / name).resolve()
        try:
            target.relative_to(dest)
        except ValueError as exc:
            raise UnsafeZipError(f"unsafe zip member: {name!r}") from exc
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info, "r") as src, target.open("wb") as out:
            shutil.copyfileobj(src, out)


def load_org_profile(path: str | Path | None = None) -> OrgProfile | None:
    """Load profile from directory, zip, or default ``org_profile.zip`` / ``org_profile/``."""
    if path is not None and str(path).strip():
        target = Path(str(path).strip())
    else:
        resolved = resolve_default_profile_path()
        if resolved is None:
            return None
        target = resolved

    if not target.exists():
        return None

    tmpdir: Path | None = None
    root = target
    if target.is_file() and target.suffix.lower() == ".zip":
        tmpdir = Path(tempfile.mkdtemp(prefix="reliquary_profile_"))
        try:
            with zipfile.ZipFile(target, "r") as zf:
                safe_extract_zip(zf, tmpdir)
        except (UnsafeZipError, zipfile.BadZipFile, OSError):
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise
        # If zip has a single top folder, use it
        children = [c for c in tmpdir.iterdir() if not c.name.startswith(".")]
        if len(children) == 1 and children[0].is_dir():
            root = children[0]
        else:
            root = tmpdir
    elif target.is_dir():
        root = target
    else:
        return None

    level_map: dict[str, Path] = {}
    for level in ("malicious", "suspicious", "unknown", "benign"):
        p = _pick(root, f"handoff_{level}.txt")
        if p:
            level_map[level] = p

    return OrgProfile(
        root=root,
        allowlist_path=_pick(root, "allowlist_extra.txt"),
        verdict_path=_pick(root, "verdict_extra.json"),
        handoff_template_path=_pick(root, "handoff_extra.txt"),
        brands_path=_pick(root, "brands.txt"),
        org_domains_path=_pick(root, "org_domains.txt"),
        handoff_by_level=level_map or None,
        _tmpdir=tmpdir,
    )


def profile_example_readme() -> str:
    files = "\n".join(f"  - {n}" for n in _PROFILE_FILES)
    return (
        "Профиль организации рядом с EXE:\n"
        "  - org_profile.zip  (предпочтительно — один файл)\n"
        "  - org_profile/     (папка)\n"
        "Содержимое:\n"
        f"{files}\n"
    )
