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
    # Per-verdict handoff templates (optional)
    "handoff_malicious.txt",
    "handoff_suspicious.txt",
    "handoff_unknown.txt",
    "handoff_benign.txt",
)


@dataclass
class OrgProfile:
    root: Path
    allowlist_path: Path | None = None
    verdict_path: Path | None = None
    handoff_template_path: Path | None = None
    brands_path: Path | None = None
    handoff_by_level: dict[str, Path] | None = None
    _tmpdir: Path | None = None

    def cleanup(self) -> None:
        if self._tmpdir and self._tmpdir.is_dir():
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None


def default_profile_dir() -> Path:
    return app_dir() / "org_profile"


def _pick(root: Path, name: str) -> Path | None:
    p = root / name
    return p if p.is_file() else None


def load_org_profile(path: str | Path | None = None) -> OrgProfile | None:
    """Load profile from directory, zip, or default ``org_profile/`` next to app."""
    if path is not None and str(path).strip():
        target = Path(str(path).strip())
    else:
        target = default_profile_dir()
        if not target.exists():
            return None

    if not target.exists():
        return None

    tmpdir: Path | None = None
    root = target
    if target.is_file() and target.suffix.lower() == ".zip":
        tmpdir = Path(tempfile.mkdtemp(prefix="reliquary_profile_"))
        with zipfile.ZipFile(target, "r") as zf:
            zf.extractall(tmpdir)
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
        handoff_by_level=level_map or None,
        _tmpdir=tmpdir,
    )


def profile_example_readme() -> str:
    files = "\n".join(f"  - {n}" for n in _PROFILE_FILES)
    return (
        "Org profile folder or .zip next to the exe (org_profile/) may contain:\n"
        f"{files}\n"
    )
