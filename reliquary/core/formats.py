"""Canonical list of analyzable file formats (GUI, CLI, document parser).

Top-level input is email only (.eml / .msg). Office/archive suffixes remain
for attachment inspection inside messages.
"""

from __future__ import annotations

from pathlib import Path

# (suffix with dot, human label for dialogs / help)
SUPPORTED_FORMATS: tuple[tuple[str, str], ...] = (
    (".eml", "Email (EML)"),
    (".msg", "Outlook MSG"),
)

SUPPORTED_SUFFIXES: frozenset[str] = frozenset(s for s, _ in SUPPORTED_FORMATS)

SUPPORTED_GLOBS: tuple[str, ...] = tuple(f"*{s}" for s, _ in SUPPORTED_FORMATS)

# Office Open XML (+ macro-enabled) — analyzed when attached to email
OFFICE_OOXML_SUFFIXES: frozenset[str] = frozenset(
    {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
)

EMAIL_SUFFIXES: frozenset[str] = frozenset({".eml", ".msg"})


def is_supported(path: str | Path) -> bool:
    return Path(path).suffix.lower() in SUPPORTED_SUFFIXES


def collect_supported(root: Path, *, recursive: bool = True) -> list[str]:
    """Collect supported email files under a directory (sorted, unique)."""
    paths: list[str] = []
    iterator = root.rglob if recursive else root.glob
    for pattern in SUPPORTED_GLOBS:
        paths.extend(str(p) for p in iterator(pattern) if p.is_file())
    return sorted(set(paths))


def formats_help_line() -> str:
    """Short suffix list for CLI --help."""
    return ", ".join(sorted(SUPPORTED_SUFFIXES))


def tk_filetypes() -> list[tuple[str, str]]:
    """Tkinter filedialog filetypes: email only + All files."""
    glob = " ".join(SUPPORTED_GLOBS)
    return [
        ("Письма (.eml .msg)", glob),
        ("Все файлы", "*.*"),
    ]
