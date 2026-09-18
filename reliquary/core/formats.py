"""Canonical list of analyzable file formats (GUI, CLI, document parser)."""

from __future__ import annotations

from pathlib import Path

# (suffix with dot, human label for dialogs / help)
SUPPORTED_FORMATS: tuple[tuple[str, str], ...] = (
    (".eml", "Email (EML)"),
    (".msg", "Outlook MSG"),
    (".pdf", "PDF"),
    (".html", "HTML"),
    (".htm", "HTML"),
    (".txt", "Text / ticket"),
    (".csv", "CSV"),
    (".log", "Log"),
    (".md", "Markdown"),
    (".json", "JSON text"),
    (".docx", "Word OOXML"),
    (".docm", "Word macro-enabled"),
    (".xlsx", "Excel OOXML"),
    (".xlsm", "Excel macro-enabled"),
    (".pptx", "PowerPoint OOXML"),
    (".pptm", "PowerPoint macro-enabled"),
    (".zip", "ZIP archive"),
    (".7z", "7-Zip archive"),
    (".rar", "RAR archive"),
)

SUPPORTED_SUFFIXES: frozenset[str] = frozenset(s for s, _ in SUPPORTED_FORMATS)

SUPPORTED_GLOBS: tuple[str, ...] = tuple(f"*{s}" for s, _ in SUPPORTED_FORMATS)

# Office Open XML (+ macro-enabled) that yield extractable text/links
OFFICE_OOXML_SUFFIXES: frozenset[str] = frozenset(
    {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
)

ARCHIVE_SUFFIXES: frozenset[str] = frozenset({".zip", ".7z", ".rar"})
EMAIL_SUFFIXES: frozenset[str] = frozenset({".eml", ".msg"})
TEXT_SUFFIXES: frozenset[str] = frozenset({".txt", ".csv", ".log", ".md", ".json"})
HTML_SUFFIXES: frozenset[str] = frozenset({".html", ".htm"})


def is_supported(path: str | Path) -> bool:
    return Path(path).suffix.lower() in SUPPORTED_SUFFIXES


def collect_supported(root: Path, *, recursive: bool = True) -> list[str]:
    """Collect supported files under a directory (sorted, unique)."""
    paths: list[str] = []
    iterator = root.rglob if recursive else root.glob
    for pattern in SUPPORTED_GLOBS:
        paths.extend(str(p) for p in iterator(pattern) if p.is_file())
    return sorted(set(paths))


def formats_help_line() -> str:
    """Short suffix list for CLI --help."""
    return ", ".join(sorted(SUPPORTED_SUFFIXES))


def tk_filetypes() -> list[tuple[str, str]]:
    """Tkinter filedialog filetypes: All supported + All files."""
    glob = " ".join(SUPPORTED_GLOBS)
    return [
        ("Поддерживаемые", glob),
        ("Все файлы", "*.*"),
    ]
