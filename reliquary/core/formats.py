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
    (".mbox", "Unix mbox"),
)

SUPPORTED_SUFFIXES: frozenset[str] = frozenset(s for s, _ in SUPPORTED_FORMATS)

SUPPORTED_GLOBS: tuple[str, ...] = tuple(f"*{s}" for s, _ in SUPPORTED_FORMATS)

# Office Open XML (+ macro-enabled) — analyzed when attached to email
OFFICE_OOXML_SUFFIXES: frozenset[str] = frozenset(
    {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
)

EMAIL_SUFFIXES: frozenset[str] = frozenset({".eml", ".msg"})
MBOX_SUFFIXES: frozenset[str] = frozenset({".mbox"})


def is_supported(path: str | Path) -> bool:
    return Path(path).suffix.lower() in SUPPORTED_SUFFIXES


def collect_supported(root: Path, *, recursive: bool = True) -> list[str]:
    """Collect supported email files under a directory (sorted, unique).

    ``.mbox`` files are expanded to temporary ``.eml`` members.
    """
    paths: list[str] = []
    iterator = root.rglob if recursive else root.glob
    for pattern in ("*.eml", "*.msg"):
        paths.extend(str(p) for p in iterator(pattern) if p.is_file())
    mbox_paths = [p for p in iterator("*.mbox") if p.is_file()]
    if mbox_paths:
        from reliquary.core.mbox_ingest import expand_mbox_to_emls

        for mp in mbox_paths:
            try:
                emls, _dest = expand_mbox_to_emls(mp)
                paths.extend(emls)
            except (OSError, ValueError, TypeError):
                continue
    return sorted(set(paths))


def formats_help_line() -> str:
    """Short suffix list for CLI --help."""
    return ", ".join(sorted(SUPPORTED_SUFFIXES))


def tk_filetypes() -> list[tuple[str, str]]:
    """Tkinter filedialog filetypes: email only + All files."""
    return [
        ("Письма (.eml .msg .mbox)", "*.eml *.msg *.mbox"),
        ("Все файлы", "*.*"),
    ]


def expand_input_paths(paths: list[str] | list[Path], *, mbox_limit: int = 500) -> list[str]:
    """Expand ``.mbox`` files to temporary ``.eml`` paths; pass through others."""
    from reliquary.core.mbox_ingest import expand_mbox_to_emls, is_mbox

    out: list[str] = []
    for raw in paths:
        p = Path(raw)
        if is_mbox(p) and p.is_file():
            try:
                emls, _dest = expand_mbox_to_emls(p, limit=mbox_limit)
                out.extend(emls)
            except (OSError, ValueError, TypeError):
                continue
        else:
            out.append(str(p))
    return out
