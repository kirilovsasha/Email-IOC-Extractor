"""Canonical list of analyzable file formats (GUI, CLI, document parser).

Top-level input is email only (.eml / .msg / .mbox / .pst). Office/archive suffixes remain
for attachment inspection inside messages.
"""

from __future__ import annotations

from pathlib import Path

# (suffix with dot, human label for dialogs / help)
SUPPORTED_FORMATS: tuple[tuple[str, str], ...] = (
    (".eml", "Email (EML)"),
    (".msg", "Outlook MSG"),
    (".mbox", "Unix mbox"),
    (".pst", "Outlook PST"),
)

SUPPORTED_SUFFIXES: frozenset[str] = frozenset(s for s, _ in SUPPORTED_FORMATS)

SUPPORTED_GLOBS: tuple[str, ...] = tuple(f"*{s}" for s, _ in SUPPORTED_FORMATS)

# Office Open XML (+ macro-enabled) — analyzed when attached to email
OFFICE_OOXML_SUFFIXES: frozenset[str] = frozenset(
    {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
)

EMAIL_SUFFIXES: frozenset[str] = frozenset({".eml", ".msg"})
MBOX_SUFFIXES: frozenset[str] = frozenset({".mbox"})
PST_SUFFIXES: frozenset[str] = frozenset({".pst"})

_INGEST_TEMP_DIRS: list[Path] = []
_INGEST_NOTES: list[str] = []


def register_ingest_temp(path: str | Path) -> None:
    """Remember a temp mailbox directory so the batch can delete it."""
    resolved = Path(path)
    if resolved not in _INGEST_TEMP_DIRS:
        _INGEST_TEMP_DIRS.append(resolved)


def push_ingest_note(text: str) -> None:
    line = (text or "").strip()
    if line and line not in _INGEST_NOTES:
        _INGEST_NOTES.append(line)


def _echo_ingest_note(text: str) -> None:
    """Keep the note for the GUI and echo problems to stderr for the CLI."""
    push_ingest_note(text)
    low = (text or "").lower()
    if any(k in low for k in ("недоступ", "пропущ", "не найден", "ошиб", "сбой")):
        import sys

        print(text, file=sys.stderr)


def take_ingest_notes() -> list[str]:
    notes = list(_INGEST_NOTES)
    _INGEST_NOTES.clear()
    return notes


def ingest_problem_notes(notes: list[str]) -> list[str]:
    """Library gaps, skipped messages, and silent attachment caps."""
    keys = ("недоступ", "пропущ", "не найден", "ошиб", "сбой", "сохранено")
    return [note for note in notes if any(key in note.lower() for key in keys)]


def cleanup_ingest_dirs() -> None:
    """Delete ``reliquary_pst_*`` / ``reliquary_mbox_*`` dirs created for this batch."""
    import shutil

    for folder in list(_INGEST_TEMP_DIRS):
        shutil.rmtree(folder, ignore_errors=True)
    _INGEST_TEMP_DIRS.clear()


def is_supported(path: str | Path) -> bool:
    return Path(path).suffix.lower() in SUPPORTED_SUFFIXES


def collect_supported(root: Path, *, recursive: bool = True) -> list[str]:
    """Collect supported email files under a directory (sorted, unique).

    ``.mbox`` / ``.pst`` files are expanded to temporary ``.eml`` members.
    """
    paths: list[str] = []
    iterator = root.rglob if recursive else root.glob
    for pattern in ("*.eml", "*.msg"):
        paths.extend(str(p) for p in iterator(pattern) if p.is_file())
    mbox_paths = [p for p in iterator("*.mbox") if p.is_file()]
    if mbox_paths:
        from reliquary.core.mbox_ingest import expand_mbox_to_emls

        for mp in mbox_paths:
            box_notes: list[str] = []
            try:
                emls, _dest = expand_mbox_to_emls(mp, notes=box_notes)
                paths.extend(emls)
            except (OSError, ValueError, TypeError) as exc:
                push_ingest_note(f"mbox «{mp.name}»: {exc}")
            for note in box_notes:
                push_ingest_note(note)
    pst_paths = [p for p in iterator("*.pst") if p.is_file()]
    if pst_paths:
        from reliquary.core.pst_ingest import expand_pst_to_emls

        for pp in pst_paths:
            try:
                emls, _dest, notes = expand_pst_to_emls(pp)
                paths.extend(emls)
                for note in notes:
                    push_ingest_note(note)
            except (OSError, ValueError, TypeError, RuntimeError) as exc:
                push_ingest_note(f"PST «{pp.name}»: {exc}")
    return sorted(set(paths))


def formats_help_line() -> str:
    """Short suffix list for CLI --help."""
    return ", ".join(sorted(SUPPORTED_SUFFIXES))


def tk_filetypes() -> list[tuple[str, str]]:
    """Tkinter filedialog filetypes: email only + All files."""
    return [
        ("Письма (.eml .msg .mbox .pst)", "*.eml *.msg *.mbox *.pst"),
        ("Все файлы", "*.*"),
    ]


def expand_input_paths(paths: list[str] | list[Path], *, mbox_limit: int = 500) -> list[str]:
    """Expand ``.mbox`` / ``.pst`` files to temporary ``.eml`` paths; pass through others."""
    from reliquary.core.mbox_ingest import expand_mbox_to_emls, is_mbox
    from reliquary.core.pst_ingest import expand_pst_to_emls, is_pst

    out: list[str] = []
    for raw in paths:
        p = Path(raw)
        if is_mbox(p) and p.is_file():
            box_notes: list[str] = []
            try:
                emls, _dest = expand_mbox_to_emls(p, limit=mbox_limit, notes=box_notes)
                out.extend(emls)
            except (OSError, ValueError, TypeError) as exc:
                push_ingest_note(f"mbox «{p.name}»: {exc}")
                box_notes.append(f"mbox «{p.name}»: {exc}")
            for note in box_notes:
                _echo_ingest_note(note)
        elif is_pst(p) and p.is_file():
            try:
                emls, _dest, notes = expand_pst_to_emls(p, limit=mbox_limit)
                out.extend(emls)
                for n in notes:
                    _echo_ingest_note(n)
            except (OSError, ValueError, TypeError, RuntimeError) as exc:
                _echo_ingest_note(f"PST: {exc}")
                continue
        else:
            out.append(str(p))
    return out
