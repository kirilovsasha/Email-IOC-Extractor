"""Optional offline YARA scan of attachment/body bytes (extra: yara)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reliquary.core.paths import app_dir


def yara_available() -> bool:
    try:
        import yara  # type: ignore[import-untyped]  # noqa: F401

        return True
    except ImportError:
        return False


def resolve_rules_path(explicit: str | Path | None = None) -> Path | None:
    if explicit and str(explicit).strip():
        p = Path(str(explicit).strip())
        return p if p.is_file() else None
    for name in ("yara_rules.yar", "yara_rules.yara", "rules.yar"):
        cand = app_dir() / name
        if cand.is_file():
            return cand
    folder = app_dir() / "yara_rules"
    if folder.is_dir():
        files = list(folder.glob("*.yar")) + list(folder.glob("*.yara"))
        if files:
            return folder
    return None


def scan_bytes(
    data: bytes,
    *,
    rules_path: str | Path | None = None,
    timeout: int = 5,
) -> tuple[list[str], list[str]]:
    """Return (match_rule_names, notes). Empty if yara missing or no rules."""
    notes: list[str] = []
    if not data:
        return [], notes
    try:
        import yara  # type: ignore[import-untyped]
    except ImportError:
        notes.append("YARA: пакет не установлен (pip install .[yara])")
        return [], notes
    path = resolve_rules_path(rules_path)
    if path is None:
        notes.append("YARA: правила не найдены рядом с EXE")
        return [], notes
    try:
        if path.is_dir():
            mapping = {
                f"r{i}": str(p)
                for i, p in enumerate(sorted(path.glob("*.yar")) + sorted(path.glob("*.yara")))
            }
            if not mapping:
                return [], ["YARA: пустая папка правил"]
            rules = yara.compile(filepaths=mapping)
        else:
            rules = yara.compile(filepath=str(path))
        matches = rules.match(data=data, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 — yara errors vary
        return [], [f"YARA: {type(exc).__name__}: {exc}"]
    names = []
    for m in matches or []:
        rule = getattr(m, "rule", None) or str(m)
        if rule not in names:
            names.append(str(rule))
    return names[:40], notes


def scan_result_attachments(
    attachments: list[Any],
    *,
    body: bytes | str = b"",
    rules_path: str | Path | None = None,
) -> tuple[list[str], list[str]]:
    """Scan body + each attachment.data; return (all rule hits, notes)."""
    hits: list[str] = []
    notes: list[str] = []
    blob = body.encode("utf-8", errors="replace") if isinstance(body, str) else body
    if blob:
        h, n = scan_bytes(blob, rules_path=rules_path)
        hits.extend(h)
        notes.extend(n)
    for att in attachments or []:
        data = getattr(att, "data", None)
        if not data:
            continue
        h, n = scan_bytes(data, rules_path=rules_path)
        for rule in h:
            if rule not in hits:
                hits.append(rule)
            flags = getattr(att, "risk_flags", None)
            if isinstance(flags, list) and "yara_match" not in flags:
                flags.append("yara_match")
            att_notes = getattr(att, "notes", None)
            if isinstance(att_notes, list):
                att_notes.append(f"YARA: {rule}")
        for note in n:
            if note not in notes:
                notes.append(note)
    return hits, notes
