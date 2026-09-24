"""Optional offline YARA scan of attachment/body bytes (extra: yara)."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from reliquary.core.paths import app_dir

_rules_lock = threading.Lock()
_compiled_rules: dict[str, Any] = {}
_compile_notes: dict[str, list[str]] = {}


def yara_available() -> bool:
    try:
        import yara  # type: ignore[import-untyped]  # noqa: F401

        return True
    except ImportError:
        return False


def resolve_rules_path(explicit: str | Path | None = None) -> Path | None:
    """Rules file or folder. Never reads a path packed inside a frozen EXE."""
    if explicit and str(explicit).strip():
        p = Path(str(explicit).strip())
        return p if p.is_file() or p.is_dir() else None
    for name in ("yara_rules.yar", "yara_rules.yara", "rules.yar", "default.yar"):
        cand = app_dir() / name
        if cand.is_file():
            return cand
    folder = app_dir() / "yara_rules"
    if folder.is_dir():
        files = list(folder.glob("*.yar")) + list(folder.glob("*.yara"))
        if files:
            # Prefer default.yar when present
            for preferred in sorted(files):
                if preferred.name == "default.yar":
                    return folder
            return folder
    return None


def clear_rules_cache() -> None:
    """Drop the compiled rules kept for the current batch."""
    with _rules_lock:
        _compiled_rules.clear()
        _compile_notes.clear()


def compiled_rules(
    rules_path: str | Path | None = None,
) -> tuple[Any | None, list[str]]:
    """Compile rules once per path and reuse them for every buffer in the batch."""
    notes: list[str] = []
    try:
        import yara  # type: ignore[import-untyped]
    except ImportError:
        return None, ["YARA: пакет не установлен (pip install .[yara])"]
    path = resolve_rules_path(rules_path)
    if path is None:
        if rules_path and str(rules_path).strip():
            return None, ["YARA: правила по указанному пути не найдены"]
        return None, ["YARA: укажите путь к правилам в настройках"]
    try:
        key = str(path.resolve())
    except OSError:
        key = str(path)
    with _rules_lock:
        if key in _compiled_rules or key in _compile_notes:
            return _compiled_rules.get(key), list(_compile_notes.get(key, []))
        try:
            if path.is_dir():
                mapping = {
                    f"r{i}": str(p)
                    for i, p in enumerate(
                        sorted(path.glob("*.yar")) + sorted(path.glob("*.yara"))
                    )
                }
                if not mapping:
                    _compile_notes[key] = ["YARA: пустая папка правил"]
                    return None, list(_compile_notes[key])
                rules = yara.compile(filepaths=mapping)
            else:
                rules = yara.compile(filepath=str(path))
        except Exception as exc:  # noqa: BLE001 — yara errors vary
            _compile_notes[key] = [f"YARA: {type(exc).__name__}: {exc}"]
            return None, list(_compile_notes[key])
        _compiled_rules[key] = rules
        _compile_notes[key] = []
        return rules, notes


def scan_bytes(
    data: bytes,
    *,
    rules_path: str | Path | None = None,
    timeout: int = 5,
    compiled: Any | None = None,
) -> tuple[list[str], list[str]]:
    """Return (match_rule_names, notes). Empty if yara missing or no rules."""
    if not data:
        return [], []
    rules = compiled
    notes: list[str] = []
    if rules is None:
        rules, notes = compiled_rules(rules_path)
    if rules is None:
        return [], notes
    try:
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
    rules, notes = compiled_rules(rules_path)
    if rules is None:
        return [], notes
    blob = body.encode("utf-8", errors="replace") if isinstance(body, str) else body
    if blob:
        h, n = scan_bytes(blob, rules_path=rules_path, compiled=rules)
        hits.extend(h)
        notes.extend(n)
    for att in attachments or []:
        data = getattr(att, "data", None)
        if not data:
            continue
        h, n = scan_bytes(data, rules_path=rules_path, compiled=rules)
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
