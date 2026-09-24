"""Expand .mbox mailboxes into temporary .eml files for batch triage."""

from __future__ import annotations

import mailbox
import tempfile
from pathlib import Path


def is_mbox(path: str | Path) -> bool:
    return Path(path).suffix.lower() == ".mbox"


def expand_mbox_to_emls(
    path: str | Path,
    *,
    dest: Path | None = None,
    limit: int = 500,
    notes: list[str] | None = None,
) -> tuple[list[str], Path]:
    """Write each mbox message as ``NNNN.eml`` under ``dest`` (temp if omitted).

    Returns (eml paths, dest directory). Caller may delete dest when done.
    When more than ``limit`` messages exist, ``notes`` gets one skip line.
    """
    src = Path(path)
    owned = dest is None
    if dest is None:
        dest = Path(tempfile.mkdtemp(prefix="reliquary_mbox_"))
    else:
        dest.mkdir(parents=True, exist_ok=True)
    if owned:
        from reliquary.core.formats import register_ingest_temp

        register_ingest_temp(dest)
    out: list[str] = []
    skipped = 0
    mbox = mailbox.mbox(str(src))
    try:
        for i, msg in enumerate(mbox):
            if i >= limit:
                skipped += 1
                continue
            try:
                raw = msg.as_bytes()
            except Exception:
                try:
                    raw = str(msg).encode("utf-8", errors="replace")
                except Exception:
                    continue
            name = dest / f"{i:04d}.eml"
            name.write_bytes(raw)
            out.append(str(name))
    finally:
        try:
            mbox.close()
        except Exception:
            pass
    if skipped:
        line = f"mbox «{src.name}»: пропущено {skipped} писем — остальные не разобраны"
        if notes is not None and line not in notes:
            notes.append(line)
        from reliquary.core.formats import push_ingest_note

        push_ingest_note(line)
    return out, dest
