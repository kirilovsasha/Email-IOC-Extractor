"""Expand .mbox mailboxes into temporary .eml files for batch triage."""

from __future__ import annotations

import mailbox
import tempfile
from pathlib import Path


def is_mbox(path: str | Path) -> bool:
    return Path(path).suffix.lower() == ".mbox"


def expand_mbox_to_emls(
    path: str | Path, *, dest: Path | None = None, limit: int = 500
) -> tuple[list[str], Path]:
    """Write each mbox message as ``NNNN.eml`` under ``dest`` (temp if omitted).

    Returns (eml paths, dest directory). Caller may delete dest when done.
    """
    src = Path(path)
    if dest is None:
        dest = Path(tempfile.mkdtemp(prefix="reliquary_mbox_"))
    else:
        dest.mkdir(parents=True, exist_ok=True)
    out: list[str] = []
    mbox = mailbox.mbox(str(src))
    try:
        for i, msg in enumerate(mbox):
            if i >= limit:
                break
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
    return out, dest
