"""Offline FP/FN analyst feedback — NDJSON beside the EXE (no DB)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reliquary.core.paths import app_dir

_FEEDBACK_NAME = "analyst_feedback.ndjson"


def feedback_path() -> Path:
    return app_dir() / _FEEDBACK_NAME


@dataclass
class FeedbackEvent:
    kind: str  # fp | fn | confirm
    expected_level: str
    observed_level: str
    score: int | None
    source_path: str
    source_sha256: str = ""
    note: str = ""
    segment: str = ""
    recorded_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def append_feedback(event: FeedbackEvent) -> Path:
    """Append one NDJSON line; returns the feedback file path."""
    if not event.recorded_at:
        event.recorded_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = feedback_path()
    line = json.dumps(event.to_dict(), ensure_ascii=False)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return path


def load_feedback(limit: int = 500) -> list[dict[str, Any]]:
    path = feedback_path()
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows[-limit:]


def feedback_summary(rows: list[dict[str, Any]] | None = None) -> str:
    rows = rows if rows is not None else load_feedback()
    if not rows:
        return "Нет записей обратной связи (analyst_feedback.ndjson)."
    counts: dict[str, int] = {}
    for r in rows:
        k = str(r.get("kind") or "?")
        counts[k] = counts.get(k, 0) + 1
    parts = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    return f"Обратная связь: {len(rows)} записей ({parts}) → {feedback_path().name}"
