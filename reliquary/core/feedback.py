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


# Segment → related VerdictConfig weight keys (heuristic mapping for ±2 suggestions)
_SEGMENT_WEIGHTS: dict[str, tuple[str, ...]] = {
    "bec": ("weight_bec_payment",),
    "display_spoof": ("weight_display_spoof", "weight_lookalike", "weight_spf_lookalike"),
    "shortener": ("weight_url_shortener",),
    "messenger": ("weight_messenger_only", "weight_messenger_lure"),
    "messenger_lure": ("weight_messenger_lure",),
    "qr_lure": ("weight_qr_lure", "weight_qr_credential", "weight_qr_present"),
    "html_smuggling": ("weight_html_smuggling",),
    "html_polyglot": ("weight_html_polyglot",),
    "cab": ("weight_cab_archive",),
    "remote_template": ("weight_office_remote_template",),
    "office_link": ("weight_office_hyperlink",),
    "script_att": ("weight_script_attachment",),
    "cloud_lure": ("weight_cloud_lure",),
    "tnef": ("weight_tnef",),
    "rar": ("weight_rar_archive",),
    "iso_exe": ("weight_iso_exe", "weight_attachment_iso"),
    "iso": ("weight_attachment_iso", "weight_iso_lnk", "weight_iso_exe"),
    "archive_password": ("weight_archive_password", "weight_archive_password_match"),
    "oob_delivery": ("weight_oob_delivery",),
    "nested_mail": ("weight_archive_nested_email",),
    "safelinks": ("weight_url_rewrite",),
    "ru_rewrite": ("weight_url_rewrite",),
    "rewrite": ("weight_url_rewrite",),
    "phishing_content": ("weight_credential_harvest", "weight_href_mismatch"),
    "attachment": ("weight_attachment_flag",),
}


def suggest_weight_overrides(rows: list[dict[str, Any]] | None = None) -> dict[str, int]:
    """Aggregate FP/FN by segment and suggest ±2 adjustments for related weights.

    FN (missed malicious) → raise related weights by 2.
    FP (benign scored high) → lower related weights by 2.
    Multiple events on the same weight accumulate (±2 each), clamped to ±10.
    """
    rows = rows if rows is not None else load_feedback()
    deltas: dict[str, int] = {}
    for r in rows:
        kind = str(r.get("kind") or "").lower()
        if kind not in ("fp", "fn"):
            continue
        seg = str(r.get("segment") or "").strip().lower()
        keys = _SEGMENT_WEIGHTS.get(seg)
        if not keys:
            continue
        step = 2 if kind == "fn" else -2
        for key in keys:
            deltas[key] = deltas.get(key, 0) + step
    out: dict[str, int] = {}
    for key, val in sorted(deltas.items()):
        clamped = max(-10, min(10, val))
        if clamped:
            out[key] = clamped
    return out


def write_weight_suggestions(path: str | Path, rows: list[dict[str, Any]] | None = None) -> Path:
    """Write suggest_weight_overrides() as JSON suitable for merging into verdict_extra."""
    suggestions = suggest_weight_overrides(rows)
    out = Path(path)
    payload = {
        "_comment": "Suggested ±2 weight deltas from analyst_feedback.ndjson (FP/FN by segment).",
        **suggestions,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return out
