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
    "office_dde": ("weight_office_dde",),
    "ole_package": ("weight_ole_package",),
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
    "wrap_lure": ("weight_wrap_lure", "weight_url_rewrite"),
    "cid_phishing": ("weight_cid_phishing",),
    "form_action": ("weight_form_action_suspicious",),
    "arc_fail": ("weight_arc_fail",),
    "reply_chain": ("weight_reply_chain_anomaly",),
    "return_path": ("weight_return_path_mismatch",),
    "campaign": ("weight_campaign_divergence",),
    "pdf_openaction": ("weight_pdf_openaction_uri",),
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


def suggest_threshold_overrides(rows: list[dict[str, Any]] | None = None) -> dict[str, int]:
    """Suggest threshold_suspicious / threshold_malicious / cap_* from FP/FN rates.

    Beyond ±2 weights: if FP rate is high overall or in noisy segments, raise
    thresholds and/or lower caps; if FN rate is high, lower thresholds.
    Returns absolute suggested values (not deltas) for keys that should change.
    """
    rows = rows if rows is not None else load_feedback()
    fp = sum(1 for r in rows if str(r.get("kind") or "").lower() == "fp")
    fn = sum(1 for r in rows if str(r.get("kind") or "").lower() == "fn")
    confirm = sum(1 for r in rows if str(r.get("kind") or "").lower() == "confirm")
    total = fp + fn + confirm
    if total < 3 or (fp + fn) == 0:
        return {}

    out: dict[str, int] = {}
    fp_rate = fp / max(1, fp + fn)
    fn_rate = fn / max(1, fp + fn)

    # Defaults from VerdictConfig
    thr_sus = 30
    thr_mal = 60
    cap_headers = 45
    cap_lookalike = 30
    cap_display = 28
    cap_content = 40

    if fp_rate >= 0.55 and fp >= 2:
        thr_sus = min(45, thr_sus + 5)
        thr_mal = min(75, thr_mal + 5)
        cap_headers = max(35, cap_headers - 5)
        cap_lookalike = max(22, cap_lookalike - 4)
        cap_display = max(20, cap_display - 4)
        out["threshold_suspicious"] = thr_sus
        out["threshold_malicious"] = thr_mal
        out["cap_headers"] = cap_headers
        out["cap_lookalike"] = cap_lookalike
        out["cap_display_spoof"] = cap_display
    elif fp_rate >= 0.35 and fp >= 2:
        thr_sus = min(40, thr_sus + 3)
        out["threshold_suspicious"] = thr_sus
        out["cap_display_spoof"] = max(22, cap_display - 2)

    if fn_rate >= 0.55 and fn >= 2:
        thr_sus = max(18, thr_sus - 5)
        thr_mal = max(45, thr_mal - 5)
        out["threshold_suspicious"] = thr_sus
        out["threshold_malicious"] = thr_mal
        out["cap_content"] = min(50, cap_content + 5)
    elif fn_rate >= 0.35 and fn >= 2:
        thr_sus = max(22, (out.get("threshold_suspicious") or thr_sus) - 3)
        out["threshold_suspicious"] = thr_sus

    # Segment-specific caps
    seg_fp: dict[str, int] = {}
    for r in rows:
        if str(r.get("kind") or "").lower() != "fp":
            continue
        seg = str(r.get("segment") or "").strip().lower()
        if seg:
            seg_fp[seg] = seg_fp.get(seg, 0) + 1
    if seg_fp.get("display_spoof", 0) >= 2:
        out["cap_display_spoof"] = min(out.get("cap_display_spoof", cap_display), 22)
        out["cap_lookalike"] = min(out.get("cap_lookalike", cap_lookalike), 24)
    if seg_fp.get("safelinks", 0) + seg_fp.get("rewrite", 0) >= 2:
        out["cap_urls"] = 22

    return out


def write_weight_suggestions(path: str | Path, rows: list[dict[str, Any]] | None = None) -> Path:
    """Write weight + threshold suggestions as JSON suitable for verdict_extra merge."""
    suggestions = suggest_weight_overrides(rows)
    thresholds = suggest_threshold_overrides(rows)
    out = Path(path)
    payload = {
        "_comment": (
            "Suggested weight deltas (±2) and threshold/cap overrides from "
            "analyst_feedback.ndjson (FP/FN by segment)."
        ),
        **suggestions,
        **thresholds,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return out
