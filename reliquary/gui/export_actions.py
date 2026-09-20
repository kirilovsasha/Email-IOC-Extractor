"""Export helpers shared by GUI (path selection stays in the UI layer)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reliquary.core.export_hook import run_post_export_hook
from reliquary.core.exporters import export_batch_csv, export_csv, export_report_json
from reliquary.core.handoff import export_handoff
from reliquary.core.models import AnalysisResult, Ioc
from reliquary.core.prefs import load_prefs

EXPORT_CHOICES = ("JSON", "CSV", "Batch CSV", "Handoff")


def normalize_export_kind(kind: str) -> str:
    return kind.strip().lower().replace(" ", "_")


def run_export(
    kind: str,
    result: AnalysisResult,
    path: str | Path,
    *,
    filters_applied: dict[str, Any] | None = None,
    batch_results: list[AnalysisResult] | None = None,
    filtered_iocs: list[Ioc] | None = None,
    handoff_template_path: str | Path | None = None,
    handoff_by_level: dict[str, Path | str] | None = None,
    post_export_hook: str | Path | None = None,
) -> Path:
    """Write export to ``path``; optionally run ``post_export_hook``."""
    kind_n = normalize_export_kind(kind)
    out = Path(path)
    if kind_n in ("csv",):
        written = export_csv(result, out)
    elif kind_n in ("batch_csv", "batch-csv"):
        written = export_batch_csv(result, out, batch_results=batch_results)
    elif kind_n == "handoff":
        written = export_handoff(
            result,
            out,
            iocs=filtered_iocs,
            template_path=handoff_template_path,
            handoff_by_level=handoff_by_level,
        )
    elif kind_n == "json":
        written = export_report_json(
            result,
            out,
            filters_applied=filters_applied,
            batch_results=batch_results,
        )
    else:
        raise ValueError(f"Неизвестный формат экспорта: {kind}")

    hook = post_export_hook
    prefs = load_prefs()
    if hook is None:
        hook = str(prefs.get("post_export_hook") or "")
    run_post_export_hook(
        hook,
        written,
        allow_external=bool(prefs.get("post_export_hook_allow_external")),
        disabled=bool(prefs.get("disable_post_export_hook")),
    )
    return written


def default_export_filename(kind: str) -> str:
    kind_n = normalize_export_kind(kind)
    return {
        "csv": "mail_iocs.csv",
        "batch_csv": "mail_batch_triage.csv",
        "json": "verdict_report.json",
        "handoff": "mail_handoff.txt",
    }.get(kind_n, "export.bin")
