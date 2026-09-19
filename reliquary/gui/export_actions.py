"""Export helpers shared by GUI (path selection stays in the UI layer)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reliquary.core.exporters import export_batch_csv, export_csv, export_report_json
from reliquary.core.handoff import export_handoff
from reliquary.core.models import AnalysisResult, Ioc

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
) -> Path:
    """Write export to ``path``."""
    kind_n = normalize_export_kind(kind)
    out = Path(path)
    if kind_n in ("csv",):
        return export_csv(result, out)
    if kind_n in ("batch_csv", "batch-csv"):
        return export_batch_csv(result, out, batch_results=batch_results)
    if kind_n == "handoff":
        return export_handoff(
            result,
            out,
            iocs=filtered_iocs,
            template_path=handoff_template_path,
            handoff_by_level=handoff_by_level,
        )
    if kind_n == "json":
        return export_report_json(
            result,
            out,
            filters_applied=filters_applied,
            batch_results=batch_results,
        )
    raise ValueError(f"Неизвестный формат экспорта: {kind}")


def default_export_filename(kind: str) -> str:
    kind_n = normalize_export_kind(kind)
    return {
        "csv": "mail_iocs.csv",
        "batch_csv": "mail_batch_triage.csv",
        "json": "verdict_report.json",
        "handoff": "mail_handoff.txt",
    }.get(kind_n, "export.bin")
