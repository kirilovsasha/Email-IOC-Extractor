"""Export helpers shared by GUI (path selection stays in the UI layer)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from reliquary.core.exporters import (
    export_case_pack,
    export_case_pack_multi,
    export_csv,
    export_misp,
    export_opencti,
    export_report_json,
    export_stix,
    export_yara,
)
from reliquary.core.models import AnalysisResult

EXPORT_CHOICES = (
    "CSV",
    "STIX",
    "JSON",
    "MISP",
    "OpenCTI",
    "YARA",
    "Case pack",
    "Case pack (по файлам)",
)

ExportFn = Callable[..., Path]


def normalize_export_kind(kind: str) -> str:
    k = kind.strip().lower()
    if k in ("case pack", "case_pack", "casepack"):
        return "case_pack"
    if "по файлам" in k or k.endswith("(per file)") or k == "case_pack_multi":
        return "case_pack_multi"
    return k


def run_export(
    kind: str,
    result: AnalysisResult,
    path: str | Path,
    *,
    filters_applied: dict[str, Any] | None = None,
    batch_results: list[AnalysisResult] | None = None,
    focus_source_file: str = "",
    include_attachments: bool = True,
) -> Path:
    """Write export to ``path``. Raises ValueError on missing batch data."""
    kind_n = normalize_export_kind(kind)
    out = Path(path)
    iocs = result.iocs

    if kind_n == "csv":
        return export_csv(result, out)
    if kind_n == "stix":
        return export_stix(result, out)
    if kind_n == "json":
        return export_report_json(result, out, filters_applied=filters_applied)
    if kind_n == "misp":
        return export_misp(result, out, iocs=iocs)
    if kind_n == "opencti":
        return export_opencti(result, out, iocs=iocs)
    if kind_n == "yara":
        return export_yara(result, out, iocs=iocs)
    if kind_n == "case_pack":
        return export_case_pack(
            result,
            out,
            filters_applied=filters_applied,
            include_attachments=include_attachments,
        )
    if kind_n == "case_pack_multi":
        results = list(batch_results or [])
        if not results:
            raise ValueError("Нет per-file результатов для экспорта")
        if focus_source_file:
            focused = [
                r for r in results if Path(r.source_path).name == focus_source_file
            ]
            if focused:
                results = focused
        return export_case_pack_multi(
            results,
            out,
            filters_applied=filters_applied,
            include_attachments=include_attachments,
        )
    raise ValueError(f"Неизвестный формат экспорта: {kind}")


def default_export_filename(kind: str) -> str:
    kind_n = normalize_export_kind(kind)
    return {
        "csv": "iocs.csv",
        "stix": "iocs_stix.json",
        "json": "iocs_report.json",
        "misp": "iocs_misp.json",
        "opencti": "iocs_opencti.json",
        "yara": "ioc_extractor_iocs.yar",
        "case_pack": "case_pack.zip",
        "case_pack_multi": "case_pack_per_file.zip",
    }.get(kind_n, "export.bin")
