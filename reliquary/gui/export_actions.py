"""Export helpers shared by GUI (path selection stays in the UI layer)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reliquary.core.campaign import export_campaign_handoff, export_campaign_pack
from reliquary.core.export_hook import run_post_export_hook
from reliquary.core.exporters import (
    export_batch_csv,
    export_cef,
    export_csv,
    export_ecs_json,
    export_misp_csv,
    export_opencti_json,
    export_report_json,
    export_stix_lite,
)
from reliquary.core.handoff import export_handoff
from reliquary.core.models import AnalysisResult, Ioc
from reliquary.core.prefs import load_prefs

EXPORT_CHOICES = (
    "JSON",
    "CSV",
    "Batch CSV",
    "Тикет",
)


def normalize_export_kind(kind: str) -> str:
    raw = kind.strip().lower().replace(" ", "_")
    aliases = {
        "тикет": "handoff",
        "handoff": "handoff",
        "кампания": "campaign",
        "campaign_handoff": "campaign",
        "campaign_pack": "campaign_pack",
        "pack": "campaign_pack",
        "opencti": "opencti",
        "misp_csv": "misp",
    }
    return aliases.get(raw, raw)


def run_export(
    kind: str,
    result: AnalysisResult,
    path: str | Path,
    *,
    filters_applied: dict[str, Any] | None = None,
    batch_results: list[AnalysisResult] | None = None,
    filtered_iocs: list[Ioc] | None = None,
    ioc_summary: str | None = None,
    handoff_template_path: str | Path | None = None,
    handoff_by_level: dict[str, Path | str] | None = None,
    post_export_hook: str | Path | None = None,
) -> Path:
    """Write export to ``path``; optionally run ``post_export_hook``."""
    kind_n = normalize_export_kind(kind)
    out = Path(path)
    if kind_n in ("csv",):
        written = export_csv(result, out, ioc_summary=ioc_summary)
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
    elif kind_n == "campaign":
        written = export_campaign_handoff(batch_results or [result], out)
    elif kind_n == "campaign_pack":
        written = export_campaign_pack(
            batch_results or [result],
            out,
            fmt="cef" if out.suffix.lower() == ".cef" else "ndjson",
        )
    elif kind_n == "json":
        written = export_report_json(
            result,
            out,
            filters_applied=filters_applied,
            batch_results=batch_results,
        )
    elif kind_n == "ecs":
        written = export_ecs_json(result, out)
    elif kind_n == "cef":
        written = export_cef(result, out)
    elif kind_n == "stix":
        written = export_stix_lite(result, out)
    elif kind_n == "misp":
        written = export_misp_csv(result, out)
    elif kind_n == "opencti":
        written = export_opencti_json(result, out)
    else:
        raise ValueError(f"Неизвестный формат экспорта: {kind}")

    hook = post_export_hook
    prefs = load_prefs()
    if hook is None:
        hook = str(prefs.get("post_export_hook") or "")
    sidecar_arg: Path | None = None
    if hook and bool(prefs.get("post_export_hook_json_sidecar", True)):
        if written.suffix.lower() != ".json":
            try:
                sidecar_arg = written.with_name(written.stem + ".sidecar.json")
                export_report_json(
                    result,
                    sidecar_arg,
                    filters_applied=filters_applied,
                    batch_results=batch_results,
                )
            except (OSError, TypeError, ValueError) as exc:
                from reliquary.core.error_log import append_error_log

                append_error_log(f"json sidecar failed: {exc}")
                sidecar_arg = None
    run_post_export_hook(
        hook,
        written,
        allow_external=bool(prefs.get("post_export_hook_allow_external")),
        disabled=bool(prefs.get("disable_post_export_hook")),
        json_sidecar=sidecar_arg,
    )
    return written


def default_export_filename(kind: str) -> str:
    kind_n = normalize_export_kind(kind)
    return {
        "csv": "mail_iocs.csv",
        "batch_csv": "mail_batch_triage.csv",
        "json": "verdict_report.json",
        "handoff": "mail_handoff.txt",
        "campaign": "campaign_handoff.txt",
        "campaign_pack": "campaign_pack.ndjson",
        "ecs": "mail_ecs.json",
        "cef": "mail_siem.cef",
        "stix": "mail_stix_bundle.json",
        "misp": "mail_misp_attributes.csv",
        "opencti": "mail_opencti.json",
    }.get(kind_n, "export.bin")
