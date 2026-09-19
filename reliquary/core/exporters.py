"""Export analysis results — CSV, JSON, and per-mail batch triage."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from reliquary.core.models import AnalysisResult, Ioc, IocType


def filter_iocs(
    result: AnalysisResult,
    types: set[str] | None = None,
    *,
    hide_private: bool = False,
    hide_rewriter: bool = False,
    hide_allowlisted: bool = False,
    actionable_only: bool = False,
    search: str = "",
    source_file: str = "",
) -> list[Ioc]:
    """Filter IOCs for GUI / export.

    ``actionable_only`` hides private, rewriter/noise, allowlisted, and bare
    filename IOCs (attachment names without risk flags).
    """
    q = (search or "").strip().lower()
    base = Path(source_file).name.lower() if source_file else ""
    out: list[Ioc] = []
    for ioc in result.iocs:
        if types is not None and ioc.ioc_type.value not in types:
            continue
        if hide_private and "private" in ioc.tags:
            continue
        if hide_rewriter and ("url_rewriter" in ioc.tags or "noise_candidate" in ioc.tags):
            continue
        if hide_allowlisted and "allowlisted" in ioc.tags:
            continue
        if actionable_only:
            if "private" in ioc.tags:
                continue
            if "url_rewriter" in ioc.tags or "noise_candidate" in ioc.tags:
                continue
            if "allowlisted" in ioc.tags:
                continue
            if ioc.ioc_type == IocType.FILENAME and not any(
                t in ioc.tags
                for t in (
                    "double_extension",
                    "dangerous_extension",
                    "archive_dangerous_member",
                    "nested_email",
                    "qr",
                )
            ):
                continue
        if base:
            file_tags = [t for t in ioc.tags if t.startswith("file:")]
            if file_tags and not any(t[5:].lower() == base for t in file_tags):
                continue
        if q:
            hay = " ".join(
                [
                    ioc.value.lower(),
                    ioc.ioc_type.value,
                    " ".join(ioc.tags).lower(),
                    (ioc.context or "").lower(),
                ]
            )
            if q not in hay:
                continue
        out.append(ioc)
    return sort_iocs(out)


_HASH_TYPES = frozenset({"md5", "sha1", "sha256"})


def sort_iocs(iocs: list[Ioc]) -> list[Ioc]:
    """unwrapped → hashes → rest (stable within group)."""

    def rank(ioc: Ioc) -> tuple[int, str, str]:
        if "unwrapped" in ioc.tags:
            tier = 0
        elif ioc.ioc_type.value in _HASH_TYPES or "attachment_hash" in ioc.tags:
            tier = 1
        else:
            tier = 2
        return (tier, ioc.ioc_type.value, ioc.value.lower())

    return sorted(iocs, key=rank)


def with_iocs(result: AnalysisResult, iocs: list[Ioc]) -> AnalysisResult:
    """Shallow copy result with replaced IOC list for exporters / GUI."""
    return AnalysisResult(
        source_path=result.source_path,
        source_kind=result.source_kind,
        subject=result.subject,
        sender=result.sender,
        recipients=list(result.recipients),
        iocs=iocs,
        headers=list(result.headers),
        raw_headers=dict(result.raw_headers),
        mail_identity=result.mail_identity,
        url_rewrites=list(result.url_rewrites),
        attachments=list(result.attachments),
        verdict=result.verdict,
        raw_text_preview=result.raw_text_preview,
        errors=list(result.errors),
        file_rows=list(result.file_rows),
        meta=result.meta,
    )


def export_csv(result: AnalysisResult, path: str | Path) -> Path:
    out = Path(path)
    fieldnames = [
        "ioc_type",
        "value",
        "source",
        "context",
        "rewritten_from",
        "tags",
        "verdict",
        "score",
        "subject",
        "sender",
        "file",
    ]
    verdict_level = result.verdict.level.value if result.verdict else ""
    score = result.verdict.score if result.verdict else ""
    with out.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        rows: Iterable[Ioc] = result.iocs
        if not result.iocs:
            writer.writerow(
                {
                    "ioc_type": "",
                    "value": "",
                    "source": "",
                    "context": "",
                    "rewritten_from": "",
                    "tags": "",
                    "verdict": verdict_level,
                    "score": score,
                    "subject": result.subject,
                    "sender": result.sender,
                    "file": result.source_path,
                }
            )
        for ioc in rows:
            writer.writerow(
                {
                    "ioc_type": ioc.ioc_type.value,
                    "value": ioc.value,
                    "source": ioc.source,
                    "context": ioc.context,
                    "rewritten_from": ioc.rewritten_from or "",
                    "tags": "|".join(ioc.tags),
                    "verdict": verdict_level,
                    "score": score,
                    "subject": result.subject,
                    "sender": result.sender,
                    "file": result.source_path,
                }
            )
    return out


def export_batch_csv(
    result: AnalysisResult,
    path: str | Path,
    *,
    batch_results: list[AnalysisResult] | None = None,
) -> Path:
    """One row per mail — triage summary for folder batches."""
    out = Path(path)
    fieldnames = [
        "file",
        "kind",
        "verdict",
        "score",
        "ioc_count",
        "subject",
        "sender",
        "message_id",
        "top_iocs",
        "top_reason",
        "errors",
    ]
    rows = list(result.file_rows or [])
    if not rows and batch_results:
        from reliquary.core.pipeline import file_triage_row

        rows = [file_triage_row(r) for r in batch_results]
    with out.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        if not rows:
            writer.writerow(
                {
                    "file": result.source_path,
                    "kind": result.source_kind,
                    "verdict": result.verdict.level.value if result.verdict else "",
                    "score": result.verdict.score if result.verdict else "",
                    "ioc_count": len(result.iocs),
                    "subject": result.subject,
                    "sender": result.sender,
                    "message_id": (
                        result.mail_identity.message_id if result.mail_identity else ""
                    ),
                    "top_iocs": "",
                    "top_reason": "",
                    "errors": "|".join(result.errors[:5]),
                }
            )
        for row in rows:
            writer.writerow(
                {
                    "file": row.path,
                    "kind": row.kind,
                    "verdict": row.verdict_level or "",
                    "score": row.verdict_score if row.verdict_score is not None else "",
                    "ioc_count": row.ioc_count,
                    "subject": row.subject,
                    "sender": row.sender,
                    "message_id": row.message_id,
                    "top_iocs": "|".join(row.top_iocs[:8]),
                    "top_reason": row.top_reason or "",
                    "errors": "|".join(row.errors[:5]),
                }
            )
    return out


def export_report_json(
    result: AnalysisResult,
    path: str | Path,
    *,
    filters_applied: dict | None = None,
    batch_results: list[AnalysisResult] | None = None,
) -> Path:
    out = Path(path)
    payload = result.to_dict()
    if result.meta is not None and filters_applied is not None:
        meta = dict(payload.get("meta") or {})
        meta["filters_applied"] = filters_applied
        payload["meta"] = meta
    elif filters_applied is not None:
        payload["meta"] = {
            "filters_applied": filters_applied,
        }
    if batch_results and len(batch_results) > 1:
        payload["batch"] = [
            {
                "source_path": r.source_path,
                "source_kind": r.source_kind,
                "subject": r.subject,
                "sender": r.sender,
                "verdict": r.verdict.to_dict() if r.verdict else None,
                "ioc_count": len(r.iocs),
                "iocs": [i.to_dict() for i in r.iocs],
                "errors": list(r.errors),
                "mail_identity": r.mail_identity.to_dict() if r.mail_identity else None,
            }
            for r in batch_results
        ]
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out
