"""Export analysis results — CSV, JSON, and per-mail batch triage."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from reliquary.core.models import SCHEMA_VERSION, AnalysisResult, Ioc, IocType


def source_file_matches(tag_value: str, wanted: str) -> bool:
    """Match an IOC ``file:`` tag to a focus path. Full path wins over the basename."""
    got = (tag_value or "").replace("\\", "/").rstrip("/").lower()
    want = (wanted or "").replace("\\", "/").rstrip("/").lower()
    if not want:
        return True
    if got == want:
        return True
    if "/" not in got:
        return got == want.rsplit("/", 1)[-1]
    return False


def file_display_name(tag_value: str) -> str:
    text = (tag_value or "").replace("\\", "/")
    return text.rsplit("/", 1)[-1]


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
        if source_file:
            file_tags = [t for t in ioc.tags if t.startswith("file:")]
            if file_tags and not any(source_file_matches(t[5:], source_file) for t in file_tags):
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


def _verdict_fields(result: AnalysisResult) -> tuple[str, int, str]:
    if not result.verdict:
        return "", 0, ""
    return (
        result.verdict.level.value,
        int(result.verdict.score),
        result.verdict.summary or "",
    )


def export_ecs_json(result: AnalysisResult, path: str | Path) -> Path:
    """Elastic Common Schema–shaped JSON for SIEM ingest (offline file only)."""
    out = Path(path)
    level, score, summary = _verdict_fields(result)
    threat_objects = []
    for ioc in result.iocs:
        entry: dict = {
            "indicator": {
                "type": ioc.ioc_type.value,
                "description": ioc.context or "",
                "marking": {"tlp": "amber"},
            },
            "tags": list(ioc.tags),
        }
        t = ioc.ioc_type.value
        if t == "url":
            entry["url"] = {"full": ioc.value}
        elif t == "domain":
            entry["dns"] = {"question": {"name": ioc.value}}
        elif t in ("ipv4", "ipv6", "ip_port"):
            entry["ip"] = ioc.value
        elif t in ("md5", "sha1", "sha256"):
            entry["hash"] = {t: ioc.value}
        elif t == "email":
            entry["email"] = {"address": ioc.value}
        else:
            entry["indicator"]["name"] = ioc.value
        threat_objects.append(entry)

    payload = {
        "@timestamp": None,
        "event": {
            "kind": "alert",
            "category": ["email"],
            "type": ["info"],
            "dataset": "reliquary.email_ioc",
            "severity": level or "unknown",
            "risk_score": score,
            "reason": summary,
        },
        "email": {
            "subject": result.subject,
            "from": {"address": result.sender},
            "message_id": (
                result.mail_identity.message_id if result.mail_identity else ""
            ),
        },
        "file": {"path": result.source_path, "name": Path(result.source_path).name},
        "threat": {"indicator": threat_objects},
        "reliquary": {
            "schema_version": result.to_dict().get("schema_version"),
            "verdict": result.verdict.to_dict() if result.verdict else None,
            "url_rewrites": [u.to_dict() for u in result.url_rewrites],
        },
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


_CEF_SEV = {
    "benign": 1,
    "unknown": 3,
    "suspicious": 6,
    "malicious": 9,
}


def export_cef(result: AnalysisResult, path: str | Path) -> Path:
    """ArcSight CEF lines (one per IOC + header summary line)."""
    out = Path(path)
    level, score, summary = _verdict_fields(result)
    sev = _CEF_SEV.get(level, 3)
    vendor = "Reliquary"
    product = "EmailIOCExtractor"
    version = "1.0"
    msg_id = result.mail_identity.message_id if result.mail_identity else ""
    lines: list[str] = []

    def _esc(value: str) -> str:
        return (
            (value or "")
            .replace("\\", "\\\\")
            .replace("=", "\\=")
            .replace("\n", " ")
            .replace("\r", " ")
        )

    header = (
        f"CEF:0|{vendor}|{product}|{version}|verdict|{_esc(level or 'none')}|{sev}|"
        f"msg={_esc(summary)} cs1={_esc(result.subject)} "
        f"cs1Label=Subject suser={_esc(result.sender)} "
        f"filePath={_esc(result.source_path)} cn1={score} cn1Label=Score "
        f"cs2={_esc(msg_id)} cs2Label=MessageId"
    )
    lines.append(header)
    for ioc in result.iocs:
        itype = ioc.ioc_type.value
        ext = f"cs3={_esc(itype)} cs3Label=IocType cs4={_esc('|'.join(ioc.tags))} cs4Label=Tags"
        if itype == "url":
            ext = f"request={_esc(ioc.value)} {ext}"
        elif itype in ("ipv4", "ipv6", "ip_port"):
            ext = f"src={_esc(ioc.value)} {ext}"
        elif itype == "domain":
            ext = f"dhost={_esc(ioc.value)} {ext}"
        elif itype in ("md5", "sha1", "sha256"):
            ext = f"fileHash={_esc(ioc.value)} {ext}"
        else:
            ext = f"cs5={_esc(ioc.value)} cs5Label=Value {ext}"
        lines.append(
            f"CEF:0|{vendor}|{product}|{version}|ioc|{_esc(itype)}|{sev}|{ext}"
        )
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def export_stix_lite(result: AnalysisResult, path: str | Path) -> Path:
    """Minimal STIX 2.1 bundle (indicators + email-message observed context)."""
    out = Path(path)
    level, score, summary = _verdict_fields(result)
    objects: list[dict] = []
    bundle_id = "bundle--reliquary-offline"
    email_id = "email-message--reliquary-source"
    objects.append(
        {
            "type": "email-message",
            "id": email_id,
            "spec_version": "2.1",
            "is_multipart": False,
            "subject": result.subject,
            "from_ref": result.sender,
            "additional_header_fields": {
                "Message-ID": (
                    result.mail_identity.message_id if result.mail_identity else ""
                )
            },
            "x_reliquary_verdict": level,
            "x_reliquary_score": score,
            "x_reliquary_summary": summary,
            "x_reliquary_source_path": result.source_path,
        }
    )
    for idx, ioc in enumerate(result.iocs):
        pattern = _stix_pattern(ioc.ioc_type.value, ioc.value)
        if not pattern:
            continue
        objects.append(
            {
                "type": "indicator",
                "id": f"indicator--reliquary-{idx}",
                "spec_version": "2.1",
                "name": f"{ioc.ioc_type.value}:{ioc.value[:80]}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": "1970-01-01T00:00:00.000Z",
                "labels": [level or "unknown", *list(ioc.tags)[:8]],
                "description": ioc.context or summary,
            }
        )
    payload = {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def _stix_pattern(ioc_type: str, value: str) -> str | None:
    esc = value.replace("\\", "\\\\").replace("'", "\\'")
    mapping = {
        "url": f"[url:value = '{esc}']",
        "domain": f"[domain-name:value = '{esc}']",
        "ipv4": f"[ipv4-addr:value = '{esc}']",
        "ipv6": f"[ipv6-addr:value = '{esc}']",
        "email": f"[email-addr:value = '{esc}']",
        "md5": f"[file:hashes.MD5 = '{esc}']",
        "sha1": f"[file:hashes.'SHA-1' = '{esc}']",
        "sha256": f"[file:hashes.'SHA-256' = '{esc}']",
    }
    return mapping.get(ioc_type)


_MISP_TYPE = {
    "url": "url",
    "domain": "domain",
    "ipv4": "ip-dst",
    "ipv6": "ip-dst",
    "email": "email-src",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "filename": "filename",
}


def export_misp_csv(result: AnalysisResult, path: str | Path) -> Path:
    """MISP-compatible attribute CSV (category,type,value,comment,to_ids)."""
    out = Path(path)
    fieldnames = ["category", "type", "value", "comment", "to_ids"]
    level, score, summary = _verdict_fields(result)
    with out.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(
            {
                "category": "External analysis",
                "type": "comment",
                "value": f"verdict={level} score={score} {summary}"[:500],
                "comment": Path(result.source_path).name,
                "to_ids": "0",
            }
        )
        for ioc in result.iocs:
            mtype = _MISP_TYPE.get(ioc.ioc_type.value)
            if not mtype:
                continue
            category = "Network activity"
            if mtype in ("md5", "sha1", "sha256", "filename"):
                category = "Payload delivery"
            if mtype.startswith("email"):
                category = "Payload delivery"
            writer.writerow(
                {
                    "category": category,
                    "type": mtype,
                    "value": ioc.value,
                    "comment": "|".join(ioc.tags[:6]),
                    "to_ids": "1",
                }
            )
    return out


def export_opencti_json(result: AnalysisResult, path: str | Path) -> Path:
    """Minimal OpenCTI-oriented observables bundle (offline file)."""
    out = Path(path)
    level, score, summary = _verdict_fields(result)
    observables: list[dict] = []
    for ioc in result.iocs:
        t = ioc.ioc_type.value
        obs: dict = {
            "type": t,
            "value": ioc.value,
            "x_opencti_score": score,
            "x_opencti_description": ioc.context or summary,
            "labels": [level or "unknown", *list(ioc.tags)[:8]],
        }
        if t == "url":
            obs["entity_type"] = "Url"
        elif t == "domain":
            obs["entity_type"] = "Domain-Name"
        elif t in ("ipv4", "ipv6"):
            obs["entity_type"] = "IPv4-Addr" if t == "ipv4" else "IPv6-Addr"
        elif t in ("md5", "sha1", "sha256"):
            obs["entity_type"] = "StixFile"
            obs["hashes"] = {t.upper(): ioc.value}
        elif t == "email":
            obs["entity_type"] = "Email-Addr"
        else:
            obs["entity_type"] = "Text"
        observables.append(obs)
    payload = {
        "type": "opencti-bundle-lite",
        "spec_version": "1",
        "x_reliquary_schema": SCHEMA_VERSION,
        "verdict": {"level": level, "score": score, "summary": summary},
        "source_path": result.source_path,
        "objects": observables,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out
