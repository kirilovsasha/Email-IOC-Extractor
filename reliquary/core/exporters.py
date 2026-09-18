"""Export IOCs — CSV, STIX, MISP, OpenCTI, YARA."""

from __future__ import annotations

import csv
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from reliquary.core.models import AnalysisResult, Ioc, IocType

try:
    from stix2 import (
        Bundle,
        DomainName,
        EmailAddress,
        File,
        Indicator,
        IPv4Address,
        IPv6Address,
        Relationship,
        URL,
        Vulnerability,
    )

    HAS_STIX = True
except ImportError:  # pragma: no cover
    HAS_STIX = False


def filter_iocs(
    result: AnalysisResult,
    types: set[str] | None = None,
    *,
    hide_private: bool = False,
    hide_rewriter: bool = False,
    hide_allowlisted: bool = False,
    only_denylisted: bool = False,
) -> list[Ioc]:
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
        if only_denylisted and "denylisted" not in ioc.tags:
            continue
        out.append(ioc)
    return out


def _with_iocs(result: AnalysisResult, iocs: list[Ioc]) -> AnalysisResult:
    """Shallow copy result with replaced IOC list for exporters."""
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


def _stix_pattern(ioc: Ioc) -> str | None:
    v = ioc.value.replace("\\", "\\\\").replace("'", "\\'")
    mapping = {
        IocType.IPV4: f"[ipv4-addr:value = '{v}']",
        IocType.IPV6: f"[ipv6-addr:value = '{v}']",
        IocType.DOMAIN: f"[domain-name:value = '{v}']",
        IocType.URL: f"[url:value = '{v}']",
        IocType.EMAIL: f"[email-addr:value = '{v}']",
        IocType.MD5: f"[file:hashes.MD5 = '{v}']",
        IocType.SHA1: f"[file:hashes.'SHA-1' = '{v}']",
        IocType.SHA256: f"[file:hashes.'SHA-256' = '{v}']",
        IocType.MESSENGER: f"[url:value = '{v}']",
        IocType.FILEPATH: f"[file:name = '{v}']",
        IocType.UNC: f"[file:name = '{v}']",
        IocType.MUTEX: f"[file:name = '{v}']",
        IocType.BITCOIN: f"[file:name = '{v}']",
        IocType.MONERO: f"[file:name = '{v}']",
        IocType.FILENAME: f"[file:name = '{v}']",
        IocType.COMMAND_LINE: f"[process:command_line = '{v}']",
    }
    if ioc.ioc_type == IocType.IP_PORT and ":" in ioc.value:
        ip = ioc.value.rsplit(":", 1)[0].replace("\\", "\\\\").replace("'", "\\'")
        return f"[ipv4-addr:value = '{ip}']"
    if ioc.ioc_type == IocType.REGISTRY:
        return f"[windows-registry-key:key = '{v}']"
    return mapping.get(ioc.ioc_type)


def _observable(ioc: Ioc):
    if not HAS_STIX:
        return None
    v = ioc.value
    if ioc.ioc_type == IocType.IPV4:
        return IPv4Address(value=v)
    if ioc.ioc_type == IocType.IP_PORT and ":" in v:
        return IPv4Address(value=v.rsplit(":", 1)[0])
    if ioc.ioc_type == IocType.IPV6:
        return IPv6Address(value=v)
    if ioc.ioc_type == IocType.DOMAIN:
        return DomainName(value=v)
    if ioc.ioc_type in (IocType.URL, IocType.MESSENGER):
        return URL(value=v if "://" in v else f"https://{v}")
    if ioc.ioc_type == IocType.EMAIL:
        return EmailAddress(value=v)
    if ioc.ioc_type == IocType.MD5:
        return File(hashes={"MD5": v})
    if ioc.ioc_type == IocType.SHA1:
        return File(hashes={"SHA-1": v})
    if ioc.ioc_type == IocType.SHA256:
        return File(hashes={"SHA-256": v})
    if ioc.ioc_type in (IocType.FILEPATH, IocType.UNC, IocType.FILENAME, IocType.MUTEX):
        return File(name=v[:256])
    return None


def export_stix(result: AnalysisResult, path: str | Path) -> Path:
    """Write a STIX 2.1 Bundle. Falls back to minimal JSON if stix2 missing."""
    out = Path(path)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    if not HAS_STIX:
        payload = {
            "type": "bundle",
            "id": f"bundle--ioc-extractor-{now}",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "name": ioc.value,
                    "pattern": _stix_pattern(ioc) or ioc.value,
                    "pattern_type": "stix",
                    "indicator_types": ["anomalous-activity"],
                    "valid_from": now,
                    "description": ioc.context,
                    "labels": [ioc.ioc_type.value, *ioc.tags],
                }
                for ioc in result.iocs
                if ioc.ioc_type != IocType.CVE
            ],
        }
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return out

    objects: list = []
    for ioc in result.iocs:
        if ioc.ioc_type == IocType.CVE:
            try:
                objects.append(
                    Vulnerability(
                        name=ioc.value,
                        description=ioc.context or f"Extracted from {result.source_path}",
                    )
                )
            except Exception:
                continue
            continue

        pattern = _stix_pattern(ioc)
        if not pattern:
            continue
        try:
            indicator = Indicator(
                name=f"{ioc.ioc_type.value}:{ioc.value}",
                description=ioc.context or f"Source: {ioc.source}",
                pattern=pattern,
                pattern_type="stix",
                indicator_types=["anomalous-activity"],
                valid_from=now,
                labels=[ioc.ioc_type.value, *ioc.tags],
            )
            objects.append(indicator)
            obs = _observable(ioc)
            if obs is not None:
                objects.append(obs)
                objects.append(
                    Relationship(
                        relationship_type="based-on",
                        source_ref=indicator.id,
                        target_ref=obs.id,
                    )
                )
        except Exception:
            continue

    bundle = Bundle(objects=objects) if objects else Bundle(objects=[])
    out.write_text(bundle.serialize(pretty=True), encoding="utf-8")
    return out


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
    # utf-8-sig → BOM so Excel on Windows opens Cyrillic correctly
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


def export_report_json(
    result: AnalysisResult,
    path: str | Path,
    *,
    filters_applied: dict | None = None,
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
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def export_case_pack(
    result: AnalysisResult,
    path: str | Path,
    *,
    filters_applied: dict | None = None,
    include_attachments: bool = True,
) -> Path:
    """Write a ZIP case pack: report JSON + CSV + optional attachment files."""
    import zipfile
    from reliquary.core.ticket import build_ticket_template

    out = Path(path)
    if out.suffix.lower() != ".zip":
        out = out.with_suffix(".zip")

    safe = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", Path(result.source_path).stem)[:80] or "case"
    buf_csv = Path(str(out) + ".tmp.csv")
    buf_json = Path(str(out) + ".tmp.json")
    try:
        export_csv(result, buf_csv)
        export_report_json(result, buf_json, filters_applied=filters_applied)
        ticket = build_ticket_template(result, result.iocs, defang=True)
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{safe}/report.json", buf_json.read_text(encoding="utf-8"))
            zf.writestr(f"{safe}/iocs.csv", buf_csv.read_bytes())
            zf.writestr(f"{safe}/ticket.txt", ticket)
            if result.file_rows:
                rows = ["path\tkind\tverdict\tscore\tiocs\ttop\terrors\tmessage_id\n"]
                for r in result.file_rows:
                    rows.append(
                        f"{r.path}\t{r.kind}\t{r.verdict_level}\t{r.verdict_score}\t"
                        f"{r.ioc_count}\t{' | '.join(r.top_iocs)}\t"
                        f"{' | '.join(r.errors)}\t{r.message_id}\n"
                    )
                zf.writestr(f"{safe}/batch_files.tsv", "".join(rows))
            if include_attachments:
                used: set[str] = set()
                for att in result.attachments:
                    if not att.data:
                        continue
                    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", att.filename or "att.bin")
                    name = name.strip(" .") or "att.bin"
                    candidate = name
                    n = 1
                    while candidate.lower() in used:
                        stem = Path(name).stem
                        suffix = Path(name).suffix
                        candidate = f"{stem}_{n}{suffix}"
                        n += 1
                    used.add(candidate.lower())
                    zf.writestr(f"{safe}/attachments/{candidate}", att.data)
                    zf.writestr(
                        f"{safe}/attachments/{candidate}.sha256.txt",
                        f"{att.sha256}  {candidate}\n",
                    )
    finally:
        for tmp in (buf_csv, buf_json):
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
    return out


_MISP_TYPE = {
    "ipv4": "ip-dst",
    "ipv6": "ip-dst",
    "ip_port": "ip-dst|port",
    "domain": "domain",
    "url": "url",
    "email": "email-src",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "filename": "filename",
    "filepath": "filename",
    "mutex": "mutex",
    "registry": "regkey",
    "cve": "vulnerability",
    "bitcoin": "btc",
    "monero": "xmr",
    "messenger": "url",
    "command_line": "text",
    "unc": "filename",
}


def export_misp(result: AnalysisResult, path: str | Path, iocs: list[Ioc] | None = None) -> Path:
    """MISP event JSON (offline stub suitable for import)."""
    out = Path(path)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    items = iocs if iocs is not None else result.iocs
    event_uuid = str(uuid.uuid4())
    attributes = []
    for ioc in items:
        attributes.append(
            {
                "type": _MISP_TYPE.get(ioc.ioc_type.value, "text"),
                "category": "Network activity"
                if ioc.ioc_type.value
                in ("ipv4", "ipv6", "ip_port", "domain", "url", "email", "messenger")
                else "Payload delivery",
                "value": ioc.value,
                "to_ids": True,
                "comment": ioc.context or "|".join(ioc.tags),
                "uuid": str(uuid.uuid4()),
            }
        )
    payload = {
        "Event": {
            "uuid": event_uuid,
            "info": f"IOC Extractor export: {result.source_path}",
            "date": now,
            "threat_level_id": "2",
            "analysis": "1",
            "distribution": "0",
            "Attribute": attributes,
            "Tag": [{"name": "ioc-extractor"}, {"name": "tlp:amber"}],
        }
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def export_opencti(result: AnalysisResult, path: str | Path, iocs: list[Ioc] | None = None) -> Path:
    """OpenCTI-friendly bundle of observables / indicators (JSON)."""
    out = Path(path)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    items = iocs if iocs is not None else result.iocs
    objects = []
    for ioc in items:
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": f"{ioc.ioc_type.value}: {ioc.value[:80]}",
                "description": ioc.context,
                "pattern_type": "stix",
                "pattern": _stix_pattern(ioc) or f"[x-ioc-extractor:value = '{ioc.value}']",
                "valid_from": now,
                "labels": [ioc.ioc_type.value, *ioc.tags, "ioc-extractor"],
                "x_opencti_main_observable_type": ioc.ioc_type.value,
                "x_opencti_score": 50,
            }
        )
    payload = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
        "x_ioc_extractor_source": result.source_path,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def _yara_escape(value: str) -> str:
    """Escape a string for use inside YARA double-quoted strings."""
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def _yara_rule_id(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"R_{cleaned}"
    return cleaned[:120] or "IOC_Extractor_Export"


def export_yara(
    result: AnalysisResult, path: str | Path, iocs: list[Ioc] | None = None
) -> Path:
    """Write valid YARA rules from filtered IOCs.

    - Network / host / crypto / paths → string matches (ascii wide nocase where useful)
    - File hashes → ``import "hash"`` + hash.md5/sha1/sha256(0, filesize)
    - Split into category rules so analysts can enable only what they need
    """
    out = Path(path)
    items = iocs if iocs is not None else result.iocs
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    source = _yara_escape(result.source_path or "unknown")
    base = _yara_rule_id(f"IOC_Extractor_{Path(result.source_path).stem}_{now.replace('-', '')}")

    buckets: dict[str, list[Ioc]] = {
        "network": [],
        "hashes": [],
        "host": [],
        "other": [],
    }
    for ioc in items:
        t = ioc.ioc_type.value
        if t in ("ipv4", "ipv6", "ip_port", "domain", "url", "email", "messenger"):
            buckets["network"].append(ioc)
        elif t in ("md5", "sha1", "sha256"):
            buckets["hashes"].append(ioc)
        elif t in (
            "filename",
            "filepath",
            "unc",
            "registry",
            "mutex",
            "command_line",
        ):
            buckets["host"].append(ioc)
        else:
            buckets["other"].append(ioc)

    needs_hash = bool(buckets["hashes"])
    lines: list[str] = [
        "// Generated by IOC Extractor — offline IOC to YARA export",
        f"// source: {result.source_path}",
        f"// date: {now}",
        "// Review before production use (FP risk on short strings / private IPs).",
        "",
    ]
    if needs_hash:
        lines.append('import "hash"')
        lines.append("")

    def _emit_rule(suffix: str, group: list[Ioc], *, use_hash_module: bool) -> None:
        if not group:
            return
        rule_name = _yara_rule_id(f"{base}_{suffix}")
        lines.append(f"rule {rule_name}")
        lines.append("{")
        lines.append("    meta:")
        lines.append(f'        description = "IOC Extractor IOC export ({suffix})"')
        lines.append('        author = "IOC Extractor"')
        lines.append(f'        date = "{now}"')
        lines.append(f'        source = "{source}"')
        lines.append(f"        ioc_count = {len(group)}")
        lines.append("")

        string_lines: list[str] = []
        hash_conds: list[str] = []
        idx = 0
        for ioc in group:
            t = ioc.ioc_type.value
            val = ioc.value.strip()
            if not val:
                continue
            if use_hash_module and t in ("md5", "sha1", "sha256"):
                hex_val = val.lower()
                if t == "md5" and len(hex_val) == 32:
                    hash_conds.append(f'hash.md5(0, filesize) == "{hex_val}"')
                elif t == "sha1" and len(hex_val) == 40:
                    hash_conds.append(f'hash.sha1(0, filesize) == "{hex_val}"')
                elif t == "sha256" and len(hex_val) == 64:
                    hash_conds.append(f'hash.sha256(0, filesize) == "{hex_val}"')
                continue

            # Skip very short strings — high FP
            if len(val) < 4:
                continue
            idx += 1
            sid = f"${t}_{idx}"
            escaped = _yara_escape(val)
            if t in ("domain", "url", "email", "messenger", "filename"):
                mods = "ascii wide nocase"
            elif t in ("filepath", "unc", "registry", "mutex", "command_line"):
                mods = "ascii wide nocase"
            else:
                mods = "ascii wide"
            string_lines.append(f'        {sid} = "{escaped}" {mods}')

        if string_lines:
            lines.append("    strings:")
            lines.extend(string_lines)
            lines.append("")

        conditions: list[str] = []
        if string_lines:
            conditions.append("any of them")
        conditions.extend(hash_conds)

        if not conditions:
            lines.append("    condition:")
            lines.append("        false  // no usable indicators in this group")
        else:
            lines.append("    condition:")
            if len(conditions) == 1:
                lines.append(f"        {conditions[0]}")
            else:
                lines.append("        " + " or\n        ".join(conditions))
        lines.append("}")
        lines.append("")

    _emit_rule("network", buckets["network"], use_hash_module=False)
    _emit_rule("hashes", buckets["hashes"], use_hash_module=True)
    _emit_rule("host", buckets["host"], use_hash_module=False)
    _emit_rule("other", buckets["other"], use_hash_module=False)

    if lines[-1] == "" and "rule " not in "\n".join(lines):
        # Nothing emitted — still write a stub rule
        lines.append(f"rule {_yara_rule_id(base)}")
        lines.append("{")
        lines.append("    meta:")
        lines.append('        description = "IOC Extractor export — no usable IOCs"')
        lines.append('        author = "IOC Extractor"')
        lines.append(f'        date = "{now}"')
        lines.append("    condition:")
        lines.append("        false")
        lines.append("}")
        lines.append("")

    out.write_text("\n".join(lines), encoding="utf-8")
    return out
