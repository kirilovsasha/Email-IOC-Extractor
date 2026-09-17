"""Export IOCs to STIX 2.1 JSON and CSV — offline only."""

from __future__ import annotations

import csv
import json
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
    }
    return mapping.get(ioc.ioc_type)


def _observable(ioc: Ioc):
    if not HAS_STIX:
        return None
    v = ioc.value
    if ioc.ioc_type == IocType.IPV4:
        return IPv4Address(value=v)
    if ioc.ioc_type == IocType.IPV6:
        return IPv6Address(value=v)
    if ioc.ioc_type == IocType.DOMAIN:
        return DomainName(value=v)
    if ioc.ioc_type == IocType.URL:
        return URL(value=v)
    if ioc.ioc_type == IocType.EMAIL:
        return EmailAddress(value=v)
    if ioc.ioc_type == IocType.MD5:
        return File(hashes={"MD5": v})
    if ioc.ioc_type == IocType.SHA1:
        return File(hashes={"SHA-1": v})
    if ioc.ioc_type == IocType.SHA256:
        return File(hashes={"SHA-256": v})
    return None


def export_stix(result: AnalysisResult, path: str | Path) -> Path:
    """Write a STIX 2.1 Bundle. Falls back to minimal JSON if stix2 missing."""
    out = Path(path)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    if not HAS_STIX:
        payload = {
            "type": "bundle",
            "id": f"bundle--reliquary-{now}",
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
    with out.open("w", encoding="utf-8", newline="") as fh:
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


def export_report_json(result: AnalysisResult, path: str | Path) -> Path:
    out = Path(path)
    out.write_text(
        json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return out
