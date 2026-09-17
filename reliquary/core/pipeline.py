"""End-to-end offline analysis pipeline."""

from __future__ import annotations

from pathlib import Path

from reliquary.core.document_parser import parse_document
from reliquary.core.header_analyzer import analyze_headers
from reliquary.core.ioc_extractor import extract_iocs
from reliquary.core.models import AnalysisResult, Ioc, IocType
from reliquary.core.url_rewrite import find_and_unwrap
from reliquary.core.verdict import render_verdict


def analyze_file(path: str | Path) -> AnalysisResult:
    path = Path(path)
    parsed = parse_document(path)

    result = AnalysisResult(
        source_path=str(path),
        source_kind=parsed.kind,
        subject=parsed.subject,
        sender=parsed.sender,
        recipients=parsed.recipients,
        attachments=list(parsed.attachments),
        raw_text_preview=(parsed.text or "")[:4000],
        errors=list(parsed.errors),
    )

    if parsed.message is not None:
        try:
            result.headers = analyze_headers(parsed.message)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"Заголовки: {exc}")

    # URL rewrite pass on body + html
    blob = f"{parsed.text}\n{parsed.html}"
    try:
        result.url_rewrites = find_and_unwrap(blob)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"URL rewrite: {exc}")

    # Build enriched text for IOC extraction: prefer unwrapped URLs
    enriched = blob
    for rewrite in result.url_rewrites:
        if rewrite.changed:
            enriched += f"\n{rewrite.unwrapped}"

    try:
        iocs = extract_iocs(enriched, source=parsed.kind)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"IOC: {exc}")
        iocs = []

    # Link rewritten_from on URL IOCs
    unwrap_map = {
        r.unwrapped: r.original for r in result.url_rewrites if r.changed
    }
    for ioc in iocs:
        if ioc.ioc_type == IocType.URL and ioc.value in unwrap_map:
            ioc.rewritten_from = unwrap_map[ioc.value]
            if "unwrapped" not in ioc.tags:
                ioc.tags.append("unwrapped")

    # Attachment hashes as IOCs
    for att in result.attachments:
        for algo, value, itype in (
            ("md5", att.md5, IocType.MD5),
            ("sha1", att.sha1, IocType.SHA1),
            ("sha256", att.sha256, IocType.SHA256),
        ):
            if value:
                iocs.append(
                    Ioc(
                        value=value,
                        ioc_type=itype,
                        source="attachment",
                        context=att.filename,
                        tags=["attachment_hash", algo, *att.risk_flags],
                    )
                )
        if att.filename:
            iocs.append(
                Ioc(
                    value=att.filename,
                    ioc_type=IocType.FILENAME,
                    source="attachment",
                    context=f"size={att.size}; mime={att.mime_guess}",
                    tags=list(att.risk_flags),
                )
            )

    # Deduplicate final IOC list
    dedup: dict[tuple[str, str], Ioc] = {}
    for ioc in iocs:
        key = (ioc.ioc_type.value, ioc.value.lower())
        if key not in dedup:
            dedup[key] = ioc
    result.iocs = list(dedup.values())
    result.iocs.sort(key=lambda i: (i.ioc_type.value, i.value.lower()))

    result.verdict = render_verdict(result)
    return result


def analyze_text(text: str, label: str = "clipboard") -> AnalysisResult:
    """Analyze pasted ticket / note text without a file on disk."""
    result = AnalysisResult(
        source_path=label,
        source_kind="ticket",
        raw_text_preview=text[:4000],
    )
    result.url_rewrites = find_and_unwrap(text)
    enriched = text
    for rewrite in result.url_rewrites:
        if rewrite.changed:
            enriched += f"\n{rewrite.unwrapped}"
    result.iocs = extract_iocs(enriched, source="ticket")
    for ioc in result.iocs:
        if ioc.ioc_type == IocType.URL:
            for r in result.url_rewrites:
                if r.changed and r.unwrapped == ioc.value:
                    ioc.rewritten_from = r.original
                    ioc.tags.append("unwrapped")
    result.verdict = render_verdict(result)
    return result
