"""End-to-end offline analysis pipeline."""

from __future__ import annotations

from pathlib import Path

from reliquary.core.allowlist import build_allowlist, build_denylist, tag_allowlist_denylist
from reliquary.core.document_parser import parse_document
from reliquary.core.header_analyzer import (
    analyze_headers,
    build_mail_identity,
    extract_raw_headers,
)
from reliquary.core.ioc_extractor import extract_iocs
from reliquary.core.models import AnalysisResult, Ioc, IocType
from reliquary.core.url_rewrite import find_and_unwrap
from reliquary.core.verdict import render_verdict


def _ioc_priority(ioc: Ioc) -> int:
    """Higher = keep when merging duplicates / competing signals."""
    score = 0
    if "unwrapped" in ioc.tags:
        score += 50
    if "denylisted" in ioc.tags:
        score += 40
    if "from_url" in ioc.tags and "url_rewriter" not in ioc.tags:
        score += 20
    if "url_rewriter" in ioc.tags:
        score -= 30
    if "allowlisted" in ioc.tags:
        score -= 10
    if "private" in ioc.tags:
        score -= 5
    return score


def _dedup_iocs(iocs: list[Ioc]) -> list[Ioc]:
    dedup: dict[tuple[str, str], Ioc] = {}
    for ioc in iocs:
        key = (ioc.ioc_type.value, ioc.value.lower())
        prev = dedup.get(key)
        if prev is None or _ioc_priority(ioc) > _ioc_priority(prev):
            dedup[key] = ioc
        elif prev is not None:
            for tag in ioc.tags:
                if tag not in prev.tags:
                    prev.tags.append(tag)
            if ioc.rewritten_from and not prev.rewritten_from:
                prev.rewritten_from = ioc.rewritten_from

    # Prefer unwrapped URL domains over rewriter hosts when both present as domain IOCs
    domains = [i for i in dedup.values() if i.ioc_type == IocType.DOMAIN]
    rewriter_keys = {
        (i.ioc_type.value, i.value.lower())
        for i in domains
        if "url_rewriter" in i.tags
    }
    unwrapped_present = any("unwrapped" in i.tags or "from_url" in i.tags for i in domains)
    if unwrapped_present:
        for key in list(dedup.keys()):
            ioc = dedup[key]
            if key in rewriter_keys and "url_rewriter" in ioc.tags:
                # keep but mark as noise-candidate; do not drop — GUI filter hides them
                if "noise_candidate" not in ioc.tags:
                    ioc.tags.append("noise_candidate")

    result = list(dedup.values())
    result.sort(key=lambda i: (-_ioc_priority(i), i.ioc_type.value, i.value.lower()))
    return result


def _finalize_iocs(iocs: list[Ioc]) -> list[Ioc]:
    allow_domains, allow_ips = build_allowlist()
    deny = build_denylist()
    tag_allowlist_denylist(iocs, allow_domains, allow_ips, deny)
    return _dedup_iocs(iocs)


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
            result.raw_headers = extract_raw_headers(parsed.message)
            result.mail_identity = build_mail_identity(parsed.message)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"Заголовки: {exc}")

    blob = f"{parsed.text}\n{parsed.html}"
    try:
        result.url_rewrites = find_and_unwrap(blob)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"URL rewrite: {exc}")

    enriched = blob
    for rewrite in result.url_rewrites:
        if rewrite.changed:
            enriched += f"\n{rewrite.unwrapped}"

    try:
        iocs = extract_iocs(enriched, source=parsed.kind)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"IOC: {exc}")
        iocs = []

    unwrap_map = {r.unwrapped: r.original for r in result.url_rewrites if r.changed}
    rewriter_hosts = set()
    for r in result.url_rewrites:
        if r.changed:
            from urllib.parse import urlparse

            host = urlparse(r.original).hostname
            if host:
                rewriter_hosts.add(host.lower())

    for ioc in iocs:
        if ioc.ioc_type == IocType.URL and ioc.value in unwrap_map:
            ioc.rewritten_from = unwrap_map[ioc.value]
            if "unwrapped" not in ioc.tags:
                ioc.tags.append("unwrapped")
        if ioc.ioc_type == IocType.DOMAIN and ioc.value.lower() in rewriter_hosts:
            if "url_rewriter" not in ioc.tags:
                ioc.tags.append("url_rewriter")

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
        for entry in att.archive_entries or []:
            base = Path(entry).name
            if not base or base.startswith("."):
                continue
            iocs.append(
                Ioc(
                    value=base,
                    ioc_type=IocType.FILENAME,
                    source="archive",
                    context=f"in:{att.filename}",
                    tags=["archive_member", *att.risk_flags],
                )
            )

    result.iocs = _finalize_iocs(iocs)
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
    iocs = extract_iocs(enriched, source="ticket")
    for ioc in iocs:
        if ioc.ioc_type == IocType.URL:
            for r in result.url_rewrites:
                if r.changed and r.unwrapped == ioc.value:
                    ioc.rewritten_from = r.original
                    if "unwrapped" not in ioc.tags:
                        ioc.tags.append("unwrapped")
    result.iocs = _finalize_iocs(iocs)
    result.verdict = render_verdict(result)
    return result


def merge_results(results: list[AnalysisResult], label: str = "batch") -> AnalysisResult:
    """Merge multiple file analyses into one result (batch open)."""
    if not results:
        return AnalysisResult(source_path=label, source_kind="batch")
    if len(results) == 1:
        return results[0]

    merged = AnalysisResult(
        source_path=f"{label} ({len(results)} files)",
        source_kind="batch",
        subject="; ".join(r.subject for r in results if r.subject)[:500],
        sender="; ".join(r.sender for r in results if r.sender)[:500],
        raw_text_preview="\n---\n".join(
            f"[{r.source_path}]\n{r.raw_text_preview}" for r in results
        )[:8000],
    )
    iocs: list[Ioc] = []
    mail_sources: list[str] = []
    for r in results:
        iocs.extend(r.iocs)
        merged.url_rewrites.extend(r.url_rewrites)
        merged.attachments.extend(r.attachments)
        merged.headers.extend(r.headers)
        merged.errors.extend(r.errors)
        if r.mail_identity:
            mail_sources.append(Path(r.source_path).name)
            if merged.mail_identity is None:
                merged.mail_identity = r.mail_identity
                merged.raw_headers = dict(r.raw_headers)
    if len(mail_sources) > 1:
        merged.errors.append(
            f"Batch: карточка почты от первого письма; всего писем с identity: "
            f"{len(mail_sources)} ({', '.join(mail_sources[:5])}"
            + ("…" if len(mail_sources) > 5 else "")
            + ")"
        )
    merged.iocs = _finalize_iocs(iocs)
    # Verdict only when the batch includes at least one email
    if any(r.source_kind == "email" for r in results):
        email_only = AnalysisResult(
            source_path=merged.source_path,
            source_kind="email",
            subject=merged.subject,
            sender=merged.sender,
            recipients=list(merged.recipients),
            iocs=list(merged.iocs),
            headers=list(merged.headers),
            raw_headers=dict(merged.raw_headers),
            mail_identity=merged.mail_identity,
            url_rewrites=list(merged.url_rewrites),
            attachments=list(merged.attachments),
            raw_text_preview=merged.raw_text_preview,
            errors=list(merged.errors),
        )
        merged.verdict = render_verdict(email_only)
    else:
        merged.verdict = None
    return merged
