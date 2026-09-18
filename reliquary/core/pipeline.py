"""End-to-end offline analysis pipeline."""

from __future__ import annotations

import email
import email.policy
import hashlib
import io
from copy import copy
from datetime import datetime, timezone
from pathlib import Path

from reliquary import __version__
from reliquary.core.allowlist import build_allowlist, build_denylist, list_mtime_label, tag_allowlist_denylist
from reliquary.core.document_parser import parse_document
from reliquary.core.header_analyzer import (
    analyze_headers,
    build_mail_identity,
    extract_raw_headers,
)
from reliquary.core.ioc_extractor import extract_iocs
from reliquary.core.models import (
    AnalysisMeta,
    AnalysisResult,
    AttachmentInfo,
    FileTriageRow,
    Ioc,
    IocType,
)
from reliquary.core.paths import file_mtime_iso, config_path, ensure_user_lists
from reliquary.core.url_rewrite import find_and_unwrap
from reliquary.core.verdict import render_verdict


def _tag_file(ioc: Ioc, filename: str) -> Ioc:
    tag = f"file:{filename}"
    if tag in ioc.tags:
        return ioc
    tagged = copy(ioc)
    tagged.tags = list(ioc.tags) + [tag]
    return tagged

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


def _source_hash_bytes(data: bytes) -> tuple[str, int]:
    return hashlib.sha256(data).hexdigest(), len(data)


def _source_hash(path: Path) -> tuple[str, int]:
    try:
        data = path.read_bytes()
    except OSError:
        return "", 0
    return _source_hash_bytes(data)


def _build_meta(source_path: str, *, source_sha256: str = "", source_size: int | None = None) -> AnalysisMeta:
    ensure_user_lists()
    return AnalysisMeta(
        app_version=__version__,
        analyzed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        source_sha256=source_sha256,
        source_size=source_size,
        allowlist_mtime=list_mtime_label("allowlist.txt"),
        denylist_mtime=list_mtime_label("denylist.txt"),
        verdict_config_mtime=file_mtime_iso(config_path("verdict.ini")) or "—",
    )


def _top_ioc_strings(iocs: list[Ioc], n: int = 5) -> list[str]:
    ranked = sorted(iocs, key=_ioc_priority, reverse=True)
    out: list[str] = []
    for ioc in ranked:
        if "allowlisted" in ioc.tags or "url_rewriter" in ioc.tags or "private" in ioc.tags:
            continue
        out.append(f"{ioc.ioc_type.value}:{ioc.value}")
        if len(out) >= n:
            break
    if len(out) < n:
        for ioc in ranked:
            s = f"{ioc.ioc_type.value}:{ioc.value}"
            if s not in out:
                out.append(s)
            if len(out) >= n:
                break
    return out


def file_triage_row(result: AnalysisResult) -> FileTriageRow:
    mid = result.mail_identity
    return FileTriageRow(
        path=result.source_path,
        kind=result.source_kind,
        verdict_level=result.verdict.level.value if result.verdict else "",
        verdict_score=result.verdict.score if result.verdict else None,
        ioc_count=len(result.iocs),
        top_iocs=_top_ioc_strings(result.iocs),
        errors=list(result.errors),
        message_id=(mid.message_id if mid else "") or "",
        subject=result.subject or (mid.subject if mid else ""),
        sender=result.sender or (mid.from_header if mid else ""),
    )


def _lift_attachment_iocs(attachments: list[AttachmentInfo], iocs: list[Ioc]) -> None:
    for att in attachments:
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
            if entry.startswith("QR:"):
                payload = entry[3:]
                for qi in extract_iocs(payload, source="qr"):
                    if "qr" not in qi.tags:
                        qi.tags.append("qr")
                    if "from_image" not in qi.tags:
                        qi.tags.append("from_image")
                    qi.context = qi.context or att.filename
                    iocs.append(qi)
                continue
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


def _parse_nested_email_attachment(att: AttachmentInfo) -> tuple[str, list[str]]:
    """Return (extra_text, errors) from nested .eml/.msg bytes."""
    if not att.data or "nested_email" not in att.risk_flags:
        return "", []
    errors: list[str] = []
    name = att.filename.lower()
    try:
        if name.endswith(".msg"):
            try:
                import extract_msg
            except ImportError as exc:
                return "", [f"nested MSG {att.filename}: {exc}"]
            msg_file = extract_msg.Message(io.BytesIO(att.data))
            body = msg_file.body or ""
            html = getattr(msg_file, "htmlBody", None) or ""
            if isinstance(html, bytes):
                html = html.decode("utf-8", errors="replace")
            subj = str(msg_file.subject or "")
            sender = str(msg_file.sender or "")
            try:
                msg_file.close()
            except Exception:
                pass
            return f"Nested MSG {att.filename}\nFrom: {sender}\nSubject: {subj}\n{body}\n{html}", errors
        # .eml / rfc822
        msg = email.message_from_bytes(att.data, policy=email.policy.default)
        parts: list[str] = [
            f"Nested EML {att.filename}",
            f"From: {msg.get('From', '')}",
            f"Subject: {msg.get('Subject', '')}",
            f"Message-ID: {msg.get('Message-ID', '')}",
        ]
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if part.get_filename():
                    parts.append(f"Nested-Att: {part.get_filename()}")
                    continue
                if ctype in ("text/plain", "text/html"):
                    try:
                        payload = part.get_payload(decode=True) or b""
                        charset = part.get_content_charset() or "utf-8"
                        parts.append(payload.decode(charset, errors="replace"))
                    except Exception:
                        continue
        else:
            try:
                payload = msg.get_payload(decode=True) or b""
                charset = msg.get_content_charset() or "utf-8"
                parts.append(payload.decode(charset, errors="replace"))
            except Exception:
                parts.append(str(msg.get_payload()))
        return "\n".join(parts), errors
    except Exception as exc:  # noqa: BLE001
        return "", [f"Nested mail {att.filename}: {exc}"]


def analyze_file(path: str | Path) -> AnalysisResult:
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        return AnalysisResult(
            source_path=str(path),
            source_kind="unknown",
            errors=[f"Чтение файла: {exc}"],
            meta=_build_meta(str(path)),
        )
    source_sha, source_size = _source_hash_bytes(data)
    parsed = parse_document(path, data=data)

    result = AnalysisResult(
        source_path=str(path),
        source_kind=parsed.kind,
        subject=parsed.subject,
        sender=parsed.sender,
        recipients=list(parsed.recipients),
        attachments=list(parsed.attachments),
        raw_text_preview=(parsed.text or "")[:4000],
        errors=list(parsed.errors),
        meta=_build_meta(str(path), source_sha256=source_sha, source_size=source_size),
    )

    if parsed.message is not None:
        try:
            result.headers = analyze_headers(parsed.message)
            result.raw_headers = extract_raw_headers(parsed.message)
            result.mail_identity = build_mail_identity(parsed.message)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"Заголовки: {exc}")

    blob = f"{parsed.text}\n{parsed.html}"

    # Nested emails inside attachments
    for att in result.attachments:
        nested_text, nested_errs = _parse_nested_email_attachment(att)
        if nested_text:
            blob += "\n" + nested_text
            att.notes.append("Вложенное письмо разобрано локально")
        result.errors.extend(nested_errs)

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

    _lift_attachment_iocs(result.attachments, iocs)

    result.iocs = _finalize_iocs(iocs)
    fname = path.name
    result.iocs = [_tag_file(i, fname) for i in result.iocs]
    result.verdict = render_verdict(result)
    result.file_rows = [file_triage_row(result)]
    return result


def analyze_text(text: str, label: str = "clipboard") -> AnalysisResult:
    """Analyze pasted ticket / note text without a file on disk."""
    result = AnalysisResult(
        source_path=label,
        source_kind="ticket",
        raw_text_preview=text[:4000],
        meta=_build_meta(label),
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
    result.file_rows = [file_triage_row(result)]
    return result


def merge_results(results: list[AnalysisResult], label: str = "batch") -> AnalysisResult:
    """Merge multiple file analyses into one result (batch open)."""
    if not results:
        return AnalysisResult(source_path=label, source_kind="batch", meta=_build_meta(label))
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
        meta=_build_meta(label),
        file_rows=[file_triage_row(r) for r in results],
    )
    iocs: list[Ioc] = []
    mail_sources: list[str] = []
    for r in results:
        fname = Path(r.source_path).name
        for ioc in r.iocs:
            iocs.append(_tag_file(ioc, fname))
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
            + ") — см. вкладку «Пакет»"
        )
    merged.iocs = _finalize_iocs(iocs)
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
