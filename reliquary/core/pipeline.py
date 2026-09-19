"""End-to-end offline analysis pipeline."""

from __future__ import annotations

import email
import email.policy
import hashlib
import io
import re
from copy import copy
from datetime import datetime, timezone
from pathlib import Path

from reliquary import __version__
from reliquary.core.allowlist import build_allowlist, resolve_allowlist_path, tag_allowlist
from reliquary.core.analysis_options import AnalysisOptions
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
from reliquary.core.url_rewrite import find_and_unwrap
from reliquary.core.verdict import VerdictConfig, load_verdict_config, render_verdict


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


def _finalize_iocs(
    iocs: list[Ioc],
    *,
    allowlist_path: str | Path | None = None,
) -> list[Ioc]:
    path = resolve_allowlist_path(allowlist_path)
    allow_domains, allow_ips = build_allowlist(extra_path=path)
    tag_allowlist(iocs, allow_domains, allow_ips)
    return _dedup_iocs(iocs)


def _source_hash_bytes(data: bytes) -> tuple[str, int]:
    return hashlib.sha256(data).hexdigest(), len(data)


def _source_hash(path: Path) -> tuple[str, int]:
    try:
        data = path.read_bytes()
    except OSError:
        return "", 0
    return _source_hash_bytes(data)


def _build_meta(
    source_path: str,
    *,
    source_sha256: str = "",
    source_size: int | None = None,
    options: AnalysisOptions | None = None,
) -> AnalysisMeta:
    del source_path
    overrides: dict[str, str] = {}
    profile_dir = ""
    if options is not None:
        overrides = options.overrides_loaded()
        # Also record auto-resolved files that exist next to the app
        from reliquary.core.allowlist import resolve_allowlist_path as _ral
        from reliquary.core.handoff import resolve_handoff_template_path as _rht
        from reliquary.core.verdict import resolve_verdict_path as _rvp

        if "allowlist" not in overrides:
            ap = _ral(options.allowlist_path)
            if ap:
                overrides["allowlist"] = str(ap)
        if "verdict" not in overrides:
            vp = _rvp(options.verdict_path)
            if vp:
                overrides["verdict"] = str(vp)
        if "handoff" not in overrides:
            hp = _rht(options.handoff_template_path)
            if hp:
                overrides["handoff"] = str(hp)
        if options.profile_dir:
            profile_dir = str(options.profile_dir)
            overrides.setdefault("profile", profile_dir)
    return AnalysisMeta(
        app_version=__version__,
        analyzed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        source_sha256=source_sha256,
        source_size=source_size,
        overrides_loaded=overrides,
        profile_dir=profile_dir,
    )


def campaign_key_for(result: AnalysisResult) -> str:
    """Stable campaign fingerprint for batch grouping."""
    mid = result.mail_identity
    msg_id = ((mid.message_id if mid else "") or "").strip().lower()
    if msg_id:
        return f"msgid:{msg_id}"
    att_hashes = sorted({a.sha256 for a in result.attachments if a.sha256})
    if att_hashes:
        return f"att:{att_hashes[0][:16]}"
    subject = (result.subject or (mid.subject if mid else "") or "").strip().lower()
    sender = (result.sender or (mid.from_header if mid else "") or "").strip().lower()
    # Normalize sender to domain
    if "@" in sender:
        sender = sender.rsplit("@", 1)[-1].strip(">")
    subject = re.sub(r"\s+", " ", subject)[:80]
    if subject or sender:
        return f"subj:{subject}|from:{sender}"
    return ""


def annotate_campaigns(rows: list[FileTriageRow]) -> None:
    """Fill campaign_peers for rows sharing the same campaign_key."""
    by_key: dict[str, list[FileTriageRow]] = {}
    for row in rows:
        if not row.campaign_key:
            continue
        by_key.setdefault(row.campaign_key, []).append(row)
    for key, group in by_key.items():
        if len(group) < 2:
            continue
        names = [Path(r.path).name for r in group]
        for row in group:
            row.campaign_peers = [n for n in names if n != Path(row.path).name]



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
    top_reason = ""
    if result.verdict and result.verdict.reasons:
        top_reason = result.verdict.reasons[0]
    return FileTriageRow(
        path=result.source_path,
        kind=result.source_kind,
        verdict_level=result.verdict.level.value if result.verdict else "",
        verdict_score=result.verdict.score if result.verdict else None,
        ioc_count=len(result.iocs),
        top_iocs=_top_ioc_strings(result.iocs),
        top_reason=top_reason,
        errors=list(result.errors),
        message_id=(mid.message_id if mid else "") or "",
        subject=result.subject or (mid.subject if mid else ""),
        sender=result.sender or (mid.from_header if mid else ""),
        campaign_key=campaign_key_for(result),
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
        msg = email.message_from_bytes(att.data, policy=email.policy.default)  # type: ignore[arg-type]
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
                        raw = part.get_payload(decode=True)
                        if not isinstance(raw, (bytes, bytearray)):
                            continue
                        charset = part.get_content_charset() or "utf-8"
                        parts.append(bytes(raw).decode(charset, errors="replace"))
                    except Exception:
                        continue
        else:
            try:
                raw = msg.get_payload(decode=True)
                if isinstance(raw, (bytes, bytearray)):
                    charset = msg.get_content_charset() or "utf-8"
                    parts.append(bytes(raw).decode(charset, errors="replace"))
                else:
                    parts.append(str(msg.get_payload()))
            except Exception:
                parts.append(str(msg.get_payload()))
        return "\n".join(parts), errors
    except Exception as exc:  # noqa: BLE001
        return "", [f"Nested mail {att.filename}: {exc}"]


def _resolve_options(
    *,
    options: AnalysisOptions | None = None,
    allowlist_path: str | Path | None = None,
    verdict_path: str | Path | None = None,
) -> AnalysisOptions:
    if options is None:
        options = AnalysisOptions()
    if allowlist_path is not None:
        options.allowlist_path = allowlist_path
    if verdict_path is not None:
        options.verdict_path = verdict_path
    return options


def analyze_file(
    path: str | Path,
    *,
    allowlist_path: str | Path | None = None,
    verdict_path: str | Path | None = None,
    verdict_cfg: VerdictConfig | None = None,
    options: AnalysisOptions | None = None,
) -> AnalysisResult:
    path = Path(path)
    opts = _resolve_options(
        options=options, allowlist_path=allowlist_path, verdict_path=verdict_path
    )
    try:
        data = path.read_bytes()
    except OSError as exc:
        return AnalysisResult(
            source_path=str(path),
            source_kind="unknown",
            errors=[f"Чтение файла: {exc}"],
            meta=_build_meta(str(path), options=opts),
        )

    if path.suffix.lower() not in (".eml", ".msg"):
        return AnalysisResult(
            source_path=str(path),
            source_kind="unknown",
            errors=[
                f"Поддерживаются только письма (.eml / .msg), получено: "
                f"{path.suffix.lower() or '(без расширения)'}"
            ],
            meta=_build_meta(str(path), options=opts),
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
        html_preview=(parsed.html or "")[:8000],
        errors=list(parsed.errors),
        meta=_build_meta(
            str(path), source_sha256=source_sha, source_size=source_size, options=opts
        ),
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
        # Drop large nested payloads after parse to free RAM on folder batches
        if (
            att.data is not None
            and "nested_email" in att.risk_flags
            and att.size > 2 * 1024 * 1024
        ):
            att.data = None
        # Surface password-protected / soft inspector notes into analysis errors
        if "encrypted_archive" in att.risk_flags:
            result.errors.append(
                f"⚠ {att.filename}: архив защищён паролем — содержимое не извлечено"
            )
        for note in att.notes:
            if note.startswith("⚠") or note.startswith("OLE разбор"):
                tagged = f"{att.filename}: {note}"
                if tagged not in result.errors:
                    result.errors.append(tagged)

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

    result.iocs = _finalize_iocs(iocs, allowlist_path=opts.allowlist_path)
    fname = path.name
    result.iocs = [_tag_file(i, fname) for i in result.iocs]
    if result.source_kind == "email":
        cfg = verdict_cfg or load_verdict_config(opts.verdict_path)
        result.verdict = render_verdict(result, cfg, brands_path=opts.brands_path)
    result.file_rows = [file_triage_row(result)]
    return result


def _looks_like_rfc822(text: str) -> bool:
    head = text.lstrip()[:4000]
    if not head:
        return False
    lower = head.lower()
    has_from = re.search(r"(?m)^from:\s*\S", head, re.I) is not None
    has_subj = re.search(r"(?m)^subject:\s*", head, re.I) is not None
    has_mid = "message-id:" in lower
    has_received = re.search(r"(?m)^received:\s*", head, re.I) is not None
    has_mime = "mime-version:" in lower or "content-type:" in lower
    return (has_from and (has_subj or has_mid or has_received)) or (
        has_from and has_mime
    )


def analyze_text(
    text: str,
    label: str = "clipboard",
    *,
    allowlist_path: str | Path | None = None,
    verdict_path: str | Path | None = None,
    verdict_cfg: VerdictConfig | None = None,
    options: AnalysisOptions | None = None,
) -> AnalysisResult:
    """Analyze pasted RFC822 email source."""
    opts = _resolve_options(
        options=options, allowlist_path=allowlist_path, verdict_path=verdict_path
    )
    if not _looks_like_rfc822(text):
        return AnalysisResult(
            source_path=label,
            source_kind="unknown",
            raw_text_preview=text[:4000],
            errors=[
                "Буфер не похож на письмо RFC822. Вставьте исходник .eml "
                "(заголовки From/Subject/…) или откройте файл .eml/.msg."
            ],
            meta=_build_meta(label, options=opts),
        )

    data = text.encode("utf-8", errors="replace")
    # Use a synthetic .eml path so parse_document / analyze_file pathing stays consistent
    from reliquary.core.document_parser import parse_eml

    path = Path(f"{label}.eml") if not str(label).lower().endswith(".eml") else Path(label)
    source_sha, source_size = _source_hash_bytes(data)
    parsed = parse_eml(path, data=data)

    result = AnalysisResult(
        source_path=label,
        source_kind="email",
        subject=parsed.subject,
        sender=parsed.sender,
        recipients=list(parsed.recipients),
        attachments=list(parsed.attachments),
        raw_text_preview=(parsed.text or "")[:4000],
        html_preview=(parsed.html or "")[:8000],
        errors=list(parsed.errors),
        meta=_build_meta(
            label, source_sha256=source_sha, source_size=source_size, options=opts
        ),
    )

    if parsed.message is not None:
        try:
            result.headers = analyze_headers(parsed.message)
            result.raw_headers = extract_raw_headers(parsed.message)
            result.mail_identity = build_mail_identity(parsed.message)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"Заголовки: {exc}")

    blob = f"{parsed.text}\n{parsed.html}"
    for att in result.attachments:
        nested_text, nested_errs = _parse_nested_email_attachment(att)
        if nested_text:
            blob += "\n" + nested_text
            att.notes.append("Вложенное письмо разобрано локально")
        result.errors.extend(nested_errs)
        if (
            att.data is not None
            and "nested_email" in att.risk_flags
            and att.size > 2 * 1024 * 1024
        ):
            att.data = None
        if "encrypted_archive" in att.risk_flags:
            result.errors.append(
                f"⚠ {att.filename}: архив защищён паролем — содержимое не извлечено"
            )

    try:
        result.url_rewrites = find_and_unwrap(blob)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"URL rewrite: {exc}")

    enriched = blob
    for rewrite in result.url_rewrites:
        if rewrite.changed:
            enriched += f"\n{rewrite.unwrapped}"

    try:
        iocs = extract_iocs(enriched, source="email")
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"IOC: {exc}")
        iocs = []

    unwrap_map = {r.unwrapped: r.original for r in result.url_rewrites if r.changed}
    rewriter_hosts: set[str] = set()
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
    result.iocs = _finalize_iocs(iocs, allowlist_path=opts.allowlist_path)
    cfg = verdict_cfg or load_verdict_config(opts.verdict_path)
    result.verdict = render_verdict(result, cfg, brands_path=opts.brands_path)
    result.file_rows = [file_triage_row(result)]
    return result


def merge_results(
    results: list[AnalysisResult],
    label: str = "batch",
    *,
    verdict_path: str | Path | None = None,
    verdict_cfg: VerdictConfig | None = None,
    options: AnalysisOptions | None = None,
) -> AnalysisResult:
    """Merge multiple email analyses into one result (batch open)."""
    opts = _resolve_options(options=options, verdict_path=verdict_path)
    if not results:
        return AnalysisResult(
            source_path=label, source_kind="batch", meta=_build_meta(label, options=opts)
        )
    if len(results) == 1:
        return results[0]

    rows = [file_triage_row(r) for r in results]
    annotate_campaigns(rows)

    merged = AnalysisResult(
        source_path=f"{label} ({len(results)} files)",
        source_kind="batch",
        subject="; ".join(r.subject for r in results if r.subject)[:500],
        sender="; ".join(r.sender for r in results if r.sender)[:500],
        raw_text_preview="\n---\n".join(
            f"[{r.source_path}]\n{r.raw_text_preview}" for r in results
        )[:8000],
        meta=_build_meta(label, options=opts),
        file_rows=rows,
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
    camp_groups = sum(1 for r in rows if r.campaign_peers)
    if camp_groups:
        merged.errors.append(
            f"Кампании: {camp_groups} писем связаны по Msg-ID/теме/хешу вложения — см. «Пакет»"
        )
    merged.iocs = _finalize_iocs(iocs)
    # Batch of emails: score from merged email signals
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
    cfg = verdict_cfg or load_verdict_config(opts.verdict_path)
    merged.verdict = render_verdict(email_only, cfg, brands_path=opts.brands_path)
    return merged
