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
from reliquary.core.ioc_extractor import extract_iocs, normalize_url_key
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


def _merge_ioc_pair(stronger: Ioc, weaker: Ioc) -> Ioc:
    """Keep the stronger IOC and fold in the weaker tags and unwrap chain."""
    kept = copy(stronger)
    kept.tags = list(stronger.tags)
    for tag in weaker.tags:
        if tag not in kept.tags:
            kept.tags.append(tag)
    weak_from = (weaker.rewritten_from or "").strip()
    strong_from = (kept.rewritten_from or "").strip()
    if weak_from and weak_from != strong_from:
        parts = [p.strip() for p in strong_from.split("|")] if strong_from else []
        if weak_from not in parts:
            kept.rewritten_from = f"{strong_from} | {weak_from}" if strong_from else weak_from
    return kept


def _dedup_iocs(iocs: list[Ioc]) -> list[Ioc]:
    dedup: dict[tuple[str, str], Ioc] = {}
    for ioc in iocs:
        if ioc.ioc_type == IocType.URL:
            key = (ioc.ioc_type.value, normalize_url_key(ioc.value))
        else:
            key = (ioc.ioc_type.value, ioc.value.lower())
        prev = dedup.get(key)
        if prev is None:
            dedup[key] = ioc
        elif _ioc_priority(ioc) > _ioc_priority(prev):
            dedup[key] = _merge_ioc_pair(ioc, prev)
        else:
            dedup[key] = _merge_ioc_pair(prev, ioc)

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
    """Campaign fingerprint: thread root → attachment hash → subject.

    The message's own Message-ID is not a thread root and does not occupy
    the key. One attachment hash may. Several hashes must not: the minimum
    hash is arbitrary, so the subject fallback is used instead.
    """
    mid = result.mail_identity
    if mid is not None:
        thread = mid.thread_root_id()
        if thread:
            return f"thread:{thread}"
    att_hashes = sorted({a.sha256 for a in result.attachments if a.sha256})
    if len(att_hashes) == 1:
        return f"att:{att_hashes[0][:16]}"
    subject = (result.subject or (mid.subject if mid else "") or "").strip().lower()
    subject = re.sub(r"\s+", " ", subject)[:80]
    if subject:
        return f"subj:{subject}"
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
        paths = [r.path for r in group]
        for row in group:
            row.campaign_peers = [p for p in paths if p != row.path]


def _from_domain(sender: str) -> str:
    sender = (sender or "").strip().lower()
    if not sender:
        return ""
    if "<" in sender and ">" in sender:
        sender = sender.split("<", 1)[1].split(">", 1)[0]
    if "@" in sender:
        return sender.rsplit("@", 1)[-1].strip(">")
    return ""


def campaign_divergence_keys(results: list[AnalysisResult]) -> set[str]:
    """Return campaign_keys shared by ≥2 mails with different From domains."""
    by_key: dict[str, set[str]] = {}
    for r in results:
        key = campaign_key_for(r)
        if not key:
            continue
        sender = r.sender or (r.mail_identity.from_header if r.mail_identity else "") or ""
        dom = _from_domain(sender)
        if dom:
            by_key.setdefault(key, set()).add(dom)
    return {k for k, doms in by_key.items() if len(doms) >= 2}


def apply_campaign_divergence(
    results: list[AnalysisResult],
    *,
    options: AnalysisOptions | None = None,
) -> None:
    """Mark content_signals + re-render verdict when campaign From domains diverge.

    The second pass uses the same ``AnalysisOptions`` as the first (verdict
    extra, brands, org domains, allowlist).
    """
    divergent = campaign_divergence_keys(results)
    if not divergent:
        return
    opts = options or AnalysisOptions()
    cfg = load_verdict_config(opts.verdict_path)
    allow_domains: set[str] = set()
    try:
        from reliquary.core.allowlist import build_allowlist

        domains, _ips = build_allowlist(extra_path=opts.allowlist_path)
        allow_domains = domains
    except (OSError, TypeError, ValueError, ImportError):
        allow_domains = set()
    for r in results:
        key = campaign_key_for(r)
        if key not in divergent:
            continue
        if "campaign_divergence" not in (r.content_signals or []):
            r.content_signals = list(r.content_signals or []) + ["campaign_divergence"]
        if r.source_kind == "email" and r.verdict is not None:
            r.verdict = render_verdict(
                r,
                cfg,
                brands_path=opts.brands_path,
                org_domains_path=opts.org_domains_path,
                allowlist_domains=allow_domains or None,
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


def is_parser_failure(line: str) -> bool:
    """True for a real parse failure. Findings and batch bookkeeping are not."""
    text = (line or "").strip()
    if not text:
        return False
    if text.startswith("Кампании:"):
        return False
    if "карточка почты" in text:
        return False
    if text.startswith("QR data:image:"):
        return False
    if "vbaProject.bin" in text or "vbaData.xml" in text:
        return False
    if text.startswith("OOXML: найден") or text.startswith("OOXML: присутствует"):
        return False
    if text.startswith("OLE разбор") or ": OLE разбор" in text or text.startswith("OLE "):
        return False
    if ": OLE " in text and "разбор" in text:
        return False
    low = text.lower()
    if "tnef:" in low and "извлечено вложений" in low:
        return False
    if "текст обрезан до" in low:
        return False
    if "защищён паролем" in low or "защищен паролем" in low:
        return False
    if "transport-заголовки частично синтезированы" in low:
        return False
    return True


def parser_failures(errors: list[str] | None) -> list[str]:
    return [line for line in (errors or []) if is_parser_failure(line)]


def _nonfailure_kind(line: str) -> str:
    low = (line or "").lower()
    if "tnef:" in low and "извлечено вложений" in low:
        return "tnef"
    if "текст обрезан до" in low:
        return "clip"
    if "защищён паролем" in low or "защищен паролем" in low:
        return "password"
    if "transport-заголовки частично синтезированы" in low:
        return "msg"
    return ""


def _note_already(att: AttachmentInfo, line: str, kind: str) -> bool:
    for note in att.notes or []:
        low = note.lower()
        if kind == "tnef" and "извлечено" in low and "вложен" in low:
            return True
        if kind == "password" and "парол" in low:
            return True
        if note == line:
            return True
    return False


def park_nonfailure_lines(result: AnalysisResult) -> None:
    """Move the four non-failures off the error list onto a note or status line."""
    kept: list[str] = []
    status = list(result.status_notes)
    for line in result.errors:
        kind = _nonfailure_kind(line)
        if not kind:
            kept.append(line)
            continue
        if kind in {"tnef", "password"}:
            placed = False
            for att in result.attachments:
                if _note_already(att, line, kind):
                    placed = True
                    break
            if placed:
                continue
            target = None
            for att in result.attachments:
                flags = att.risk_flags or []
                if kind == "tnef" and "tnef_attachment" in flags:
                    target = att
                    break
                if kind == "password" and "encrypted_archive" in flags:
                    target = att
                    break
            if target is not None:
                target.notes.append(line)
                continue
        if line not in status:
            status.append(line)
    result.errors = kept
    result.status_notes = status


def sort_batch_rows(
    rows: list[FileTriageRow],
    *,
    column: str = "score",
    reverse: bool = True,
) -> list[FileTriageRow]:
    """Same order the batch table uses. Score descending is the default."""

    def _key(row: FileTriageRow):
        if column == "file":
            return Path(row.path).name.lower()
        if column == "verdict":
            return (row.verdict_level or "").lower()
        if column == "score":
            return row.verdict_score if row.verdict_score is not None else -1
        return Path(row.path).name.lower()

    return sorted(rows, key=_key, reverse=reverse)


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
        errors=parser_failures(result.errors),
        message_id=(mid.message_id if mid else "") or "",
        subject=result.subject or (mid.subject if mid else ""),
        sender=result.sender or (mid.from_header if mid else ""),
        campaign_key=campaign_key_for(result),
    )


# Digests of b"" — not useful IOCs when a part was saved empty.
_EMPTY_FILE_DIGESTS = frozenset(
    {
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
)


def _lift_attachment_iocs(attachments: list[AttachmentInfo], iocs: list[Ioc]) -> None:
    for att in attachments:
        skip_hashes = "empty_file" in (att.risk_flags or [])
        for algo, value, itype in (
            ("md5", att.md5, IocType.MD5),
            ("sha1", att.sha1, IocType.SHA1),
            ("sha256", att.sha256, IocType.SHA256),
        ):
            if not value or skip_hashes or value.lower() in _EMPTY_FILE_DIGESTS:
                continue
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
            # LNK / Office hyperlink targets often land in archive_entries as raw paths/URLs
            if entry.startswith(("http://", "https://", "file://", "\\\\")) or (
                "lnk_target" in (att.risk_flags or [])
                and (":\\" in entry or entry.lower().endswith((".exe", ".dll", ".js", ".vbs")))
            ):
                for qi in extract_iocs(entry, source="lnk" if "lnk" in (att.risk_flags or []) else "office"):
                    tag = "lnk_target" if "lnk" in "".join(att.risk_flags or []) else "office_hyperlink"
                    if tag not in qi.tags:
                        qi.tags.append(tag)
                    if "lnk_dangerous" in (att.risk_flags or []) and "lnk_dangerous" not in qi.tags:
                        qi.tags.append("lnk_dangerous")
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


def _parse_office_attachment(att: AttachmentInfo) -> tuple[str, list[str]]:
    """Extract text/URLs from OOXML attachments for IOC + content signals."""
    if not att.data:
        return "", []
    suffix = Path(att.filename).suffix.lower()
    if suffix not in {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}:
        return "", []
    try:
        from reliquary.core.office_extract import (
            clean_extracted,
            extract_office_text,
            extract_office_urls,
        )

        text, errs = extract_office_text(att.data, suffix)
        text = clean_extracted(text or "")
        findings = [err for err in errs if not is_parser_failure(err)]
        errs = [err for err in errs if is_parser_failure(err)]
        for note in findings:
            if note not in att.notes:
                att.notes.append(note)
        urls = extract_office_urls(att.data, suffix)
        if urls:
            if "office_hyperlink" not in att.risk_flags:
                att.risk_flags.append("office_hyperlink")
            for u in urls[:20]:
                if u not in att.archive_entries:
                    att.archive_entries.append(u)
            att.notes.append(f"OOXML-гиперссылки: {len(urls)}")
        try:
            from reliquary.core.office_extract import detect_office_remote_template

            if detect_office_remote_template(att.data):
                if "office_remote_template" not in att.risk_flags:
                    att.risk_flags.append("office_remote_template")
                att.notes.append("OOXML: remote template / TargetMode=External http(s)")
        except (OSError, ValueError, TypeError, RuntimeError):
            pass
        if not text and not errs and not urls:
            return "", []
        header = f"Office-Att {att.filename}"
        if urls and "URLs:" not in (text or ""):
            text = (text or "") + "\nURLs:\n" + "\n".join(dict.fromkeys(urls))
        return f"{header}\n{text}", errs
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        return "", [f"Office {att.filename}: {exc}"]


def _parse_web_attachment(att: AttachmentInfo) -> tuple[str, list[str]]:
    """Extract text/HTML from .html/.htm/.mht/.svg attachment bytes for IOC + signals."""
    web_flags = {"html_attachment", "mht_attachment", "svg_attachment"}
    if not att.data or not web_flags.intersection(att.risk_flags or []):
        return "", []
    errors: list[str] = []
    try:
        raw = att.data
        # Strip UTF-8 BOM; try charset sniff for MHT
        text = raw.decode("utf-8", errors="replace")
        if raw[:3] == b"\xef\xbb\xbf":
            text = raw[3:].decode("utf-8", errors="replace")
        header = f"Web-Att {att.filename} flags={','.join(sorted(web_flags.intersection(att.risk_flags)))}"
        return f"{header}\n{text}", errors
    except (UnicodeError, TypeError, ValueError) as exc:
        return "", [f"Web-att {att.filename}: {exc}"]


def _append_body_qr_note(result: AnalysisResult, notes: list[str], payloads: list[str]) -> None:
    """Park HTML-body QR payloads on an attachment note (not in parser errors)."""
    if not notes and not payloads:
        return
    att = AttachmentInfo(
        filename="тело.html",
        size=0,
        mime_guess="text/html",
        md5="",
        sha1="",
        sha256="",
        risk_flags=["qr_url"] if payloads else [],
        notes=list(notes),
        archive_entries=[f"QR:{p}" for p in payloads],
    )
    result.attachments.append(att)


def _decode_data_image_qr(html: str, result: AnalysisResult) -> str:
    """Decode data:image/*;base64 blobs in HTML. Payloads become notes and IOC text."""
    import base64
    import re as _re

    extra = ""
    try:
        from reliquary.core.qr_scan import decode_qr_payloads, qr_decoder_available
    except ImportError:
        return extra
    if not qr_decoder_available():
        result.errors.append("QR: сбой декодера (недоступен)")
        return extra
    starts = list(
        _re.finditer(
            r"data:image/(?:png|jpeg|jpg|gif);base64,",
            html,
            flags=_re.IGNORECASE,
        )
    )
    payloads_all: list[str] = []
    notes: list[str] = []
    decoder_failed = False
    found = 0
    for idx, m in enumerate(starts):
        if found >= 4:
            break
        end = starts[idx + 1].start() if idx + 1 < len(starts) else len(html)
        blob = _re.sub(r"\s+", "", html[m.end() : end])
        if len(blob) < 80:
            continue
        try:
            raw = base64.b64decode(blob, validate=False)
        except (ValueError, TypeError):
            continue
        if len(raw) < 64 or len(raw) > 2 * 1024 * 1024:
            continue
        payloads, dec_notes = decode_qr_payloads(raw)
        if dec_notes and not payloads:
            decoder_failed = True
        for p in payloads:
            if p not in payloads_all:
                payloads_all.append(p)
                extra += f"\n{p}"
        found += 1
    if len(starts) > 4:
        notes.append("просмотрено 4, дальше не декодировалось")
    if payloads_all:
        notes.insert(0, "QR: " + "; ".join(payloads_all))
    if decoder_failed and not any(e.startswith("QR: сбой декодера") for e in result.errors):
        result.errors.append("QR: сбой декодера")
    _append_body_qr_note(result, notes, payloads_all)
    return extra


def _parse_nested_email_attachment(
    att: AttachmentInfo, *, depth: int = 0, max_depth: int = 2
) -> tuple[str, list[str]]:
    """Return (extra_text, errors) from nested .eml/.msg bytes (up to ``max_depth``)."""
    if not att.data or "nested_email" not in att.risk_flags:
        return "", []
    if depth > max_depth:
        return "", [f"nested mail depth>{max_depth}: {att.filename}"]
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
            parts: list[str] = [
                f"Nested MSG {att.filename}",
                f"From: {sender}",
                f"Subject: {subj}",
            ]
            # Transport-ish headers when available
            for attr, label in (
                ("messageId", "Message-ID"),
                ("date", "Date"),
                ("inReplyTo", "In-Reply-To"),
            ):
                val = getattr(msg_file, attr, None)
                if val:
                    parts.append(f"{label}: {val}")
            # Nested MSG attachments
            try:
                for matt in msg_file.attachments:
                    mname = (
                        getattr(matt, "longFilename", None)
                        or getattr(matt, "shortFilename", None)
                        or "attachment"
                    )
                    parts.append(f"Nested-Att: {mname}")
                    raw = getattr(matt, "data", None)
                    adata = bytes(raw) if isinstance(raw, (bytes, bytearray)) else b""
                    fl = str(mname).lower()
                    if fl.endswith((".eml", ".msg")) and depth < max_depth and adata:
                        from reliquary.core.attachment_inspector import inspect_bytes

                        nested_info = inspect_bytes(str(mname), adata, keep_bytes=True)
                        extra, nest_err = _parse_nested_email_attachment(
                            nested_info, depth=depth + 1, max_depth=max_depth
                        )
                        if extra:
                            parts.append(extra)
                        errors.extend(nest_err)
                    elif fl.endswith((".one", ".onepkg", ".iso", ".lnk", ".html", ".htm")):
                        parts.append(f"Nested-Risk-Att: {mname}")
            except (OSError, ValueError, TypeError, AttributeError, RuntimeError) as exc:
                errors.append(f"Nested MSG attachments: {exc}")
            try:
                msg_file.close()
            except (OSError, AttributeError, RuntimeError):
                pass
            parts.append(body)
            parts.append(html if isinstance(html, str) else "")
            return "\n".join(parts), errors
        # .eml / rfc822
        from reliquary.core.document_parser import normalize_email_bytes

        msg = email.message_from_bytes(
            normalize_email_bytes(att.data),  # type: ignore[arg-type]
            policy=email.policy.default,
        )
        parts = [
            f"Nested EML {att.filename}",
            f"From: {msg.get('From', '')}",
            f"Reply-To: {msg.get('Reply-To', '')}",
            f"Subject: {msg.get('Subject', '')}",
            f"Message-ID: {msg.get('Message-ID', '')}",
            f"In-Reply-To: {msg.get('In-Reply-To', '')}",
            f"Authentication-Results: {msg.get('Authentication-Results', '')}",
        ]
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                fname = part.get_filename() or ""
                if fname:
                    parts.append(f"Nested-Att: {fname}")
                    fl = fname.lower()
                    if fl.endswith((".eml", ".msg")) and depth < max_depth:
                        try:
                            if part.get_content_type() == "message/rfc822":
                                from reliquary.core.document_parser import _part_payload

                                raw = _part_payload(part)
                            else:
                                raw = part.get_payload(decode=True)
                        except (TypeError, ValueError, AttributeError):
                            raw = None
                        if isinstance(raw, (bytes, bytearray)) and raw:
                            from reliquary.core.attachment_inspector import inspect_bytes

                            nested_info = inspect_bytes(fname, bytes(raw), keep_bytes=True)
                            extra, nest_err = _parse_nested_email_attachment(
                                nested_info, depth=depth + 1, max_depth=max_depth
                            )
                            if extra:
                                parts.append(extra)
                            errors.extend(nest_err)
                    elif fl.endswith((".one", ".onepkg", ".iso", ".lnk")):
                        parts.append(f"Nested-Risk-Att: {fname}")
                    continue
                if ctype in ("text/plain", "text/html"):
                    try:
                        raw = part.get_payload(decode=True)
                        if not isinstance(raw, (bytes, bytearray)):
                            continue
                        from reliquary.core.attachment_inspector import decode_payload_text

                        parts.append(
                            decode_payload_text(bytes(raw), part.get_content_charset())
                        )
                    except (LookupError, UnicodeError, TypeError, ValueError, AttributeError):
                        continue
        else:
            try:
                raw = msg.get_payload(decode=True)
                if isinstance(raw, (bytes, bytearray)):
                    from reliquary.core.attachment_inspector import decode_payload_text

                    parts.append(decode_payload_text(bytes(raw), msg.get_content_charset()))
                else:
                    parts.append(str(msg.get_payload()))
            except (LookupError, UnicodeError, TypeError, ValueError, AttributeError):
                parts.append(str(msg.get_payload()))
        return "\n".join(parts), errors
    except (
        OSError,
        ValueError,
        TypeError,
        AttributeError,
        KeyError,
        LookupError,
        UnicodeError,
        RuntimeError,
    ) as exc:
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


# Hard cap for source EML/MSG bytes loaded into memory (DoS / RAM).
MAX_SOURCE_BYTES = 40 * 1024 * 1024
# Soft timeout hint for GUI cancel (seconds); analysis checks cancel flag between stages.
DEFAULT_ANALYSIS_TIMEOUT_S = 120.0


def source_too_large_message(size: int) -> str:
    """User-facing stop line. The cap is fixed; there is no setting to raise it."""
    mb = MAX_SOURCE_BYTES // (1024 * 1024)
    return f"Файл больше {mb} МБ ({size} байт). Разбор остановлен."


def text_too_large_message() -> str:
    mb = MAX_SOURCE_BYTES // (1024 * 1024)
    return f"Текст больше {mb} МБ. Разбор остановлен."


def _mailbox_ioc_lines(value: str) -> list[str]:
    """Display name and mailbox. Angle brackets hide the address from extract_iocs."""
    text = (value or "").strip()
    if not text:
        return []
    lines: list[str] = []
    for name, addr in email.utils.getaddresses([text]):
        if name and name.strip():
            lines.append(name.strip())
        if addr and "@" in addr:
            lines.append(addr.strip())
    if lines:
        return lines
    return [text.replace("<", " ").replace(">", " ")]


def _header_ioc_text(result: AnalysisResult, parsed) -> str:
    """Already-parsed Subject, From and Reply-To for the same IOC extractor."""
    mid = result.mail_identity
    subject = (mid.subject if mid else "") or getattr(parsed, "subject", "") or ""
    sender = (mid.from_header if mid else "") or getattr(parsed, "sender", "") or ""
    reply = (mid.reply_to if mid else "") or ""
    if not reply and getattr(parsed, "message", None) is not None:
        reply = str(parsed.message.get("Reply-To", "") or "")
    chunks = [subject.strip()] if subject and subject.strip() else []
    chunks.extend(_mailbox_ioc_lines(sender))
    chunks.extend(_mailbox_ioc_lines(reply))
    return "\n".join(chunks)


def _enrich_parsed_result(
    result: AnalysisResult,
    parsed,
    *,
    opts: AnalysisOptions,
    verdict_cfg: VerdictConfig | None,
    ioc_source: str,
    tag_filename: str | None,
    surface_ole_notes: bool = True,
) -> AnalysisResult:
    """Shared post-parse enrichment: nested mail, URL unwrap, IOC, verdict."""
    if parsed.message is not None:
        try:
            result.headers = analyze_headers(parsed.message)
            result.raw_headers = extract_raw_headers(parsed.message)
            result.mail_identity = build_mail_identity(parsed.message)
        except (
            OSError,
            ValueError,
            TypeError,
            AttributeError,
            KeyError,
            LookupError,
            UnicodeError,
            re.error,
        ) as exc:
            result.errors.append(f"Заголовки: {exc}")

    blob = f"{parsed.text}\n{parsed.html}"

    # Archives are signals (names, encryption). Payloads are not unpacked.
    expanded: list = []
    for att in list(result.attachments):
        if att.data and "tnef_attachment" in (att.risk_flags or []):
            try:
                from reliquary.core.attachment_inspector import inspect_bytes
                from reliquary.core.tnef import extract_tnef_attachments

                parts, tnotes = extract_tnef_attachments(att.data)
                result.errors.extend(tnotes)
                for fname, payload in parts:
                    expanded.append(inspect_bytes(fname, payload, keep_bytes=True))
                if parts:
                    att.notes.append(f"TNEF: извлечено {len(parts)} вложений")
            except (OSError, ValueError, TypeError, ImportError) as exc:
                result.errors.append(f"TNEF {att.filename}: {exc}")
    if expanded:
        result.attachments.extend(expanded)

    yara_rules = None
    yara_hits: list[str] = []
    if opts.enable_yara:
        try:
            from reliquary.core.yara_scan import compiled_rules

            yara_rules, ynotes = compiled_rules(opts.yara_rules_path)
            for note in ynotes:
                if note not in result.errors:
                    result.errors.append(note)
        except (OSError, TypeError, ValueError, ImportError) as exc:
            result.errors.append(f"YARA: {exc}")
            yara_rules = None

    # data:image QR in HTML body
    if parsed.html and "data:image" in parsed.html.lower():
        blob += _decode_data_image_qr(parsed.html, result)

    for att in result.attachments:
        nested_text, nested_errs = _parse_nested_email_attachment(att)
        if nested_text:
            blob += "\n" + nested_text
            att.notes.append("Вложенное письмо разобрано локально")
        result.errors.extend(nested_errs)
        web_text, web_errs = _parse_web_attachment(att)
        if web_text:
            blob += "\n" + web_text
            att.notes.append("HTML/SVG/MHT разобрано локально")
        result.errors.extend(web_errs)
        office_text, office_errs = _parse_office_attachment(att)
        if office_text:
            blob += "\n" + office_text
            if "office_text_extracted" not in att.risk_flags:
                att.risk_flags.append("office_text_extracted")
            att.notes.append("Текст Office извлечён офлайн")
        result.errors.extend(office_errs)
        for note in att.notes:
            if note.startswith("LNK→ "):
                blob += "\n" + note[5:]
        if yara_rules is not None and att.data:
            try:
                from reliquary.core.yara_scan import scan_bytes

                hits, ynotes = scan_bytes(att.data, compiled=yara_rules)
            except (OSError, TypeError, ValueError) as exc:
                hits, ynotes = [], [f"YARA: {exc}"]
            for rule in hits:
                if rule not in yara_hits:
                    yara_hits.append(rule)
                if "yara_match" not in att.risk_flags:
                    att.risk_flags.append("yara_match")
                att.notes.append(f"YARA: {rule}")
            for note in ynotes:
                if note not in result.errors:
                    result.errors.append(note)
        elif yara_rules is not None and not att.data and any(
            "не сохранено в памяти" in (note or "") for note in (att.notes or [])
        ):
            missed = f"YARA не видела этот файл ({att.filename})"
            if missed not in att.notes:
                att.notes.append(missed)
        if (
            att.data is not None
            and (
                "nested_email" in att.risk_flags
                or {"html_attachment", "mht_attachment", "svg_attachment"}.intersection(
                    att.risk_flags or []
                )
                or "office_text_extracted" in (att.risk_flags or [])
                or Path(att.filename).suffix.lower()
                in {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
            )
            and att.size > 2 * 1024 * 1024
        ):
            att.data = None
        if "encrypted_archive" in att.risk_flags:
            msg = f"⚠ {att.filename}: архив защищён паролем — содержимое не извлечено"
            if msg not in result.errors:
                result.errors.append(msg)
        for note in list(att.notes):
            if "сбой декодера" in note and not any(
                e.startswith("QR: сбой декодера") for e in result.errors
            ):
                result.errors.append("QR: сбой декодера")
                break
    _ = surface_ole_notes

    try:
        result.url_rewrites = find_and_unwrap(blob)
    except (ValueError, TypeError, AttributeError, KeyError, IndexError, re.error) as exc:
        result.errors.append(f"URL rewrite: {exc}")

    enriched = blob
    for rewrite in result.url_rewrites:
        if rewrite.changed:
            enriched += f"\n{rewrite.unwrapped}"

    try:
        iocs = extract_iocs(enriched, source=ioc_source)
    except (ValueError, TypeError, AttributeError, KeyError, IndexError, re.error) as exc:
        result.errors.append(f"IOC: {exc}")
        iocs = []
    header_text = _header_ioc_text(result, parsed)
    if header_text:
        try:
            iocs.extend(extract_iocs(header_text, source="header"))
        except (ValueError, TypeError, AttributeError, KeyError, IndexError, re.error) as exc:
            result.errors.append(f"IOC: {exc}")

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
    if tag_filename:
        result.iocs = [_tag_file(i, tag_filename) for i in result.iocs]
    result.score_text = enriched
    result.score_html = getattr(parsed, "html", "") or ""
    result.body_chars = len(getattr(parsed, "text", "") or "")
    if yara_rules is not None:
        try:
            from reliquary.core.yara_scan import scan_bytes

            body_blob = f"{getattr(parsed, 'text', '')}\n{getattr(parsed, 'html', '')}".strip()
            if body_blob:
                hits, ynotes = scan_bytes(
                    body_blob.encode("utf-8", errors="replace"),
                    compiled=yara_rules,
                )
                for rule in hits:
                    if rule not in yara_hits:
                        yara_hits.append(rule)
                for note in ynotes:
                    if note not in result.errors:
                        result.errors.append(note)
        except (OSError, TypeError, ValueError) as exc:
            result.errors.append(f"YARA: {exc}")
        for rule in yara_hits:
            sig = f"yara:{rule}"
            if sig not in result.content_signals:
                result.content_signals.append(sig)
    park_nonfailure_lines(result)
    if result.source_kind == "email":
        cfg = verdict_cfg or load_verdict_config(opts.verdict_path)
        allow_domains: set[str] = set()
        try:
            from reliquary.core.allowlist import build_allowlist

            domains, _ips = build_allowlist(extra_path=opts.allowlist_path)
            allow_domains = domains
        except (OSError, TypeError, ValueError, ImportError):
            allow_domains = set()
        result.verdict = render_verdict(
            result,
            cfg,
            brands_path=opts.brands_path,
            org_domains_path=opts.org_domains_path,
            allowlist_domains=allow_domains or None,
        )
    result.file_rows = [file_triage_row(result)]
    return result


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
        size = path.stat().st_size
    except OSError as exc:
        return AnalysisResult(
            source_path=str(path),
            source_kind="unknown",
            errors=[f"Чтение файла: {exc}"],
            meta=_build_meta(str(path), options=opts),
        )
    if size > MAX_SOURCE_BYTES:
        return AnalysisResult(
            source_path=str(path),
            source_kind="unknown",
            errors=[source_too_large_message(size)],
            meta=_build_meta(str(path), options=opts),
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
    return _enrich_parsed_result(
        result,
        parsed,
        opts=opts,
        verdict_cfg=verdict_cfg,
        ioc_source=parsed.kind,
        tag_filename=str(path),
        surface_ole_notes=True,
    )


def _looks_like_rfc822(text: str) -> bool:
    from reliquary.core.document_parser import normalize_email_text

    head = normalize_email_text(text).lstrip()[:4000]
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
    if len(data) > MAX_SOURCE_BYTES:
        return AnalysisResult(
            source_path=label,
            source_kind="unknown",
            errors=[text_too_large_message()],
            meta=_build_meta(label, options=opts),
        )
    from reliquary.core.document_parser import normalize_email_bytes, parse_eml

    data = normalize_email_bytes(data)
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
    return _enrich_parsed_result(
        result,
        parsed,
        opts=opts,
        verdict_cfg=verdict_cfg,
        ioc_source="email",
        tag_filename=None,
        surface_ole_notes=True,
    )


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
    apply_campaign_divergence(results, options=opts)
    # Refresh rows after divergence re-score (per-message verdicts stay).
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
    for r in results:
        fname = r.source_path or Path(r.source_path).name
        for ioc in r.iocs:
            iocs.append(_tag_file(ioc, fname))
        merged.url_rewrites.extend(r.url_rewrites)
        merged.attachments.extend(r.attachments)
        merged.headers.extend(r.headers)
        for err in parser_failures(r.errors):
            if err not in merged.errors:
                merged.errors.append(err)
        if r.mail_identity and merged.mail_identity is None:
            merged.mail_identity = r.mail_identity
            merged.raw_headers = dict(r.raw_headers)
    merged.iocs = _finalize_iocs(iocs, allowlist_path=opts.allowlist_path)
    # The batch card is not a re-score of every signal piled together.
    # GUI shows the already computed verdict of the selected message.
    merged.verdict = None
    _ = verdict_cfg
    return merged


def rescore_with_options(
    result: AnalysisResult,
    options: AnalysisOptions | None = None,
) -> AnalysisResult:
    """Re-run the current message with a new options set (allowlist file)."""
    opts = _resolve_options(options=options)
    path = Path(result.source_path) if result.source_path else None
    if (
        path is not None
        and path.is_file()
        and path.suffix.lower() in {".eml", ".msg"}
    ):
        return analyze_file(path, options=opts)
    iocs = []
    for ioc in result.iocs:
        cloned = copy(ioc)
        cloned.tags = [tag for tag in ioc.tags if tag != "allowlisted"]
        iocs.append(cloned)
    result.iocs = _finalize_iocs(iocs, allowlist_path=opts.allowlist_path)
    if result.source_kind == "email":
        cfg = load_verdict_config(opts.verdict_path)
        allow_domains: set[str] = set()
        try:
            from reliquary.core.allowlist import build_allowlist

            domains, _ips = build_allowlist(extra_path=opts.allowlist_path)
            allow_domains = domains
        except (OSError, TypeError, ValueError, ImportError):
            allow_domains = set()
        result.verdict = render_verdict(
            result,
            cfg,
            brands_path=opts.brands_path,
            org_domains_path=opts.org_domains_path,
            allowlist_domains=allow_domains or None,
        )
        if result.verdict is not None:
            result.file_rows = [file_triage_row(result)]
    return result
