"""Ticket / handoff text templates for SOC clipboard paste."""

from __future__ import annotations

from pathlib import Path

from reliquary.core.defang import defang_value
from reliquary.core.models import AnalysisResult, Ioc


def build_ticket_template(
    result: AnalysisResult,
    iocs: list[Ioc] | None = None,
    *,
    defang: bool = True,
    max_iocs: int = 40,
) -> str:
    """Plain-text triage note suitable for ITSM / chat handoff."""
    items = iocs if iocs is not None else result.iocs
    mid = result.mail_identity
    lines: list[str] = [
        "=== IOC Extractor — triage note ===",
        f"Source: {result.source_path}",
        f"Kind: {result.source_kind}",
    ]
    if result.meta:
        lines.append(f"Analyzed: {result.meta.analyzed_at}")
        lines.append(f"App: v{result.meta.app_version}")
        if result.meta.source_sha256:
            lines.append(f"Source SHA256: {result.meta.source_sha256}")

    if result.verdict:
        lines.append(
            f"Verdict: {result.verdict.level.value.upper()} (score {result.verdict.score})"
        )
        lines.append(f"Summary: {result.verdict.summary}")
        if result.verdict.reasons:
            lines.append("Reasons:")
            for r in result.verdict.reasons[:8]:
                lines.append(f"  - {r}")

    lines.append("")
    lines.append("--- Mail ---")
    subject = (mid.subject if mid and mid.subject else result.subject) or "—"
    sender = (mid.from_header if mid and mid.from_header else result.sender) or "—"
    reply_to = (mid.reply_to if mid else "") or "—"
    lines.append(f"Subject: {subject}")
    lines.append(f"From: {sender}")
    lines.append(f"Reply-To: {reply_to}")
    if mid:
        lines.append(f"Return-Path: {mid.return_path or '—'}")
        lines.append(f"Message-ID: {mid.message_id or '—'}")
        lines.append(
            f"Auth: SPF={mid.spf or '—'} DKIM={mid.dkim or '—'} DMARC={mid.dmarc or '—'}"
        )
        lines.append(f"Date: {mid.date or '—'}")

    lines.append("")
    lines.append("--- Unwrapped URLs ---")
    rewrites = [u for u in result.url_rewrites if u.changed]
    if not rewrites:
        lines.append("(none)")
    else:
        for u in rewrites[:20]:
            val = defang_value(u.unwrapped) if defang else u.unwrapped
            lines.append(f"  {u.rewriter}: {val}")

    lines.append("")
    lines.append("--- Attachments ---")
    if not result.attachments:
        lines.append("(none)")
    else:
        for a in result.attachments[:30]:
            flags = ",".join(a.risk_flags) if a.risk_flags else "-"
            lines.append(f"  {a.filename} | {a.size}B | sha256={a.sha256} | flags={flags}")
            if a.ole_streams:
                lines.append(f"    OLE streams: {', '.join(a.ole_streams[:8])}")

    lines.append("")
    lines.append(f"--- IOC (top {max_iocs}) ---")
    if not items:
        lines.append("(none)")
    else:
        for ioc in items[:max_iocs]:
            val = defang_value(ioc.value) if defang else ioc.value
            tags = ",".join(ioc.tags) if ioc.tags else ""
            suffix = f" [{tags}]" if tags else ""
            lines.append(f"  {ioc.ioc_type.value}|{val}{suffix}")

    if result.file_rows and len(result.file_rows) > 1:
        lines.append("")
        lines.append("--- Batch files ---")
        for row in result.file_rows:
            name = Path(row.path).name
            v = row.verdict_level or "-"
            err = f" err={len(row.errors)}" if row.errors else ""
            lines.append(f"  {name} | {row.kind} | {v} | iocs={row.ioc_count}{err}")

    lines.append("")
    lines.append("=== end ===")
    return "\n".join(lines)


def build_message_id_block(result: AnalysisResult) -> str:
    """Message-ID (+ subject) for campaign correlation."""
    mid = result.mail_identity
    parts: list[str] = []
    if mid and mid.message_id:
        parts.append(mid.message_id)
    elif result.raw_headers.get("Message-ID"):
        parts.append(result.raw_headers["Message-ID"])
    if mid and mid.subject:
        parts.append(f"Subject: {mid.subject}")
    elif result.subject:
        parts.append(f"Subject: {result.subject}")
    if result.file_rows:
        for row in result.file_rows:
            if row.message_id:
                parts.append(row.message_id)
    # Dedup
    seen: set[str] = set()
    out: list[str] = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return "\n".join(out)
