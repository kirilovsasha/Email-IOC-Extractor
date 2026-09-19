"""Analyst handoff text for ITSM / ticket paste (offline, plain text)."""

from __future__ import annotations

from pathlib import Path

from reliquary import __app_name__, __version__
from reliquary.core.defang import defang_value
from reliquary.core.models import AnalysisResult, Ioc
from reliquary.core.paths import app_dir

_EXTRA_NAME = "handoff_extra.txt"

_PLACEHOLDER_KEYS = (
    "product",
    "version",
    "verdict",
    "score",
    "summary",
    "reasons",
    "actions",
    "breakdown",
    "file",
    "from",
    "subject",
    "msg_id",
    "auth",
    "iocs",
    "batch",
)


def default_extra_handoff_path() -> Path:
    return app_dir() / _EXTRA_NAME


def default_level_handoff_path(level: str) -> Path:
    return app_dir() / f"handoff_{level.strip().lower()}.txt"


def resolve_handoff_template_path(
    explicit: str | Path | None = None,
    level: str | None = None,
) -> Path | None:
    """Explicit path wins; else ``handoff_{level}.txt`` then ``handoff_extra.txt`` next to app."""
    if explicit is not None and str(explicit).strip():
        return Path(str(explicit).strip())
    if level is not None and str(level).strip():
        level_candidate = default_level_handoff_path(str(level))
        if level_candidate.is_file():
            return level_candidate
    candidate = default_extra_handoff_path()
    return candidate if candidate.is_file() else None


def load_handoff_template(
    path: str | Path | None = None,
    *,
    level: str | None = None,
) -> str | None:
    resolved = resolve_handoff_template_path(path, level=level)
    if resolved is None:
        return None
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError:
        return None
    return text if text.strip() else None


def _handoff_values(
    result: AnalysisResult,
    iocs: list[Ioc] | None,
    *,
    defang: bool,
    max_iocs: int,
) -> dict[str, str]:
    mid = result.mail_identity
    v = result.verdict
    evidence = list(iocs if iocs is not None else result.iocs)

    reasons = ""
    actions = ""
    breakdown = ""
    if v:
        reasons = "\n".join(f"  - {r}" for r in v.reasons[:8]) or "  - —"
        actions = (
            "\n".join(f"  {a.priority}. {a.action}" for a in v.actions[:5]) or "  —"
        )
        if v.breakdown:
            breakdown = "\n".join(
                f"  +{b.points} {b.category}: {b.reason}" for b in v.breakdown
            )

    ioc_lines: list[str] = []
    for ioc in evidence[:max_iocs]:
        val = defang_value(ioc.value) if defang else ioc.value
        ioc_lines.append(f"  {ioc.ioc_type.value}|{val}")
    if len(evidence) > max_iocs:
        ioc_lines.append(f"  … +{len(evidence) - max_iocs} more")

    batch_lines: list[str] = []
    rows = result.file_rows or []
    if len(rows) >= 2:
        for row in rows[:30]:
            name = Path(row.path).name
            level = (row.verdict_level or "—").upper()
            score = f" {row.verdict_score}" if row.verdict_score is not None else ""
            top = f" · {row.top_reason}" if getattr(row, "top_reason", "") else ""
            batch_lines.append(f"  {name}: {level}{score}, IOC {row.ioc_count}{top}")

    src = Path(result.source_path).name if result.source_path else "—"
    from_hdr = "—"
    subject = result.subject or "—"
    msg_id = "—"
    auth = "—"
    if mid:
        from_hdr = mid.from_header or "—"
        subject = mid.subject or result.subject or "—"
        msg_id = mid.message_id or "—"
        auth = f"SPF={mid.spf or '—'} DKIM={mid.dkim or '—'} DMARC={mid.dmarc or '—'}"
    else:
        if result.sender:
            from_hdr = result.sender
        mid_hdr = result.raw_headers.get("Message-ID")
        if mid_hdr:
            msg_id = mid_hdr

    return {
        "product": __app_name__,
        "version": __version__,
        "verdict": v.level.value.upper() if v else "—",
        "score": str(v.score) if v else "—",
        "summary": (v.summary if v else "") or "—",
        "reasons": reasons or "  - —",
        "actions": actions or "  —",
        "breakdown": breakdown or "  —",
        "file": src,
        "from": from_hdr,
        "subject": subject,
        "msg_id": msg_id,
        "auth": auth,
        "iocs": "\n".join(ioc_lines) if ioc_lines else "  —",
        "batch": "\n".join(batch_lines) if batch_lines else "",
    }


def _apply_template(template: str, values: dict[str, str]) -> str:
    """Replace ``{key}`` placeholders; unknown braces left intact when possible."""
    out = template
    for key in _PLACEHOLDER_KEYS:
        out = out.replace("{" + key + "}", values.get(key, ""))
    return out.rstrip() + "\n"


def render_default_handoff(
    result: AnalysisResult,
    iocs: list[Ioc] | None = None,
    *,
    defang: bool = True,
    max_iocs: int = 40,
) -> str:
    """Built-in compact triage block (no template file)."""
    values = _handoff_values(result, iocs, defang=defang, max_iocs=max_iocs)
    lines: list[str] = [f"=== {values['product']} — handoff ===", ""]
    if values["verdict"] != "—":
        lines.append(f"Verdict: {values['verdict']} (score {values['score']}/100)")
        if values["summary"] and values["summary"] != "—":
            lines.append(f"Summary: {values['summary']}")
        lines.append("Reasons:")
        lines.append(values["reasons"])
        lines.append("Actions:")
        lines.append(values["actions"])
        lines.append("")
    lines.append(f"File: {values['file']}")
    lines.append(f"From: {values['from']}")
    lines.append(f"Subject: {values['subject']}")
    lines.append(f"Message-ID: {values['msg_id']}")
    if values["auth"] != "—":
        lines.append(f"Auth: {values['auth']}")
    evidence = list(iocs if iocs is not None else result.iocs)
    if evidence:
        lines.append("")
        lines.append(f"IOC evidence ({min(len(evidence), max_iocs)}/{len(evidence)}):")
        lines.append(values["iocs"])
    if values["batch"]:
        rows = result.file_rows or []
        lines.append("")
        lines.append(f"Batch files ({len(rows)}):")
        lines.append(values["batch"])
    lines.append("")
    return "\n".join(lines)


def render_handoff(
    result: AnalysisResult,
    iocs: list[Ioc] | None = None,
    *,
    defang: bool = True,
    max_iocs: int = 40,
    template: str | None = None,
    template_path: str | Path | None = None,
    handoff_by_level: dict[str, Path | str] | None = None,
) -> str:
    """Build a compact triage block for paste into a ticket.

    Optional ``template`` / ``template_path`` uses placeholders:
    ``{product} {version} {verdict} {score} {summary} {reasons} {actions}
    {breakdown} {file} {from} {subject} {msg_id} {auth} {iocs} {batch}``.

    When ``handoff_by_level`` or ``handoff_{level}.txt`` next to the app is set,
    the template is chosen from the verdict level (falls back to ``handoff_extra.txt``).
    """
    body = template
    if body is None:
        level = result.verdict.level.value if result.verdict else None
        explicit: str | Path | None = template_path
        if (not explicit or not str(explicit).strip()) and handoff_by_level and level:
            mapped = handoff_by_level.get(level)
            if mapped is not None and str(mapped).strip():
                explicit = mapped
        body = load_handoff_template(explicit, level=level)
    if body:
        values = _handoff_values(result, iocs, defang=defang, max_iocs=max_iocs)
        return _apply_template(body, values)
    return render_default_handoff(result, iocs, defang=defang, max_iocs=max_iocs)


def export_handoff(
    result: AnalysisResult,
    path: str | Path,
    iocs: list[Ioc] | None = None,
    *,
    defang: bool = True,
    template: str | None = None,
    template_path: str | Path | None = None,
    handoff_by_level: dict[str, Path | str] | None = None,
) -> Path:
    out = Path(path)
    out.write_text(
        render_handoff(
            result,
            iocs,
            defang=defang,
            template=template,
            template_path=template_path,
            handoff_by_level=handoff_by_level,
        ),
        encoding="utf-8",
    )
    return out
