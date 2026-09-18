"""Result tab badge helpers (kept out of CustomTkinter app module for unit tests)."""

from __future__ import annotations

from reliquary.core.models import AnalysisResult


def desired_result_tabs(
    result: AnalysisResult | None, filtered_count: int = 0
) -> list[tuple[str, str]]:
    """Which result facets to show: (stable_key, badge_label)."""
    if result is None:
        return [("ioc", "IOC")]

    tabs: list[tuple[str, str]] = [("ioc", f"IOC {filtered_count}")]
    rows = result.file_rows or []
    if len(rows) >= 2:
        tabs.append(("batch", f"Пакет {len(rows)}"))
    if result.url_rewrites:
        changed = sum(1 for u in result.url_rewrites if u.changed)
        if changed:
            tabs.append(("url", f"URL {changed}/{len(result.url_rewrites)}"))
        else:
            tabs.append(("url", f"URL {len(result.url_rewrites)}"))
    if result.attachments:
        risky = sum(1 for a in result.attachments if a.risk_flags)
        if risky:
            tabs.append(("att", f"Вложения {len(result.attachments)}·{risky}!"))
        else:
            tabs.append(("att", f"Вложения {len(result.attachments)}"))
    mail_relevant = result.source_kind in ("email", "batch") and bool(
        result.verdict
        or result.mail_identity
        or result.headers
        or result.raw_headers
        or any(r.kind == "email" for r in rows)
    )
    if mail_relevant:
        if result.verdict:
            tabs.append(("mail", f"Письмо · {result.verdict.level.value}"))
        else:
            tabs.append(("mail", "Письмо"))
    if result.errors:
        tabs.append(("err", f"Ошибки {len(result.errors)}"))
    return tabs
