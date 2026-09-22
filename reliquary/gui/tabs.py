"""Result tab badge helpers (kept out of CustomTkinter app module for unit tests)."""

from __future__ import annotations

from reliquary.core.models import AnalysisResult


def desired_result_tabs(
    result: AnalysisResult | None,
    filtered_count: int = 0,
    *,
    compact: bool = False,
) -> list[tuple[str, str]]:
    """Which result facets to show: (stable_key, badge_label).

    Verdict tab is always first for email triage.
    Labels stay short and stable (no verdict level in the tab — that lives
    in the summary badge) so the segmented bar does not jump on refresh/EXE.
    """
    _ = compact  # kept for API compatibility; labels are always compact/stable
    if result is None:
        return [("mail", "Вердикт"), ("ioc", "IOC")]

    tabs: list[tuple[str, str]] = [("mail", "Вердикт")]

    if result.attachments:
        n = len(result.attachments)
        risky = sum(1 for a in result.attachments if a.risk_flags)
        tabs.append(("att", f"Влож. {n}" + ("!" if risky else "")))

    if result.url_rewrites:
        total = len(result.url_rewrites)
        tabs.append(("url", f"URL {total}"))

    tabs.append(("ioc", f"IOC {filtered_count}"))

    rows = result.file_rows or []
    if len(rows) >= 2:
        tabs.append(("batch", f"Пакет {len(rows)}"))

    if result.errors:
        tabs.append(("err", f"Ошибки {len(result.errors)}"))
    return tabs
