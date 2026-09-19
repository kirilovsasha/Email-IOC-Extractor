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
    ``compact`` shortens labels so the segmented bar fits a narrow pane.
    """
    if result is None:
        return [("mail", "Вердикт"), ("ioc", "IOC")]

    tabs: list[tuple[str, str]] = []

    if result.verdict and not compact:
        tabs.append(("mail", f"Вердикт · {result.verdict.level.value}"))
    else:
        tabs.append(("mail", "Вердикт"))

    if result.attachments:
        n = len(result.attachments)
        risky = sum(1 for a in result.attachments if a.risk_flags)
        if compact:
            label = f"Влож. {n}" + ("!" if risky else "")
        elif risky:
            label = f"Вложения {n}·{risky}!"
        else:
            label = f"Вложения {n}"
        tabs.append(("att", label))

    if result.url_rewrites:
        total = len(result.url_rewrites)
        changed = sum(1 for u in result.url_rewrites if u.changed)
        if compact:
            tabs.append(("url", f"URL {total}"))
        elif changed:
            tabs.append(("url", f"URL {changed}/{total}"))
        else:
            tabs.append(("url", f"URL {total}"))

    tabs.append(("ioc", f"IOC {filtered_count}"))

    rows = result.file_rows or []
    if len(rows) >= 2:
        tabs.append(("batch", f"Пакет {len(rows)}" if not compact else f"Пак. {len(rows)}"))

    if result.errors:
        n = len(result.errors)
        tabs.append(("err", f"Ошибки {n}" if not compact else f"! {n}"))
    return tabs
