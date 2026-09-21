"""Offline inbox calibration (no DB) — shared by CLI script and GUI."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from reliquary.core.pipeline import analyze_file


def segment_for(result) -> str:
    """Грубая сегментация для калибровки FP/FN без БД."""
    signals = set(result.content_signals or [])
    if "bec_payment" in signals:
        return "bec"
    if any(u.changed for u in (result.url_rewrites or [])):
        rewriters = {u.rewriter for u in result.url_rewrites if u.changed}
        if "microsoft_safelinks" in rewriters:
            return "safelinks"
        if rewriters & {"mailru_away", "yandex_redir"}:
            return "ru_rewrite"
        return "rewrite"
    if any(
        f in (a.risk_flags or [])
        for a in (result.attachments or [])
        for f in (
            "dangerous_extension",
            "macro_enabled_office",
            "encrypted_archive",
            "iso_image",
            "shortcut_lnk",
            "html_smuggling",
            "pdf_javascript",
            "html_attachment",
        )
    ):
        return "attachment"
    if "credential_harvest" in signals or "href_mismatch" in signals:
        return "phishing_content"
    mid = result.mail_identity
    if mid and ((mid.auto_submitted or "").lower() not in ("", "no")):
        return "auto_reply"
    if mid and (
        (mid.list_unsubscribe or mid.list_id or "").strip()
        or (mid.precedence or "").lower() in ("bulk", "list", "junk")
    ):
        return "bulk_mail"
    subj = (result.subject or "").lower()
    if "meeting" in subj or "приглашен" in subj or "calendar" in subj:
        return "calendar"
    reasons = (result.verdict.reasons if result.verdict else []) or []
    if any("lookalike" in (r or "").lower() for r in reasons):
        return "lookalike"
    return "other"


@dataclass
class InboxCalibrationReport:
    folder: str
    file_count: int = 0
    scored: int = 0
    level_counts: dict[str, int] = field(default_factory=dict)
    by_segment: dict[str, dict[str, int]] = field(default_factory=dict)
    mean_score: float | None = None
    hints: list[str] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)

    def to_text(self) -> str:
        return "\n".join(self.lines) + ("\n" if self.lines else "")


def calibrate_inbox(folder: str | Path) -> InboxCalibrationReport:
    """Scan .eml/.msg under folder; return RU text report (configs beside EXE only)."""
    root = Path(folder)
    report = InboxCalibrationReport(folder=str(root))
    files = sorted(
        p for p in root.rglob("*") if p.suffix.lower() in {".eml", ".msg"} and p.is_file()
    )
    report.file_count = len(files)
    if not files:
        report.lines = [f"Нет .eml/.msg в {root}"]
        report.hints = ["Положите выгрузку почты в папку и повторите"]
        return report

    counts: dict[str, int] = {}
    scores: list[int] = []
    by_seg: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    lines: list[str] = [
        f"Калибровка inbox ({len(files)} файлов) — {root}",
        "Без БД: только офлайн-разбор. Конфиги — рядом с EXE.",
        "",
    ]
    for path in files:
        result = analyze_file(path)
        v = result.verdict
        if v is None:
            lines.append(f"ПРОПУСК  {path.name}: нет вердикта")
            continue
        seg = segment_for(result)
        counts[v.level.value] = counts.get(v.level.value, 0) + 1
        by_seg[seg][v.level.value] += 1
        scores.append(v.score)
        report.scored += 1
        lines.append(f"  [{seg}] {path.name}: {v.level.value} score={v.score}")

    lines.append("")
    lines.append("Распределение уровней:")
    for level in ("benign", "unknown", "suspicious", "malicious"):
        lines.append(f"  {level}: {counts.get(level, 0)}")
    lines.append("")
    lines.append("По сегментам:")
    for seg in sorted(by_seg):
        parts = ", ".join(f"{lvl}={n}" for lvl, n in sorted(by_seg[seg].items()))
        lines.append(f"  {seg}: {parts}")

    hints: list[str] = []
    marketing_fp = by_seg.get("safelinks", {}).get("suspicious", 0) + by_seg.get(
        "safelinks", {}
    ).get("malicious", 0)
    bulk_fp = by_seg.get("bulk_mail", {}).get("suspicious", 0) + by_seg.get("bulk_mail", {}).get(
        "malicious", 0
    )
    bec_fn = by_seg.get("bec", {}).get("benign", 0) + by_seg.get("bec", {}).get("unknown", 0)
    if marketing_fp:
        hints.append(
            f"FP: safelinks→suspicious/malicious = {marketing_fp} (см. weight_url_rewrite)"
        )
    if bulk_fp:
        hints.append(
            f"FP: bulk_mail→suspicious/malicious = {bulk_fp} (см. weight_mailing_list)"
        )
    if bec_fn:
        hints.append(f"FN: bec→benign/unknown = {bec_fn} (см. weight_bec_payment)")
    if hints:
        lines.append("")
        lines.extend(hints)

    mean: float | None = None
    if scores:
        mean = sum(scores) / len(scores)
        lines.append("")
        lines.append(f"Средний score: {mean:.1f}  (n={len(scores)})")
    lines.append("")
    lines.append("Тюнинг: docs/TUNING.md · verdict_extra.json / org_profile рядом с EXE.")

    report.level_counts = dict(counts)
    report.by_segment = {k: dict(v) for k, v in by_seg.items()}
    report.mean_score = mean
    report.hints = hints
    report.lines = lines
    return report
