"""Сводка кампании по пакету писем (офлайн)."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from reliquary.core.labels import verdict_label_ru
from reliquary.core.models import AnalysisResult, Ioc
from reliquary.core.pipeline import campaign_key_for


@dataclass
class CampaignSummary:
    """Агрегат по одной или нескольким кампаниям в batch."""

    campaign_key: str
    file_count: int
    paths: list[str] = field(default_factory=list)
    levels: dict[str, int] = field(default_factory=dict)
    max_score: int = 0
    shared_iocs: list[str] = field(default_factory=list)
    top_brands: list[str] = field(default_factory=list)
    subjects: list[str] = field(default_factory=list)
    senders: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_text(self) -> str:
        lines = [
            f"▸ Кампания  {self.campaign_key or '(без ключа)'}",
            f"  Писем: {self.file_count}",
            f"  Макс. score: {self.max_score}",
        ]
        if self.levels:
            parts = ", ".join(
                f"{verdict_label_ru(k)}={v}" for k, v in sorted(self.levels.items())
            )
            lines.append(f"  Уровни: {parts}")
        if self.subjects:
            lines.append("  Темы:")
            for s in self.subjects[:5]:
                lines.append(f"    • {s}")
        if self.senders:
            lines.append("  From: " + "; ".join(self.senders[:5]))
        if self.shared_iocs:
            lines.append(f"  Общие IOC ({len(self.shared_iocs)}):")
            for i in self.shared_iocs[:15]:
                lines.append(f"    = {i}")
        if self.top_brands:
            lines.append("  Lookalike-бренды: " + ", ".join(self.top_brands[:8]))
        return "\n".join(lines) + "\n"


def _ioc_label(ioc: Ioc) -> str:
    return f"{ioc.ioc_type.value}: {ioc.value}"


def summarize_campaigns(results: list[AnalysisResult]) -> list[CampaignSummary]:
    """Сгруппировать batch по campaign_key и посчитать пересечения IOC."""
    groups: dict[str, list[AnalysisResult]] = {}
    for r in results:
        key = campaign_key_for(r) or Path(r.source_path).name
        groups.setdefault(key, []).append(r)

    out: list[CampaignSummary] = []
    for key, members in groups.items():
        level_counts: Counter[str] = Counter()
        max_score = 0
        ioc_sets: list[set[str]] = []
        brand_hits: Counter[str] = Counter()
        subjects: list[str] = []
        senders: list[str] = []
        paths: list[str] = []
        for r in members:
            paths.append(r.source_path)
            if r.subject:
                subjects.append(r.subject)
            if r.sender:
                senders.append(r.sender)
            if r.verdict:
                level_counts[r.verdict.level.value] += 1
                max_score = max(max_score, int(r.verdict.score))
                for reason in r.verdict.reasons:
                    if "lookalike" in reason.lower() or "бренд" in reason.lower():
                        brand_hits[reason[:80]] += 1
            ioc_sets.append({_ioc_label(i) for i in r.iocs})
        shared: set[str] = set.intersection(*ioc_sets) if ioc_sets else set()
        # Also include IOCs appearing in ≥2 mails if intersection empty but n>1
        if not shared and len(ioc_sets) > 1:
            counts: Counter[str] = Counter()
            for s in ioc_sets:
                counts.update(s)
            shared = {k for k, v in counts.items() if v >= 2}
        out.append(
            CampaignSummary(
                campaign_key=key,
                file_count=len(members),
                paths=paths,
                levels=dict(level_counts),
                max_score=max_score,
                shared_iocs=sorted(shared)[:40],
                top_brands=[b for b, _ in brand_hits.most_common(5)],
                subjects=list(dict.fromkeys(subjects))[:8],
                senders=list(dict.fromkeys(senders))[:8],
            )
        )
    out.sort(key=lambda c: (-c.max_score, -c.file_count, c.campaign_key))
    return out


def export_campaign_handoff(
    results: list[AnalysisResult],
    path: str | Path,
) -> Path:
    """Один текстовый блок для ITSM по всему пакету / кампаниям."""
    out = Path(path)
    campaigns = summarize_campaigns(results)
    lines = [
        "=== Пакетный handoff (кампании) ===",
        f"Писем в пакете: {len(results)}",
        f"Кампаний: {len(campaigns)}",
        "",
    ]
    for c in campaigns:
        lines.append(c.to_text().rstrip())
        lines.append("")
    # Per-mail one-liners
    lines.append("=== По файлам ===")
    for r in results:
        lvl = r.verdict.level.value if r.verdict else "—"
        score = r.verdict.score if r.verdict else "—"
        lines.append(
            f"- {Path(r.source_path).name}: {verdict_label_ru(lvl)} ({lvl}) "
            f"score={score}"
        )
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def export_campaign_pack(
    results: list[AnalysisResult],
    path: str | Path,
    *,
    fmt: str = "ndjson",
) -> Path:
    """Offline SIEM pack for a folder of mails: NDJSON (default) or CEF lines.

    One file beside the EXE / analyst share — no DB. Groups by campaign_key.
    """
    import json

    from reliquary.core.exporters import export_cef

    out = Path(path)
    fmt_l = (fmt or "ndjson").strip().lower()
    if fmt_l in ("cef", "siem") or out.suffix.lower() == ".cef":
        # Concatenate per-mail CEF into one pack
        chunks: list[str] = []
        for r in results:
            tmp = out.with_suffix(".tmp_cef")
            export_cef(r, tmp)
            chunks.append(tmp.read_text(encoding="utf-8").rstrip())
            try:
                tmp.unlink()
            except OSError:
                pass
        out.write_text("\n".join(chunks) + "\n", encoding="utf-8")
        return out

    # NDJSON: one object per mail + campaign index header as first line
    campaigns = summarize_campaigns(results)
    lines: list[str] = [
        json.dumps(
            {
                "type": "campaign_pack_meta",
                "schema": "reliquary.campaign_pack.v1",
                "mail_count": len(results),
                "campaigns": [c.to_dict() for c in campaigns],
            },
            ensure_ascii=False,
        )
    ]
    for r in results:
        payload = r.to_dict()
        payload["type"] = "mail"
        payload["campaign_key"] = campaign_key_for(r)
        lines.append(json.dumps(payload, ensure_ascii=False, default=str))
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out
