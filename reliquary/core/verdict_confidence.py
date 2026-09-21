"""Verdict confidence — how settled the score is relative to band edges."""

from __future__ import annotations

from reliquary.core.models import ScoreContribution, Verdict, VerdictLevel
from reliquary.core.verdict_config import VerdictConfig


def compute_confidence(
    score: int,
    level: VerdictLevel,
    breakdown: list[ScoreContribution],
    cfg: VerdictConfig,
) -> tuple[str, str]:
    """Return (confidence, note).

    high — far from nearest threshold and clear risk/mitigation dominance
    medium — default
    low — within ~5 points of a band edge or risk≈mitigation tug-of-war
    """
    risk = sum(b.points for b in breakdown if b.points > 0)
    mitigation = sum(-b.points for b in breakdown if b.points < 0)

    edges = (
        cfg.threshold_unknown,
        cfg.threshold_suspicious,
        cfg.threshold_malicious,
    )
    dist = min(abs(score - e) for e in edges)

    top_risk = sorted(
        (b for b in breakdown if b.points > 0),
        key=lambda b: b.points,
        reverse=True,
    )[:3]
    top_mit = sorted(
        (b for b in breakdown if b.points < 0),
        key=lambda b: b.points,
    )[:2]

    why_parts: list[str] = []
    if top_risk:
        why_parts.append(
            "риск: " + "; ".join(f"{b.reason} (+{b.points})" for b in top_risk)
        )
    if top_mit:
        why_parts.append(
            "смягчение: " + "; ".join(f"{b.reason} ({b.points})" for b in top_mit)
        )
    if level != VerdictLevel.BENIGN and not top_risk:
        why_parts.append("нет сильных risk-сигналов при ненулевом score")
    if level == VerdictLevel.BENIGN and risk:
        why_parts.append(f"risk={risk} перекрыт mitigations={mitigation}")

    note = " | ".join(why_parts) if why_parts else "эвристики без явного доминирования"

    tug = risk > 0 and mitigation > 0 and abs(risk - mitigation) <= 8
    if dist <= 5 or tug:
        return "low", note
    if dist >= 12 and (risk >= 20 or level in (VerdictLevel.BENIGN, VerdictLevel.MALICIOUS)):
        return "high", note
    return "medium", note


def attach_confidence(verdict: Verdict, cfg: VerdictConfig) -> Verdict:
    conf, note = compute_confidence(verdict.score, verdict.level, verdict.breakdown, cfg)
    verdict.confidence = conf
    verdict.confidence_note = note
    return verdict
