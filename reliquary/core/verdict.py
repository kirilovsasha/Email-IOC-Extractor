"""Mail-triage heuristics (fully offline) — primary product output.

Applied to email artifacts (.eml / .msg). Weights are built-in constants
with optional local JSON override (``verdict_extra.json`` / ``--verdict``).

Score uses per-category caps so stacking identical flags does not inflate
malicious on noisy mail.
"""

from __future__ import annotations

from pathlib import Path

from reliquary.core.models import (
    AnalysisResult,
    ScoreContribution,
    Verdict,
    VerdictLevel,
)
from reliquary.core.verdict_confidence import attach_confidence
from reliquary.core.verdict_config import (
    URGENCY_RE,
    VerdictConfig,
    default_extra_verdict_path,
    default_verdict_config,
    load_verdict_config,
    load_verdict_overrides,
    load_verdict_overrides_report,
    parse_verdict_overrides,
    probe_verdict_extra_warnings,
    resolve_verdict_path,
    validate_verdict_extra,
)
from reliquary.core.verdict_scoring import (
    _score_attachments,
    _score_compounds,
    _score_content,
    _score_headers,
    _score_lookalike,
    _score_mitigations,
    _score_urls,
)

__all__ = [
    "URGENCY_RE",
    "VerdictConfig",
    "default_extra_verdict_path",
    "default_verdict_config",
    "load_verdict_config",
    "load_verdict_overrides",
    "load_verdict_overrides_report",
    "parse_verdict_overrides",
    "probe_verdict_extra_warnings",
    "resolve_verdict_path",
    "validate_verdict_extra",
    "render_verdict",
]


def render_verdict(
    result: AnalysisResult,
    cfg: VerdictConfig | None = None,
    *,
    brands_path: str | Path | None = None,
    org_domains_path: str | Path | None = None,
    allowlist_domains: set[str] | None = None,
) -> Verdict | None:
    """Mail triage score — primary output for email artifacts."""
    if result.source_kind != "email":
        return None

    cfg = cfg or load_verdict_config()
    breakdown: list[ScoreContribution] = []
    score = 0

    for scorer in (
        lambda r, c: _score_headers(r, c),
        lambda r, c: _score_attachments(r, c),
        lambda r, c: _score_urls(r, c),
        lambda r, c: _score_content(r, c),
        lambda r, c: _score_lookalike(
            r, c, brands_path=brands_path, org_domains_path=org_domains_path
        ),
    ):
        part, parts = scorer(result, cfg)
        score += part
        breakdown.extend(parts)

    part, parts = _score_compounds(result, cfg, prior_breakdown=breakdown)
    score += part
    breakdown.extend(parts)

    part, parts = _score_mitigations(result, cfg, allowlist_domains=allowlist_domains)
    score += part
    breakdown.extend(parts)

    reasons = [b.reason for b in breakdown if b.points != 0]
    seen: set[str] = set()
    uniq_reasons: list[str] = []
    for r in reasons:
        # Strip [cap] marker for display reasons dedupe key
        key = r.replace(" [cap]", "")
        if key not in seen:
            seen.add(key)
            uniq_reasons.append(key)

    score = min(100, max(0, score))
    if score >= cfg.threshold_malicious:
        level = VerdictLevel.MALICIOUS
        summary = "Высокая вероятность вредоносной активности / фишинга"
    elif score >= cfg.threshold_suspicious:
        level = VerdictLevel.SUSPICIOUS
        summary = "Подозрительные признаки — требуется углублённый разбор"
    elif score >= cfg.threshold_unknown:
        level = VerdictLevel.UNKNOWN
        summary = "Слабые сигналы — вердикт неоднозначен"
    else:
        level = VerdictLevel.BENIGN
        summary = "Существенных индикаторов компрометации не выявлено"

    if not uniq_reasons:
        uniq_reasons.append("Эвристики не сработали на явные red flags")

    verdict = Verdict(
        level=level,
        score=score,
        summary=summary,
        reasons=uniq_reasons[:12],
        breakdown=breakdown,
    )
    return attach_confidence(verdict, cfg)
