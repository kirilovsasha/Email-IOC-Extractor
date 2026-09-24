"""Compare two analysis results (campaign / peer email diff)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from reliquary.core.models import AnalysisResult, Ioc


@dataclass
class ResultDiff:
    """Delta between two mail triage results."""

    left_path: str
    right_path: str
    score_left: int | None = None
    score_right: int | None = None
    level_left: str = ""
    level_right: str = ""
    score_delta: int | None = None
    iocs_only_left: list[str] = field(default_factory=list)
    iocs_only_right: list[str] = field(default_factory=list)
    iocs_shared: list[str] = field(default_factory=list)
    reasons_only_left: list[str] = field(default_factory=list)
    reasons_only_right: list[str] = field(default_factory=list)
    subject_left: str = ""
    subject_right: str = ""
    sender_left: str = ""
    sender_right: str = ""

    def to_text(self) -> str:
        lines = [
            f"▸ Diff  {Path(self.left_path).name}  ↔  {Path(self.right_path).name}",
            f"  Verdict  {(self.level_left or '—').upper()}"
            f" {self.score_left if self.score_left is not None else '—'}"
            f"  →  {(self.level_right or '—').upper()}"
            f" {self.score_right if self.score_right is not None else '—'}"
            + (
                f"  (Δ {self.score_delta:+d})"
                if self.score_delta is not None
                else ""
            ),
        ]
        if self.subject_left or self.subject_right:
            lines.append(f"  Subject L  {self.subject_left or '—'}")
            lines.append(f"  Subject R  {self.subject_right or '—'}")
        if self.sender_left or self.sender_right:
            lines.append(f"  From L     {self.sender_left or '—'}")
            lines.append(f"  From R     {self.sender_right or '—'}")
        if self.iocs_shared:
            lines.append(f"  Shared IOC ({len(self.iocs_shared)})")
            for v in self.iocs_shared[:12]:
                lines.append(f"    = {v}")
        if self.iocs_only_left:
            lines.append(f"  Only left ({len(self.iocs_only_left)})")
            for v in self.iocs_only_left[:12]:
                lines.append(f"    − {v}")
        if self.iocs_only_right:
            lines.append(f"  Only right ({len(self.iocs_only_right)})")
            for v in self.iocs_only_right[:12]:
                lines.append(f"    + {v}")
        if self.reasons_only_left:
            lines.append("  Reasons only left")
            for r in self.reasons_only_left[:6]:
                lines.append(f"    − {r}")
        if self.reasons_only_right:
            lines.append("  Reasons only right")
            for r in self.reasons_only_right[:6]:
                lines.append(f"    + {r}")
        return "\n".join(lines) + "\n"


def _ioc_key(ioc: Ioc) -> str:
    return f"{ioc.ioc_type.value}|{ioc.value.lower()}"


def _ioc_label(ioc: Ioc) -> str:
    return f"{ioc.ioc_type.value}: {ioc.value}"


def diff_results(left: AnalysisResult, right: AnalysisResult) -> ResultDiff:
    """Compare IOC sets, verdict scores, and reason lists."""
    left_map = {_ioc_key(i): i for i in left.iocs}
    right_map = {_ioc_key(i): i for i in right.iocs}
    shared_keys = sorted(set(left_map) & set(right_map))
    only_l = sorted(set(left_map) - set(right_map))
    only_r = sorted(set(right_map) - set(left_map))

    reasons_l = set(left.verdict.reasons if left.verdict else [])
    reasons_r = set(right.verdict.reasons if right.verdict else [])

    score_l = left.verdict.score if left.verdict else None
    score_r = right.verdict.score if right.verdict else None
    delta = None
    if score_l is not None and score_r is not None:
        delta = score_r - score_l

    return ResultDiff(
        left_path=left.source_path,
        right_path=right.source_path,
        score_left=score_l,
        score_right=score_r,
        level_left=left.verdict.level.value if left.verdict else "",
        level_right=right.verdict.level.value if right.verdict else "",
        score_delta=delta,
        iocs_only_left=[_ioc_label(left_map[k]) for k in only_l],
        iocs_only_right=[_ioc_label(right_map[k]) for k in only_r],
        iocs_shared=[_ioc_label(left_map[k]) for k in shared_keys],
        reasons_only_left=sorted(reasons_l - reasons_r),
        reasons_only_right=sorted(reasons_r - reasons_l),
        subject_left=left.subject or "",
        subject_right=right.subject or "",
        sender_left=left.sender or "",
        sender_right=right.sender or "",
    )


def find_batch_peer(
    batch_results: list[AnalysisResult],
    *,
    filename: str,
) -> AnalysisResult | None:
    """Locate a batch member by full path, or by a unique basename."""
    raw = (filename or "").replace("\\", "/")
    if not raw:
        return None
    for result in batch_results:
        src = (result.source_path or "").replace("\\", "/")
        if src == raw or src.lower() == raw.lower():
            return result
    needle = Path(raw).name.lower()
    hits = [r for r in batch_results if Path(r.source_path).name.lower() == needle]
    if len(hits) == 1:
        return hits[0]
    return None
