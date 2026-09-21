"""Compare verdict scores under two weight configs (offline A/B)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from reliquary.core.formats import collect_supported
from reliquary.core.pipeline import analyze_file
from reliquary.core.verdict import VerdictConfig, load_verdict_config


@dataclass
class WeightCompareRow:
    path: str
    level_a: str
    score_a: int
    level_b: str
    score_b: int

    @property
    def changed(self) -> bool:
        return self.level_a != self.level_b or self.score_a != self.score_b


@dataclass
class WeightCompareReport:
    folder: str
    verdict_a: str
    verdict_b: str
    rows: list[WeightCompareRow] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def changed_count(self) -> int:
        return sum(1 for r in self.rows if r.changed)

    def to_text(self) -> str:
        lines = [
            f"Сравнение весов: {self.folder}",
            f"A: {self.verdict_a or '(defaults)'}",
            f"B: {self.verdict_b or '(defaults)'}",
            f"Файлов: {len(self.rows)}, изменилось: {self.changed_count}",
            "",
        ]
        for r in self.rows:
            mark = "*" if r.changed else " "
            name = Path(r.path).name
            lines.append(
                f"{mark} {name}: {r.level_a}/{r.score_a} → {r.level_b}/{r.score_b}"
            )
        if self.errors:
            lines.append("")
            lines.append("Ошибки:")
            for e in self.errors[:20]:
                lines.append(f"  ! {e}")
        return "\n".join(lines) + "\n"


def compare_verdict_weights(
    folder: str | Path,
    *,
    verdict_a: str | Path | None = None,
    verdict_b: str | Path | None = None,
    limit: int = 200,
) -> WeightCompareReport:
    """Re-score the same inbox under two ``verdict_extra`` paths."""
    root = Path(folder)
    report = WeightCompareReport(
        folder=str(root),
        verdict_a=str(verdict_a or ""),
        verdict_b=str(verdict_b or ""),
    )
    cfg_a = load_verdict_config(verdict_a)
    cfg_b = load_verdict_config(verdict_b)
    paths = collect_supported(root, recursive=True)[: max(1, limit)]
    for p in paths:
        try:
            ra = analyze_file(p, verdict_cfg=cfg_a)
            rb = analyze_file(p, verdict_cfg=cfg_b)
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"{Path(p).name}: {exc}")
            continue
        va = ra.verdict
        vb = rb.verdict
        report.rows.append(
            WeightCompareRow(
                path=p,
                level_a=va.level.value if va else "",
                score_a=int(va.score) if va else -1,
                level_b=vb.level.value if vb else "",
                score_b=int(vb.score) if vb else -1,
            )
        )
    return report


def rescore_with_config(path: str | Path, cfg: VerdictConfig):
    """Single-file helper for tests."""
    return analyze_file(path, verdict_cfg=cfg)
