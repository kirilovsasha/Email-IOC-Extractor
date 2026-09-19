"""Parallel folder/file analysis with progress callbacks (no Tk)."""

from __future__ import annotations

import concurrent.futures
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from reliquary.core.analysis_options import AnalysisOptions
from reliquary.core.models import AnalysisResult
from reliquary.core.pipeline import analyze_file, merge_results

ProgressCb = Callable[[int, int, str, float | None], None]


@dataclass
class BatchProgress:
    done: int = 0
    total: int = 0
    current: str = ""
    eta_seconds: float | None = None
    failed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class BatchOutcome:
    result: AnalysisResult | None
    batch_results: list[AnalysisResult]
    failed: list[str]
    errors: list[str]
    cancelled: bool = False


def default_max_workers(configured: int | None = None) -> int:
    if configured is not None and configured > 0:
        return min(int(configured), 16)
    return min(4, max(1, os.cpu_count() or 1))


def format_eta(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return ""
    if seconds < 60:
        return f"~{int(seconds)}с"
    mins = int(seconds // 60)
    secs = int(seconds % 60)
    return f"~{mins}м {secs:02d}с"


def run_batch(
    paths: list[str],
    *,
    max_workers: int | None = None,
    skip_broken: bool = True,
    is_cancelled: Callable[[], bool] | None = None,
    on_progress: ProgressCb | None = None,
    allowlist_path: str | Path | None = None,
    verdict_path: str | Path | None = None,
    options: AnalysisOptions | None = None,
) -> BatchOutcome:
    """Analyze many files; merge into one result. Soft parse errors stay in result.errors."""
    opts = options or AnalysisOptions()
    if allowlist_path is not None:
        opts.allowlist_path = allowlist_path
    if verdict_path is not None:
        opts.verdict_path = verdict_path
    if max_workers is not None and max_workers > 0:
        opts.max_workers = max_workers
    opts.skip_broken = skip_broken

    total = len(paths)
    if total == 0:
        return BatchOutcome(None, [], [], ["Нет файлов для разбора"])

    cancel = is_cancelled or (lambda: False)
    workers = default_max_workers(opts.max_workers or max_workers)
    slots: list[AnalysisResult | None] = [None] * total
    failed: list[str] = []
    hard_errors: list[str] = []
    done = 0
    t0 = time.monotonic()

    def _work(idx: int, path: str) -> tuple[int, AnalysisResult | None, str | None]:
        if cancel():
            return idx, None, "cancelled"
        try:
            return (
                idx,
                analyze_file(path, options=opts),
                None,
            )
        except Exception as exc:  # noqa: BLE001
            return idx, None, f"{path}: {exc}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_work, i, p) for i, p in enumerate(paths)]
        for fut in concurrent.futures.as_completed(futures):
            if cancel():
                for pending in futures:
                    pending.cancel()
                break
            idx, result, err = fut.result()
            done += 1
            path = paths[idx]
            elapsed = time.monotonic() - t0
            eta: float | None = None
            if done > 0 and done < total:
                eta = (elapsed / done) * (total - done)
            if on_progress:
                on_progress(done, total, Path(path).name, eta)

            if err == "cancelled":
                continue
            if err:
                hard_errors.append(err)
                failed.append(path)
                continue
            if result is None:
                continue
            if skip_broken and result.errors and not result.iocs and result.source_kind == "unknown":
                hard_errors.append(
                    f"{path}: пустой/непрочитанный результат — "
                    + "; ".join(result.errors[:3])
                )
                failed.append(path)
                continue
            slots[idx] = result

    cancelled = cancel()
    if cancelled:
        hard_errors.append("Пакетная обработка отменена")

    results = [r for r in slots if r is not None]
    if not results:
        return BatchOutcome(
            None,
            [],
            failed,
            hard_errors or ["Не удалось разобрать ни одного файла"],
            cancelled=cancelled,
        )

    if len(results) == 1:
        merged = results[0]
    else:
        merged = merge_results(
            results,
            label=f"batch:{len(results)}",
            options=opts,
        )

    for err in hard_errors:
        merged.errors.append(err)
    if hard_errors:
        merged.errors.insert(
            0,
            f"Успешно: {len(results)}/{total}, ошибок: {len(hard_errors)}",
        )
    if failed:
        merged.errors.append(
            "Не разобраны: " + "; ".join(Path(p).name for p in failed[:20])
        )

    return BatchOutcome(
        result=merged,
        batch_results=results,
        failed=failed,
        errors=hard_errors,
        cancelled=cancelled,
    )
