"""Compare samples/corpus/*.eml verdicts against expected.json.

Also supports offline calibration on a local inbox folder of .eml/.msg files::

    python scripts/corpus_metrics.py --inbox path/to/emls
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from reliquary.core.calibration import calibrate_inbox
from reliquary.core.pipeline import analyze_file

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "samples" / "corpus"
EXPECTED_PATH = CORPUS / "expected.json"


def _score_inbox(folder: Path) -> int:
    report = calibrate_inbox(folder)
    print(report.to_text())
    return 0 if report.scored else 1


def _score_corpus() -> int:
    expected = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    total = len(expected)
    correct_level = 0
    mismatches: list[str] = []
    drift_sum = 0.0
    drift_n = 0

    print(f"Corpus metrics ({total} expected entries)\n")
    for name in sorted(expected):
        spec = expected[name]
        path = CORPUS / name
        if not path.is_file():
            mismatches.append(f"{name}: MISSING FILE")
            print(f"FAIL  {name}: file missing")
            continue

        result = analyze_file(path)
        v = result.verdict
        if v is None:
            mismatches.append(f"{name}: no verdict")
            print(f"FAIL  {name}: no verdict")
            continue

        want_level = spec["level"]
        smin = int(spec.get("score_min", 0))
        smax = int(spec.get("score_max", 100))
        level_ok = v.level.value == want_level
        score_ok = smin <= v.score <= smax
        if level_ok:
            correct_level += 1
        else:
            mismatches.append(
                f"{name}: level {v.level.value} != {want_level} (score={v.score})"
            )
        mid = (smin + smax) / 2.0
        drift = abs(v.score - mid)
        drift_sum += drift
        drift_n += 1
        status = "OK" if level_ok and score_ok else "FAIL"
        print(
            f"{status:4} {name}: level={v.level.value} "
            f"(want {want_level}) score={v.score} [{smin}-{smax}] "
            f"drift_vs_mid={drift:+.1f}"
        )
        if not score_ok and level_ok:
            mismatches.append(
                f"{name}: score {v.score} outside [{smin},{smax}] (level ok)"
            )

    avg_drift = (drift_sum / drift_n) if drift_n else 0.0
    print()
    print(f"Level accuracy: {correct_level}/{total}")
    print(f"Mean |score - range mid|: {avg_drift:.2f}")
    max_drift = float(os.environ.get("CORPUS_MAX_DRIFT", "25"))
    if avg_drift > max_drift:
        print(f"\nDRIFT GATE FAIL: mean abs drift {avg_drift:.2f} > {max_drift}")
        return 1
    if mismatches:
        print("\nMismatches:")
        for m in mismatches:
            print(f"  - {m}")
        return 1
    print("\nAll levels and score ranges matched.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--inbox",
        type=Path,
        help="Offline folder of .eml/.msg for score distribution (no expected.json)",
    )
    args = parser.parse_args()
    if args.inbox:
        return _score_inbox(args.inbox)
    return _score_corpus()


if __name__ == "__main__":
    raise SystemExit(main())
