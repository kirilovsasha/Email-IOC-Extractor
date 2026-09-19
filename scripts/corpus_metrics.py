"""Compare samples/corpus/*.eml verdicts against expected.json."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from reliquary.core.pipeline import analyze_file

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "samples" / "corpus"
EXPECTED_PATH = CORPUS / "expected.json"


def main() -> int:
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
            print(f"FAIL  {name}: no verdict errors={result.errors}")
            continue

        want_level = spec["level"]
        smin = int(spec["score_min"])
        smax = int(spec["score_max"])
        mid = (smin + smax) / 2.0
        drift = v.score - mid
        drift_sum += abs(drift)
        drift_n += 1

        level_ok = v.level.value == want_level
        score_ok = smin <= v.score <= smax
        if level_ok:
            correct_level += 1
        else:
            mismatches.append(
                f"{name}: level want={want_level} got={v.level.value} score={v.score}"
            )

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
    if mismatches:
        print("\nMismatches:")
        for m in mismatches:
            print(f"  - {m}")
        return 1
    print("\nAll levels and score ranges matched.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
