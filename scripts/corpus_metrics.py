"""Compare samples/corpus/*.eml verdicts against expected.json.

Also supports offline calibration on a local inbox folder of .eml/.msg files::

    python scripts/corpus_metrics.py --inbox path/to/emls
"""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from pathlib import Path

from reliquary.core.pipeline import analyze_file

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "samples" / "corpus"
EXPECTED_PATH = CORPUS / "expected.json"


def _segment_for(result) -> str:
    """Грубая сегментация для калибровки FP/FN без БД."""
    signals = set(result.content_signals or [])
    if "bec_payment" in signals:
        return "bec"
    if any(u.changed for u in (result.url_rewrites or [])):
        rewriters = {u.rewriter for u in result.url_rewrites if u.changed}
        if "microsoft_safelinks" in rewriters:
            return "safelinks"
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
        )
    ):
        return "attachment"
    if "credential_harvest" in signals or "href_mismatch" in signals:
        return "phishing_content"
    mid = result.mail_identity
    if mid and ((mid.auto_submitted or "").lower() not in ("", "no")):
        return "auto_reply"
    subj = (result.subject or "").lower()
    if "meeting" in subj or "приглашен" in subj or "calendar" in subj:
        return "calendar"
    reasons = (result.verdict.reasons if result.verdict else []) or []
    if any("lookalike" in (r or "").lower() for r in reasons):
        return "lookalike"
    return "other"


def _score_inbox(folder: Path) -> int:
    files = sorted(
        p for p in folder.rglob("*") if p.suffix.lower() in {".eml", ".msg"} and p.is_file()
    )
    if not files:
        print(f"No .eml/.msg under {folder}")
        return 1
    counts: dict[str, int] = {}
    scores: list[int] = []
    by_seg: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    print(f"Inbox calibration ({len(files)} files) under {folder}\n")
    for path in files:
        result = analyze_file(path)
        v = result.verdict
        if v is None:
            print(f"SKIP  {path.name}: no verdict")
            continue
        seg = _segment_for(result)
        counts[v.level.value] = counts.get(v.level.value, 0) + 1
        by_seg[seg][v.level.value] += 1
        scores.append(v.score)
        print(f"  [{seg}] {path.name}: {v.level.value} score={v.score}")
    print()
    print("Level distribution:")
    for level in ("benign", "unknown", "suspicious", "malicious"):
        print(f"  {level}: {counts.get(level, 0)}")
    print("\nBy segment (level counts):")
    for seg in sorted(by_seg):
        parts = ", ".join(f"{lvl}={n}" for lvl, n in sorted(by_seg[seg].items()))
        print(f"  {seg}: {parts}")
    marketing_fp = by_seg.get("safelinks", {}).get("suspicious", 0) + by_seg.get(
        "safelinks", {}
    ).get("malicious", 0)
    bec_fn = by_seg.get("bec", {}).get("benign", 0) + by_seg.get("bec", {}).get("unknown", 0)
    if marketing_fp:
        print(
            f"\nHint FP: safelinks→suspicious/malicious = {marketing_fp} "
            f"(см. weight_url_rewrite)"
        )
    if bec_fn:
        print(f"Hint FN: bec→benign/unknown = {bec_fn} (см. weight_bec_payment)")
    if scores:
        avg = sum(scores) / len(scores)
        print(f"\nMean score: {avg:.1f}  (n={len(scores)})")
    print("\nUse docs/TUNING.md to adjust verdict_extra.json / org profile.")
    print("Configs live next to the EXE only — no database.")
    return 0


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
