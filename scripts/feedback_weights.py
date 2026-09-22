#!/usr/bin/env python3
"""Write suggested verdict weight + threshold overrides from analyst_feedback.ndjson."""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "out",
        nargs="?",
        default="verdict_weights_suggested.json",
        help="Output JSON path (default: verdict_weights_suggested.json)",
    )
    args = parser.parse_args()
    from reliquary.core.feedback import (
        suggest_threshold_overrides,
        suggest_weight_overrides,
        write_weight_suggestions,
    )

    path = write_weight_suggestions(args.out)
    sug = suggest_weight_overrides()
    thr = suggest_threshold_overrides()
    print(f"Wrote {path} ({len(sug)} weight keys, {len(thr)} threshold/cap keys)")
    for k, v in sug.items():
        print(f"  {k}: {v:+d}")
    for k, v in thr.items():
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
