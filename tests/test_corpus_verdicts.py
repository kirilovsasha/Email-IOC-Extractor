"""Golden verdict corpus — samples/corpus/*.eml vs expected.json."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reliquary.core.pipeline import analyze_file

CORPUS = Path(__file__).resolve().parents[1] / "samples" / "corpus"
EXPECTED = json.loads((CORPUS / "expected.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("filename", sorted(EXPECTED.keys()))
def test_corpus_verdict(filename: str) -> None:
    path = CORPUS / filename
    assert path.is_file(), f"missing corpus file: {path}"
    spec = EXPECTED[filename]
    result = analyze_file(path)
    assert result.verdict is not None, result.errors
    assert result.verdict.level.value == spec["level"]
    assert spec["score_min"] <= result.verdict.score <= spec["score_max"]
    needles = spec.get("reason_substrings") or []
    blob = " ".join(result.verdict.reasons).lower()
    if needles:
        assert any(n.lower() in blob for n in needles), (
            f"none of {needles} found in reasons: {result.verdict.reasons}"
        )
