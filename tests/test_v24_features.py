"""v2.4 features: diff, schema_version, mitigations config."""

from __future__ import annotations

from pathlib import Path

from reliquary.core.diff import diff_results
from reliquary.core.models import SCHEMA_VERSION
from reliquary.core.pipeline import analyze_file
from reliquary.core.verdict import load_verdict_config

CORPUS = Path(__file__).resolve().parents[1] / "samples" / "corpus"


def test_schema_version_constant() -> None:
    assert SCHEMA_VERSION >= 1
    result = analyze_file(CORPUS / "benign_hr_notice.eml")
    assert result.to_dict()["schema_version"] == SCHEMA_VERSION


def test_diff_campaign_peers() -> None:
    a = analyze_file(CORPUS / "campaign_a1.eml")
    b = analyze_file(CORPUS / "campaign_a2.eml")
    delta = diff_results(a, b)
    assert delta.score_delta is not None
    text = delta.to_text()
    assert "Diff" in text
    assert "campaign_a1" in text or "Shared" in text or "Only" in text


def test_mitigation_weights_in_config() -> None:
    cfg = load_verdict_config()
    assert cfg.weight_dmarc_pass_aligned < 0
    assert cfg.weight_internal_relay < 0
    assert cfg.cap_mitigation > 0
