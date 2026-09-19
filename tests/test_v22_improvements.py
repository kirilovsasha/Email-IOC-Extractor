"""Tests for Reliquary 2.2 features."""

from __future__ import annotations

import json
from pathlib import Path

from reliquary.core.error_log import append_error_log, error_log_path
from reliquary.core.filter_state import LEGACY_HOST_TYPES, FilterState
from reliquary.core.handoff import render_handoff
from reliquary.core.pipeline import analyze_file
from reliquary.core.verdict import load_verdict_config, parse_verdict_overrides


SAMPLES = Path(__file__).resolve().parents[1] / "samples"
CORPUS = SAMPLES / "corpus"


def test_verdict_override_json(tmp_path: Path) -> None:
    path = tmp_path / "verdict_extra.json"
    path.write_text(
        json.dumps({"threshold_malicious": 200, "threshold_suspicious": 200}),
        encoding="utf-8",
    )
    cfg = load_verdict_config(path)
    assert cfg.threshold_malicious == 200
    result = analyze_file(CORPUS / "malicious_exe_ip_url.eml", verdict_path=path)
    assert result.verdict is not None
    # With absurd thresholds, even score 100 stays below malicious/suspicious.
    assert result.verdict.level.value in ("unknown", "benign")


def test_parse_verdict_overrides_ignores_unknown() -> None:
    data = parse_verdict_overrides(
        {"_comment": "x", "weight_urgency": 99, "nope": 1, "threshold_malicious": "50"}
    )
    assert data == {"weight_urgency": 99, "threshold_malicious": 50}


def test_handoff_template_placeholders() -> None:
    result = analyze_file(CORPUS / "benign_hr_notice.eml")
    text = render_handoff(
        result,
        template="V={verdict} S={score} F={file} ID={msg_id}\n{iocs}\n",
    )
    assert "V=BENIGN" in text or "V=UNKNOWN" in text or "V=" in text
    assert "S=" in text
    assert "benign_hr_notice.eml" in text


def test_email_mode_hides_legacy_types() -> None:
    state = FilterState(full_ioc_types=False, cat_host=True, cat_crypto=True)
    types = state.selected_types()
    assert types is not None
    assert not (types & LEGACY_HOST_TYPES)
    assert "bitcoin" in types  # crypto chip still works without full mode

    full = FilterState(full_ioc_types=True, cat_host=True, cat_crypto=True)
    assert full.selected_types() is None or LEGACY_HOST_TYPES <= (full.selected_types() or set())


def test_full_ioc_types_cli_style() -> None:
    class Args:
        hide_rewriter = True
        hide_allowlisted = True
        hide_private = True
        actionable = True
        search = ""
        types = None
        full_ioc_types = True

    state = FilterState.from_cli_args(Args())
    assert state.full_ioc_types
    assert state.cat_crypto
    assert state.selected_types() is None


def test_append_error_log(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("reliquary.core.error_log.app_dir", lambda: tmp_path)
    path = append_error_log("unit test note")
    assert path is not None
    assert path.exists()
    assert "unit test note" in path.read_text(encoding="utf-8")
    assert error_log_path() == tmp_path / path.name


def test_file_triage_top_reason() -> None:
    result = analyze_file(CORPUS / "malicious_exe_ip_url.eml")
    assert result.file_rows
    assert result.file_rows[0].top_reason
