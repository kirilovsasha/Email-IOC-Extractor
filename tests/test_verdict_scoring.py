"""Verdict scoring, overrides, mitigations, breakdown."""

from __future__ import annotations

import email
import email.policy
import json
from pathlib import Path

from reliquary.core.header_analyzer import analyze_headers, build_mail_identity
from reliquary.core.pipeline import analyze_file
from reliquary.core.verdict import (
    VerdictConfig,
    load_verdict_config,
    parse_verdict_overrides,
    render_verdict,
)

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
    assert result.verdict.level.value in ("unknown", "benign")


def test_parse_verdict_overrides_ignores_unknown() -> None:
    data = parse_verdict_overrides(
        {"_comment": "x", "weight_urgency": 99, "nope": 1, "threshold_malicious": "50"}
    )
    assert data == {"weight_urgency": 99, "threshold_malicious": 50}


def test_header_spf_fail_and_verdict_urgency():
    raw = (
        b"From: ceo@evil.example\r\n"
        b"To: victim@corp.test\r\n"
        b"Subject: URGENT: verify your account immediately\r\n"
        b"Message-ID: <abc@evil.example>\r\n"
        b"Authentication-Results: mx; spf=fail smtp.mailfrom=evil.example;"
        b" dkim=fail; dmarc=fail\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Click https://185.199.108.153/login now\r\n"
    )
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    findings = analyze_headers(msg)
    assert any(f.severity.value in ("high", "critical", "medium") for f in findings)
    mid = build_mail_identity(msg)
    assert mid.spf == "fail"

    result = analyze_file(SAMPLES / "phishing_sample.eml")
    assert result.verdict is not None
    cfg = VerdictConfig(threshold_malicious=1, weight_urgency=100)
    v = render_verdict(result, cfg)
    assert v is not None
    assert v.score >= 0


def test_verdict_has_breakdown() -> None:
    result = analyze_file(CORPUS / "malicious_exe_ip_url.eml")
    assert result.verdict is not None
    assert result.verdict.breakdown
    assert sum(b.points for b in result.verdict.breakdown) >= result.verdict.score - 5


def test_score_caps_in_config() -> None:
    cfg = load_verdict_config()
    assert cfg.cap_headers <= 50
    assert cfg.cap_attachments <= 50
    assert cfg.cap_mitigation >= 10


def test_mitigation_on_benign_pass_auth() -> None:
    result = analyze_file(CORPUS / "benign_newsletter.eml")
    assert result.verdict is not None
    cats = {b.category for b in result.verdict.breakdown}
    assert "mitigation" in cats or result.verdict.score == 0


def test_no_mitigation_on_auth_fail() -> None:
    result = analyze_file(CORPUS / "malicious_exe_ip_url.eml")
    assert result.verdict is not None
    assert not any(
        b.category == "mitigation" and b.points < 0 for b in result.verdict.breakdown
    )


def test_file_triage_top_reason() -> None:
    result = analyze_file(CORPUS / "malicious_exe_ip_url.eml")
    assert result.file_rows
    assert result.file_rows[0].top_reason
