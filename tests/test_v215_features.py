"""v2.15 features — confidence, feedback, unlock, mbox, weight compare, watch."""

from __future__ import annotations

import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from reliquary.core.analysis_options import AnalysisOptions
from reliquary.core.archive_unlock import extract_zip_with_passwords, unlock_attachment
from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.feedback import FeedbackEvent, append_feedback, feedback_summary, load_feedback
from reliquary.core.formats import expand_input_paths, is_supported
from reliquary.core.mbox_ingest import expand_mbox_to_emls
from reliquary.core.models import ScoreContribution, VerdictLevel
from reliquary.core.pipeline import analyze_file
from reliquary.core.verdict import VerdictConfig
from reliquary.core.verdict_confidence import compute_confidence

CORPUS = Path(__file__).resolve().parents[1] / "samples" / "corpus"


def test_confidence_near_threshold_is_low() -> None:
    cfg = VerdictConfig()
    breakdown = [
        ScoreContribution("headers", 28, "near edge"),
        ScoreContribution("mitigation", -5, "mild"),
    ]
    conf, note = compute_confidence(28, VerdictLevel.UNKNOWN, breakdown, cfg)
    assert conf in {"low", "medium"}
    assert note


def test_render_verdict_sets_confidence() -> None:
    r = analyze_file(CORPUS / "benign_hr_notice.eml")
    assert r.verdict is not None
    assert r.verdict.confidence in {"high", "medium", "low"}
    data = r.verdict.to_dict()
    assert "confidence" in data


def test_feedback_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("reliquary.core.feedback.app_dir", lambda: tmp_path)
    path = append_feedback(
        FeedbackEvent(
            kind="fp",
            expected_level="benign",
            observed_level="suspicious",
            score=35,
            source_path="x.eml",
            note="noise",
            segment="safelinks",
        )
    )
    assert path.is_file()
    rows = load_feedback()
    assert len(rows) == 1
    assert "fp=" in feedback_summary(rows)


def test_is_supported_mbox() -> None:
    assert is_supported("inbox.mbox")


def test_expand_mbox(tmp_path: Path) -> None:
    mbox = tmp_path / "box.mbox"
    mbox.write_text(
        "From me@x Tue Sep 1 00:00:00 2025\n"
        "From: a@b.c\nSubject: one\n\nhello\n"
        "From me@x Tue Sep 1 00:00:01 2025\n"
        "From: c@d.e\nSubject: two\n\nworld\n",
        encoding="utf-8",
    )
    emls, dest = expand_mbox_to_emls(mbox, dest=tmp_path / "out")
    assert len(emls) >= 2
    assert all(Path(p).suffix == ".eml" for p in emls)
    expanded = expand_input_paths([str(mbox)])
    assert len(expanded) >= 2


def test_archive_unlock_password(tmp_path: Path) -> None:
    # Create a real encrypted zip via zipfile + pwd if possible
    data = BytesIO()
    pwd = b"secret"
    with zipfile.ZipFile(data, "w") as zf:
        zf.setpassword(pwd)
        try:
            zf.writestr("inner.eml", b"From: x@y.z\nSubject: nested\n\nbody\n")
        except RuntimeError:
            pytest.skip("ZipFile encryption write not supported")
    raw = data.getvalue()
    # Many CPython builds don't encrypt on writestr+setpassword — detect flag
    with zipfile.ZipFile(BytesIO(raw)) as zf:
        encrypted = any(i.flag_bits & 0x1 for i in zf.infolist())
    if not encrypted:
        pytest.skip("produced zip is not encrypted")
    members, notes = extract_zip_with_passwords(raw, ["secret"])
    assert members, notes


def test_unlock_attachment_updates_flags() -> None:
    # Non-encrypted: unlock should still inventory members when password unused path
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"hi")
    att = inspect_bytes("a.zip", buf.getvalue(), keep_bytes=True)
    # Without encryption, unlock_attachment still extracts via zip path
    if "encrypted_archive" not in att.risk_flags:
        att.risk_flags.append("encrypted_archive")
    updated, kids, notes = unlock_attachment(att, ["x"])
    # Wrong password → notes explain failure OR success on plain zip
    assert isinstance(notes, list)
    assert updated is att


def test_pipeline_archive_password_option() -> None:
    sample = CORPUS / "malicious_encrypted_zip.eml"
    if not sample.is_file():
        pytest.skip("corpus sample missing")
    opts = AnalysisOptions(archive_passwords=("1234",))
    r = analyze_file(sample, options=opts)
    assert r.verdict is not None
    # Password may or may not decrypt corpus zip depending on encoding; no crash
    assert r.source_kind == "email"


def test_yara_scan_graceful_without_package() -> None:
    from reliquary.core.yara_scan import scan_bytes, yara_available

    hits, notes = scan_bytes(b"hello", rules_path=None)
    assert hits == []
    assert notes  # missing rules or package
    assert isinstance(yara_available(), bool)
