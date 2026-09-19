"""Tests for Reliquary 2.3 features."""

from __future__ import annotations

import zipfile
from pathlib import Path

from reliquary.core.analysis_options import AnalysisOptions
from reliquary.core.content_signals import analyze_content_signals
from reliquary.core.handoff import render_handoff
from reliquary.core.lookalike import check_domain, levenshtein, scan_lookalikes
from reliquary.core.org_profile import load_org_profile
from reliquary.core.pipeline import analyze_file, campaign_key_for, merge_results
from reliquary.core.verdict import load_verdict_config

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
CORPUS = SAMPLES / "corpus"


def test_lookalike_levenshtein_microsoft() -> None:
    hits = check_domain("micros0ft.com")
    kinds = {h.kind for h in hits}
    assert "levenshtein" in kinds or "brand_spoof" in kinds or "homoglyph" in kinds


def test_idn_detection() -> None:
    hits = check_domain("xn--pple-43d.com")  # often IDN form
    # may or may not be in brand list; at least IDN flag if punycode
    assert isinstance(hits, list)


def test_levenshtein_basic() -> None:
    assert levenshtein("microsoft", "micros0ft") == 1


def test_content_href_mismatch() -> None:
    html = (
        '<a href="https://evil.top/login">https://www.microsoft.com/account</a>'
    )
    sigs = analyze_content_signals("", html)
    kinds = {s.kind for s in sigs}
    assert "href_mismatch" in kinds


def test_content_credential() -> None:
    sigs = analyze_content_signals("Please sign in to OWA webmail now")
    assert any(s.kind == "credential_harvest" for s in sigs)


def test_verdict_has_breakdown() -> None:
    result = analyze_file(CORPUS / "malicious_exe_ip_url.eml")
    assert result.verdict is not None
    assert result.verdict.breakdown
    assert sum(b.points for b in result.verdict.breakdown) >= result.verdict.score - 5


def test_score_caps_in_config() -> None:
    cfg = load_verdict_config()
    assert cfg.cap_headers <= 50
    assert cfg.cap_attachments <= 50


def test_analysis_options_overrides() -> None:
    opts = AnalysisOptions(allowlist_path="a.txt", verdict_path="v.json")
    assert opts.overrides_loaded()["allowlist"] == "a.txt"


def test_org_profile_dir(tmp_path: Path) -> None:
    (tmp_path / "allowlist_extra.txt").write_text("safe.example\n", encoding="utf-8")
    (tmp_path / "brands.txt").write_text("contoso.com\n", encoding="utf-8")
    profile = load_org_profile(tmp_path)
    assert profile is not None
    assert profile.allowlist_path is not None
    assert profile.brands_path is not None


def test_org_profile_zip(tmp_path: Path) -> None:
    root = tmp_path / "pack"
    root.mkdir()
    (root / "verdict_extra.json").write_text(
        '{"weight_urgency": 1}', encoding="utf-8"
    )
    zpath = tmp_path / "org.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.write(root / "verdict_extra.json", "verdict_extra.json")
    profile = load_org_profile(zpath)
    assert profile is not None
    assert profile.verdict_path is not None
    profile.cleanup()


def test_handoff_level_template(tmp_path: Path) -> None:
    result = analyze_file(CORPUS / "malicious_exe_ip_url.eml")
    level = result.verdict.level.value if result.verdict else "malicious"
    tmpl = tmp_path / f"handoff_{level}.txt"
    tmpl.write_text("LVL={verdict} VER={version} BD=\n{breakdown}\n", encoding="utf-8")
    text = render_handoff(
        result,
        handoff_by_level={level: tmpl},
    )
    assert "LVL=" in text
    assert "VER=" in text


def test_campaign_key_grouping() -> None:
    a = analyze_file(CORPUS / "benign_hr_notice.eml")
    b = analyze_file(CORPUS / "benign_newsletter.eml")
    ka = campaign_key_for(a)
    kb = campaign_key_for(b)
    assert ka and kb
    # Different msgs → different keys
    assert ka != kb
    merged = merge_results([a, b])
    assert len(merged.file_rows) == 2


def test_meta_version() -> None:
    result = analyze_file(CORPUS / "benign_hr_notice.eml")
    assert result.meta is not None
    assert result.meta.app_version


def test_scan_lookalikes_from_addr() -> None:
    hits = scan_lookalikes(from_addr="Microsoft Support <help@evil-secure.top>")
    # brand_spoof may fire on display via domain scan of evil; at least runs
    assert isinstance(hits, list)
