"""Org profile packs and AnalysisOptions."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from reliquary.core.analysis_options import AnalysisOptions
from reliquary.core.org_profile import load_org_profile
from reliquary.core.pipeline import analyze_file, campaign_key_for, merge_results

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
CORPUS = SAMPLES / "corpus"
PRESETS = Path(__file__).resolve().parents[1] / "org_profile.example"


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
    (root / "verdict_extra.json").write_text('{"weight_urgency": 1}', encoding="utf-8")
    zpath = tmp_path / "org.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.write(root / "verdict_extra.json", "verdict_extra.json")
    profile = load_org_profile(zpath)
    assert profile is not None
    assert profile.verdict_path is not None
    assert profile._tmpdir is not None
    tmp = profile._tmpdir
    profile.cleanup()
    assert not tmp.exists()


def test_org_profile_m365_preset() -> None:
    profile = load_org_profile(PRESETS / "m365")
    assert profile is not None
    assert profile.brands_path is not None
    assert profile.verdict_path is not None
    # allowlist_extra.txt is part of the preset pack (must be tracked in git)
    assert profile.allowlist_path is not None
    assert Path(profile.allowlist_path).is_file()


@pytest.mark.parametrize(
    "preset",
    ["proxysg", "kaspersky", "drweb", "local_mx", "google", "banking", "ru_gov", "by_gov"],
)
def test_org_profile_new_presets(preset: str) -> None:
    profile = load_org_profile(PRESETS / preset)
    assert profile is not None
    assert profile.brands_path is not None
    assert Path(profile.brands_path).is_file()


def test_campaign_key_grouping() -> None:
    a = analyze_file(CORPUS / "campaign_a1.eml")
    b = analyze_file(CORPUS / "campaign_a2.eml")
    assert campaign_key_for(a) == campaign_key_for(b)
    merged = merge_results([a, b])
    assert len(merged.file_rows) == 2
    assert merged.file_rows[0].campaign_peers


def test_meta_version() -> None:
    result = analyze_file(CORPUS / "benign_hr_notice.eml")
    assert result.meta is not None
    assert result.meta.app_version
