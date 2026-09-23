"""Quality sprint: cover install/yara/labels/prefs/error_log gaps (no new features)."""

from __future__ import annotations

import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from reliquary.core.analysis_options import AnalysisOptions
from reliquary.core.error_log import _MAX_LOG_BYTES, append_error_log, error_log_path
from reliquary.core.formats import (
    collect_supported,
    expand_input_paths,
    formats_help_line,
    tk_filetypes,
)
from reliquary.core.labels import parse_verdict_level, verdict_label_ru
from reliquary.core.models import VerdictLevel
from reliquary.core.org_profile_install import install_org_profile, verify_org_profile
from reliquary.core.prefs import _coerce_value, load_prefs, save_prefs
from reliquary.core.yara_scan import (
    resolve_rules_path,
    scan_bytes,
    scan_result_attachments,
    yara_available,
)

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
CORPUS = SAMPLES / "corpus"


def test_install_org_profile_zip_and_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("reliquary.core.org_profile_install.app_dir", lambda: tmp_path)
    pack = tmp_path / "src_pack"
    pack.mkdir()
    (pack / "allowlist_extra.txt").write_text("trusted.example\n", encoding="utf-8")
    (pack / "brands.txt").write_text("contoso.com\n", encoding="utf-8")

    dest_dir, notes = install_org_profile(pack)
    assert dest_dir == tmp_path / "org_profile"
    assert dest_dir.is_dir()
    assert any("Скопирован каталог" in n for n in notes)
    # Re-install over existing dir (covers rmtree path)
    dest_dir2, _ = install_org_profile(pack)
    assert dest_dir2 == dest_dir
    assert (dest_dir2 / "allowlist_extra.txt").is_file()

    zpath = tmp_path / "pack.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.write(pack / "allowlist_extra.txt", "allowlist_extra.txt")
        zf.write(pack / "brands.txt", "brands.txt")

    dest_zip, znotes = install_org_profile(zpath)
    assert dest_zip == tmp_path / "org_profile.zip"
    assert dest_zip.is_file()
    assert any("Скопирован" in n for n in znotes)

    dest_extracted, enotes = install_org_profile(zpath, as_zip=False)
    assert dest_extracted == tmp_path / "org_profile"
    assert (dest_extracted / "allowlist_extra.txt").is_file()
    assert any("Распакован" in n for n in enotes)


def test_install_org_profile_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("reliquary.core.org_profile_install.app_dir", lambda: tmp_path)
    with pytest.raises(FileNotFoundError):
        install_org_profile(tmp_path / "missing")
    weird = tmp_path / "x.bin"
    weird.write_bytes(b"nope")
    with pytest.raises(ValueError):
        install_org_profile(weird)


def test_verify_org_profile_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "allowlist_extra.txt").write_text("ok.example\n", encoding="utf-8")
    (tmp_path / "verdict_extra.json").write_text("{}", encoding="utf-8")
    notes = verify_org_profile(tmp_path, sample_eml=CORPUS / "benign_hr_notice.eml")
    assert any("Профиль:" in n for n in notes)
    assert any("allowlist" in n for n in notes)
    assert any("Пробный разбор" in n for n in notes)

    empty = verify_org_profile(tmp_path / "nope")
    assert "не загружен" in empty[0]


def test_yara_resolve_and_scan_without_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("reliquary.core.yara_scan.app_dir", lambda: tmp_path)
    assert resolve_rules_path(None) is None
    assert resolve_rules_path(tmp_path / "missing.yar") is None

    rules = tmp_path / "yara_rules.yar"
    rules.write_text("rule r { condition: false }", encoding="utf-8")
    assert resolve_rules_path(None) == rules
    assert resolve_rules_path(rules) == rules

    folder = tmp_path / "yara_rules"
    folder.mkdir()
    (folder / "a.yar").write_text("rule a { condition: false }", encoding="utf-8")
    rules.unlink()
    assert resolve_rules_path(None) == folder

    # Rules packed inside a frozen bundle must not be picked up.
    import sys

    meipass = tmp_path / "bundle"
    packed = meipass / "yara_rules"
    packed.mkdir(parents=True)
    (packed / "default.yar").write_text("rule packed { condition: false }", encoding="utf-8")
    monkeypatch.setattr(sys, "_MEIPASS", str(meipass), raising=False)
    folder.rename(tmp_path / "yara_rules_off")
    assert resolve_rules_path(None) is None

    hits, notes = scan_bytes(b"", rules_path=rules)
    assert hits == [] and notes == []

    # Without yara package installed, scan returns a clear note.
    if not yara_available():
        hits, notes = scan_bytes(b"payload", rules_path=tmp_path / "nope.yar")
        assert hits == []
        assert any("не установлен" in n or "не найдены" in n for n in notes)

    att = SimpleNamespace(data=b"x", risk_flags=[], notes=[])
    hits2, notes2 = scan_result_attachments([att], body="body", rules_path=tmp_path / "no")
    assert isinstance(hits2, list)
    assert isinstance(notes2, list)


def test_labels_and_analysis_options() -> None:
    assert verdict_label_ru(None) == "—"
    assert verdict_label_ru(VerdictLevel.SUSPICIOUS) == "подозрительный"
    assert verdict_label_ru("malicious") == "вредоносный"
    assert parse_verdict_level("фишинг") == VerdictLevel.MALICIOUS
    assert parse_verdict_level("безопасно") == VerdictLevel.BENIGN
    assert parse_verdict_level("???") is None

    opts = AnalysisOptions.from_prefs(
        {
            "allowlist_path": "a.txt",
            "max_workers": "2",
            "enable_yara": True,
            "yara_rules_path": "r.yar",
        }
    )
    assert opts.allowlist_path == "a.txt"
    assert opts.max_workers == 2
    assert opts.enable_yara is True
    assert opts.with_profile(None) is opts
    ov = opts.overrides_loaded()
    assert ov["allowlist"] == "a.txt"
    assert "yara" not in ov


def test_prefs_coerce_remaining_edges(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _coerce_value("hide_rewriter", "on", False) is True
    assert _coerce_value("hide_rewriter", "off", True) is False
    assert _coerce_value("hide_rewriter", "maybe", True) is True
    assert _coerce_value("hide_rewriter", 1, False) is True
    assert _coerce_value("copy_format", "defanged", "type|value") == "defanged"
    assert _coerce_value("copy_format", "weird", "type|value") == "type|value"
    assert _coerce_value("export_choice", "Handoff", "JSON") == "Тикет"
    assert _coerce_value("export_choice", "ECS", "JSON") == "JSON"
    assert _coerce_value("export_choice", "Nope", "JSON") == "JSON"
    assert _coerce_value("ui_scale", 3.0, 1.0) == 2.0
    assert _coerce_value("ui_scale", 0.1, 1.0) == 0.75
    assert _coerce_value("folder_warn_threshold", -5, 80) == 0
    assert _coerce_value("last_dir", None, "") == ""
    assert _coerce_value("max_workers", None, 0) == 0
    assert _coerce_value("ui_scale", None, 1.0) == 1.0

    prefs_file = tmp_path / "ui_prefs.json"
    prefs_file.write_text("{not-json", encoding="utf-8")
    monkeypatch.setattr("reliquary.core.prefs.prefs_path", lambda: prefs_file)
    data = load_prefs()
    assert data["appearance_mode"] == "dark"

    monkeypatch.setattr(
        "reliquary.core.prefs.prefs_path",
        lambda: tmp_path / "readonly" / "ui_prefs.json",
    )
    assert save_prefs({"last_dir": "x"}) is False


def test_error_log_rotate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("reliquary.core.error_log.app_dir", lambda: tmp_path)
    path = error_log_path()
    path.write_bytes(b"x" * (_MAX_LOG_BYTES + 10))
    out = append_error_log("rotated", exc=ValueError("boom"))
    assert out == path
    assert path.is_file()
    assert path.with_suffix(path.suffix + ".1").is_file()


def test_formats_mbox_and_help(tmp_path: Path) -> None:
    (tmp_path / "a.eml").write_text("From: a@b.c\n\nHi\n", encoding="utf-8")
    mbox = tmp_path / "box.mbox"
    mbox.write_text(
        "From nobody@local\nFrom: x@y.z\nSubject: one\n\nbody\n",
        encoding="utf-8",
    )
    found = collect_supported(tmp_path, recursive=False)
    assert any(p.endswith(".eml") for p in found)
    assert ".eml" in formats_help_line()
    assert tk_filetypes()[0][1].startswith("*.eml")
    expanded = expand_input_paths([mbox, tmp_path / "a.eml"])
    assert len(expanded) >= 2
