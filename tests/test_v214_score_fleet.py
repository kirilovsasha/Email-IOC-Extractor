"""v2.14: score wiring, scripts/VHD/cloud lure, RU unwrap, fleet CLI/settings."""

from __future__ import annotations

import json
from pathlib import Path

from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.calibration import segment_for
from reliquary.core.content_signals import CLOUD_LURE_RE
from reliquary.core.pipeline import analyze_file
from reliquary.core.update_check import check_update_manifest, detect_runtime_channel
from reliquary.core.url_rewrite import unwrap_url
from reliquary.core.verdict import VerdictConfig, render_verdict

CORPUS = Path(__file__).resolve().parents[1] / "samples" / "corpus"


def test_tnef_iso_in_high_flags_breakdown() -> None:
    tnef = analyze_file(CORPUS / "suspicious_tnef_winmail.eml")
    blob = " ".join(c.reason for c in (tnef.verdict.breakdown or []))
    assert "TNEF" in blob or "winmail" in blob.lower()
    iso = analyze_file(CORPUS / "suspicious_iso_lnk_inventory.eml")
    blob2 = " ".join(c.reason for c in (iso.verdict.breakdown or []))
    assert "lnk" in blob2.lower() or "ISO" in blob2


def test_script_attachment_scored() -> None:
    r = analyze_file(CORPUS / "suspicious_script_js.eml")
    flags = {f for a in r.attachments for f in a.risk_flags}
    assert "script_attachment" in flags
    assert "script_url" in flags
    blob = " ".join(c.reason for c in (r.verdict.breakdown or []))
    assert "Скрипт" in blob or "script" in blob.lower()
    assert segment_for(r) in {"script_att", "attachment"}


def test_vhd_disk_image() -> None:
    r = analyze_file(CORPUS / "suspicious_vhd_lnk.eml")
    flags = {f for a in r.attachments for f in a.risk_flags}
    assert "disk_image" in flags
    assert "iso_contains_lnk" in flags or "archive_dangerous_member" in flags


def test_cloud_lure_signal() -> None:
    assert CLOUD_LURE_RE.search("https://disk.yandex.ru/d/abc")
    r = analyze_file(CORPUS / "suspicious_cloud_lure.eml")
    assert "cloud_lure" in (r.content_signals or []) or "oob_delivery" in (
        r.content_signals or []
    )
    assert segment_for(r) in {"cloud_lure", "oob_delivery", "phishing_content", "other"}


def test_bitrix_unwrap() -> None:
    u = unwrap_url(
        "https://company.bitrix24.ru/bitrix/redirect.php?goto=https%3A%2F%2Fevil.top%2Fx"
    )
    assert u.changed
    assert "evil.top" in u.unwrapped
    assert u.rewriter in {"bitrix_redir", "generic_redirect"}


def test_office_hyperlink_weight_exists() -> None:
    assert VerdictConfig().weight_office_hyperlink >= 8
    assert VerdictConfig().weight_nested_archive >= 8
    assert VerdictConfig().weight_script_attachment >= 10


def test_nested_archive_scored() -> None:
    r = analyze_file(CORPUS / "suspicious_nested_archive.eml")
    flags = {f for a in r.attachments for f in a.risk_flags}
    assert "nested_archive" in flags
    blob = " ".join(c.reason for c in (r.verdict.breakdown or []))
    assert "Вложенный архив" in blob or "nested" in blob.lower()


def test_allowlist_skipped_on_display_spoof() -> None:
    r = analyze_file(CORPUS / "suspicious_allowlist_spoof.eml")
    assert r.verdict is not None
    # Even with company.local allowlisted, spoof should block mitigation
    v = render_verdict(r, allowlist_domains={"company.local"})
    assert v is not None
    mit = [c for c in (v.breakdown or []) if c.category == "mitigation" and "allowlist" in c.reason.lower()]
    assert not mit


def test_update_manifest_newer_version(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("reliquary.core.update_check.app_dir", lambda: tmp_path)
    (tmp_path / "update.json").write_text(
        json.dumps({"latest": "99.0.0", "sha256": "a" * 64, "notes": "тест"}),
        encoding="utf-8",
    )
    msg = check_update_manifest()
    assert msg
    assert "99.0.0" in msg
    assert "Доступно обновление" in msg


def test_detect_runtime_channel() -> None:
    ch = detect_runtime_channel()
    assert ch in {"standard", "no_qr"}


def test_cli_self_check(tmp_path: Path) -> None:
    from reliquary.cli import main

    assert main(["--self-check"]) == 0


def test_schema_weight_drift() -> None:
    """All VerdictConfig weight_* keys must appear in schema + example."""
    import json as _json
    from dataclasses import fields

    cfg_keys = {
        f.name
        for f in fields(VerdictConfig)
        if f.name.startswith("weight_") or f.name.startswith("threshold_") or f.name.startswith("cap_")
    }
    schema = _json.loads(
        (Path(__file__).resolve().parents[1] / "docs" / "verdict_extra.schema.json").read_text(
            encoding="utf-8"
        )
    )
    example = _json.loads(
        (Path(__file__).resolve().parents[1] / "verdict_extra.example.json").read_text(
            encoding="utf-8"
        )
    )
    props = set(schema.get("properties") or {})
    missing_schema = sorted(k for k in cfg_keys if k not in props)
    assert not missing_schema, f"schema missing: {missing_schema}"
    # example may omit some; require new 2.14+ weights at least
    for key in (
        "weight_office_hyperlink",
        "weight_script_attachment",
        "weight_cloud_lure",
        "weight_disk_image",
        "weight_nested_archive",
    ):
        assert key in example
        assert key in props


def test_inspect_script_unit() -> None:
    data = b'var x = "https://evil.example/a"; ActiveXObject("WScript.Shell");'
    info = inspect_bytes("pay.js", data)
    assert "script_attachment" in info.risk_flags
    assert "script_url" in info.risk_flags
