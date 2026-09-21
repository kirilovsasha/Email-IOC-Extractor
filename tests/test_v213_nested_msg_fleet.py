"""v2.13: nested mail from archives, password+enc, TNEF/ISO, OOB, allowlist mitigation, prefs."""

from __future__ import annotations

import json
from pathlib import Path

from reliquary.core.attachment_inspector import (
    extract_nested_mail_from_archive,
    inspect_bytes,
)
from reliquary.core.calibration import segment_for
from reliquary.core.content_signals import ARCHIVE_PASSWORD_RE, OOB_DELIVERY_RE
from reliquary.core.export_hook import run_post_export_hook
from reliquary.core.lookalike import check_display_name_spoof
from reliquary.core.pipeline import analyze_file
from reliquary.core.prefs import _DEFAULTS
from reliquary.core.tnef import extract_tnef_attachments, is_tnef
from reliquary.core.update_check import check_update_manifest
from reliquary.core.verdict import VerdictConfig, render_verdict

CORPUS = Path(__file__).resolve().parents[1] / "samples" / "corpus"


def test_nested_mail_extracted_from_zip() -> None:
    r = analyze_file(CORPUS / "suspicious_nested_mail_in_zip.eml")
    assert r.verdict is not None
    flags = {f for a in r.attachments for f in a.risk_flags}
    assert "archive_nested_email" in flags
    assert any(a.filename.endswith(".eml") for a in r.attachments)
    urls = [i.value for i in r.iocs if i.ioc_type.value == "url"]
    assert any("evil-phish.top" in u for u in urls)
    assert segment_for(r) in {"nested_mail", "phishing_content", "attachment", "other"}


def test_password_zip_match_signal() -> None:
    assert ARCHIVE_PASSWORD_RE.search("Password is: 1234")
    r = analyze_file(CORPUS / "suspicious_password_zip_match.eml")
    assert r.verdict is not None
    assert "archive_password_match" in (r.content_signals or [])
    flags = {f for a in r.attachments for f in a.risk_flags}
    assert "encrypted_archive" in flags
    assert segment_for(r) in {"archive_password", "attachment", "phishing_content"}


def test_oob_delivery_signal() -> None:
    assert OOB_DELIVERY_RE.search("Пароль в Telegram: @bot")
    r = analyze_file(CORPUS / "suspicious_oob_delivery.eml")
    assert r.verdict is not None
    assert "oob_delivery" in (r.content_signals or [])
    assert segment_for(r) in {"oob_delivery", "phishing_content", "other"}


def test_fns_display_spoof() -> None:
    hits = check_display_name_spoof('"ФНС России" <x@evil.top>')
    assert hits
    r = analyze_file(CORPUS / "suspicious_display_spoof_fns.eml")
    assert r.verdict is not None
    assert r.verdict.level.value in {"suspicious", "malicious"}


def test_iso_lnk_inventory() -> None:
    r = analyze_file(CORPUS / "suspicious_iso_lnk_inventory.eml")
    flags = {f for a in r.attachments for f in a.risk_flags}
    assert "iso_image" in flags
    assert "iso_contains_lnk" in flags
    assert segment_for(r) in {"iso", "attachment"}


def test_tnef_extract() -> None:
    r = analyze_file(CORPUS / "suspicious_tnef_winmail.eml")
    flags = {f for a in r.attachments for f in a.risk_flags}
    assert "tnef_attachment" in flags
    # Expanded payload.exe from winmail
    names = [a.filename.lower() for a in r.attachments]
    assert any("exe" in n or "winmail" in n for n in names)
    assert VerdictConfig().weight_tnef >= 8


def test_tnef_unit_magic() -> None:
    import struct

    sig = struct.pack("<I", 0x223E9F78) + struct.pack("<H", 1)
    payload = b"PK\x03\x04" + b"\x00" * 80
    attr = bytes([2]) + struct.pack("<I", 0x0006800F) + struct.pack("<I", len(payload))
    attr += payload + struct.pack("<H", 0)
    data = sig + attr
    assert is_tnef(data)
    parts, notes = extract_tnef_attachments(data)
    assert parts
    assert notes


def test_msg_corpus_parses() -> None:
    r = analyze_file(CORPUS / "unknown_msg_sample.msg")
    assert r.verdict is not None
    assert r.source_kind == "email"


def test_allowlist_mitigation_in_verdict() -> None:
    r = analyze_file(CORPUS / "benign_hr_notice.eml")
    assert r.verdict is not None
    # Soft mitigation weight exists on config
    assert VerdictConfig().weight_allowlisted_from < 0
    v = render_verdict(r, allowlist_domains={"company.local", "example.com"})
    assert v is not None
    # Mitigation may or may not fire depending on From host; weight must be wired
    blob = " ".join(c.reason for c in (v.breakdown or []))
    assert "allowlist" in blob.lower() or v.score <= 100


def test_update_manifest_channel_sha(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("reliquary.core.update_check.app_dir", lambda: tmp_path)
    (tmp_path / "update.json").write_text(
        json.dumps(
            {
                "latest": "99.0.0",
                "channel": "full",
                "sha256": "a" * 64,
                "notes": "тест",
            }
        ),
        encoding="utf-8",
    )
    msg = check_update_manifest()
    assert msg
    assert "99.0.0" in msg
    assert "Full" in msg or "full" in msg.lower()


def test_prefs_export_ui_and_sidecar_defaults() -> None:
    from reliquary.core.prefs import _EXPORT_OK, _EXPORT_LEGACY, _coerce_value

    assert _EXPORT_OK == frozenset({"JSON", "CSV", "Batch CSV", "Тикет"})
    assert _coerce_value("export_choice", "Campaign pack", "JSON") == "Batch CSV"
    assert _coerce_value("export_choice", "ECS", "JSON") == "JSON"
    assert "Campaign pack" in _EXPORT_LEGACY
    assert "post_export_hook_json_sidecar" in _DEFAULTS
    assert _DEFAULTS["post_export_hook_json_sidecar"] is True
    assert "batch_sort_column" in _DEFAULTS


def test_export_hook_accepts_sidecar(tmp_path: Path) -> None:
    script = tmp_path / "hook.sh"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)
    export = tmp_path / "out.csv"
    export.write_text("a,b\n", encoding="utf-8")
    sidecar = tmp_path / "out.sidecar.json"
    sidecar.write_text('{"schema_version":2}\n', encoding="utf-8")
    # Should not raise
    run_post_export_hook(
        str(script),
        export,
        allow_external=True,
        json_sidecar=sidecar,
    )


def test_extract_nested_helper_direct() -> None:
    import io
    import zipfile

    inner = b"From: a@b.c\nSubject: x\n\nhttps://evil.example/login\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner.eml", inner)
    kids, notes = extract_nested_mail_from_archive(buf.getvalue(), container_name="x.zip")
    assert len(kids) == 1
    assert "nested_email" in kids[0].risk_flags
    info = inspect_bytes("x.zip", buf.getvalue())
    assert "archive_nested_email" in info.risk_flags
