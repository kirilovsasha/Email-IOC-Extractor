"""v2.11: display-spoof, office extract, RAR/CAB/LNK, shorteners, CLI/docs RU."""

from __future__ import annotations

from pathlib import Path

from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.content_signals import analyze_content_signals
from reliquary.core.document_parser import parse_msg
from reliquary.core.lookalike import check_display_name_spoof
from reliquary.core.pipeline import analyze_file
from reliquary.core.self_check import build_self_check_lines
from reliquary.core.verdict import VerdictConfig

CORPUS = Path(__file__).resolve().parents[1] / "samples" / "corpus"


def test_display_name_spoof_sber() -> None:
    hits = check_display_name_spoof("Сбербанк Онлайн <noreply@evil.top>")
    assert hits and hits[0].kind == "display_spoof"
    r = analyze_file(CORPUS / "suspicious_display_spoof_sber.eml")
    assert r.verdict is not None
    assert r.verdict.level.value == "malicious"
    assert any("сбер" in x.lower() or "Имя" in x for x in r.verdict.reasons)


def test_display_spoof_gosuslugi_and_shortener() -> None:
    r = analyze_file(CORPUS / "suspicious_display_spoof_gosuslugi.eml")
    assert r.verdict is not None
    assert "url_shortener" in (r.content_signals or [])
    assert any("госуслуг" in x.lower() or "Имя" in x for x in r.verdict.reasons)


def test_messenger_only_signal() -> None:
    signals = analyze_content_signals("только https://t.me/evil_x", "")
    kinds = {s.kind for s in signals}
    assert "messenger_only" in kinds
    r = analyze_file(CORPUS / "suspicious_messenger_only.eml")
    assert r.verdict is not None
    assert "messenger_only" in (r.content_signals or []) or any(
        "Telegram" in x or "messenger" in x.lower() for x in r.verdict.reasons
    )


def test_lnk_target_flags() -> None:
    # Minimal LNK header + embedded path
    raw = b"L\x00\x00\x00" + b"\x00" * 0x48 + b"C:\\Windows\\System32\\cmd.exe\x00"
    info = inspect_bytes("x.lnk", raw)
    assert "shortcut_lnk" in info.risk_flags
    r = analyze_file(CORPUS / "suspicious_lnk_attachment.eml")
    assert r.verdict is not None
    assert any("shortcut_lnk" in (a.risk_flags or []) for a in r.attachments)


def test_cab_inventory_flags() -> None:
    raw = b"MSCF" + b"\x00" * 32 + b"payload.exe\x00malware.lnk\x00"
    info = inspect_bytes("x.cab", raw)
    assert "cab_archive" in info.risk_flags
    r = analyze_file(CORPUS / "suspicious_cab_attachment.eml")
    assert r.verdict is not None
    assert any("cab_archive" in (a.risk_flags or []) for a in r.attachments)


def test_new_weights() -> None:
    cfg = VerdictConfig()
    assert cfg.weight_url_shortener > 0
    assert cfg.weight_messenger_only > 0


def test_self_check_mentions_unrar() -> None:
    text = "\n".join(build_self_check_lines())
    assert "Сборка" in text
    assert "RAR" in text or "Lite" in text


def test_parse_msg_accepts_bytes(tmp_path: Path) -> None:
    # Without a real MSG binary, ensure empty/invalid bytes return errors, not crash
    doc = parse_msg(tmp_path / "virtual.msg", data=b"not-a-real-msg")
    assert doc.kind == "email"
    assert doc.errors or doc.text == ""
