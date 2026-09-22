"""v2.12: scoring flags, display_spoof weight, RU unwrap, campaign pack, self-check."""

from __future__ import annotations

import json
from pathlib import Path

from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.calibration import segment_for
from reliquary.core.campaign import export_campaign_pack
from reliquary.core.handoff import render_default_handoff
from reliquary.core.lookalike import check_display_name_spoof
from reliquary.core.pipeline import analyze_file
from reliquary.core.self_check import build_self_check_lines
from reliquary.core.url_rewrite import unwrap_url
from reliquary.core.verdict import VerdictConfig

CORPUS = Path(__file__).resolve().parents[1] / "samples" / "corpus"


def test_display_spoof_has_dedicated_weight() -> None:
    hits = check_display_name_spoof('"Сбербанк Онлайн" <thief@evil.top>')
    assert hits and hits[0].kind == "display_spoof"
    r = analyze_file(CORPUS / "suspicious_display_spoof_sber.eml")
    assert r.verdict is not None
    blob = " ".join(c.reason for c in (r.verdict.breakdown or []))
    assert "Сбер" in blob or "похож" in blob or any(
        "display" in (c.reason or "").lower() or "Имя" in (c.reason or "")
        for c in (r.verdict.breakdown or [])
    )
    # Dedicated display_spoof weight appears as lookalike contribution
    lookalike_pts = [c.points for c in (r.verdict.breakdown or []) if c.category == "lookalike"]
    assert lookalike_pts and max(lookalike_pts) >= min(
        VerdictConfig().weight_display_spoof, VerdictConfig().cap_display_spoof
    )


def test_lnk_dangerous_flag_and_ioc() -> None:
    # Minimal LNK-like header + UTF-16LE powershell path
    payload = b"L\x00\x00\x00" + b"\x00" * 0x48
    wide = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".encode("utf-16-le")
    data = payload + wide
    info = inspect_bytes("evil.lnk", data)
    assert "shortcut_lnk" in info.risk_flags
    assert "lnk_dangerous" in info.risk_flags or "lnk_target" in info.risk_flags


def test_pdf_uri_and_cab_scored() -> None:
    r = analyze_file(CORPUS / "suspicious_pdf_uri_only.eml")
    assert r.verdict and r.verdict.level.value in {"suspicious", "malicious"}
    flags = {f for a in r.attachments for f in a.risk_flags}
    assert "pdf_uri_action" in flags
    reasons = " ".join(r.verdict.reasons)
    assert "URI" in reasons or "pdf" in reasons.lower()


def test_vk_away_unwrap() -> None:
    u = unwrap_url("https://vk.com/away.php?to=https%3A%2F%2Fevil.top%2Flogin")
    assert u.changed
    assert "evil.top" in u.unwrapped
    assert u.rewriter in {"vk_away", "generic_redirect"}


def test_ru_mail_segments_and_corpus() -> None:
    r = analyze_file(CORPUS / "suspicious_shortener_only.eml")
    assert r.verdict is not None
    assert "url_shortener" in (r.content_signals or [])
    assert segment_for(r) in {"shortener", "phishing_content", "other", "attachment"}
    svg = analyze_file(CORPUS / "suspicious_svg_script.eml")
    assert segment_for(svg) in {"html_smuggling", "attachment"}


def test_handoff_includes_chains_and_campaign() -> None:
    r = analyze_file(CORPUS / "suspicious_vk_away.eml")
    text = render_default_handoff(r)
    assert "Campaign:" in text
    assert "URL unwrap" in text or "chains" in text.lower() or "→" in text


def test_campaign_pack_ndjson(tmp_path: Path) -> None:
    a = analyze_file(CORPUS / "campaign_a1.eml")
    b = analyze_file(CORPUS / "campaign_a2.eml")
    out = tmp_path / "pack.ndjson"
    export_campaign_pack([a, b], out)
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 3
    meta = json.loads(lines[0])
    assert meta["type"] == "campaign_pack_meta"
    assert meta["mail_count"] == 2


def test_self_check_mentions_qr() -> None:
    lines = build_self_check_lines()
    blob = "\n".join(lines)
    assert "Версия" in blob
    assert "QR" in blob or "pyzbar" in blob or "Сборка" in blob


def test_local_mx_ru_benign() -> None:
    r = analyze_file(CORPUS / "benign_local_mx_ru.eml")
    assert r.verdict and r.verdict.level.value == "benign"
    assert any("MX" in x or "внутренн" in x for x in r.verdict.reasons)


def test_office_hyperlink_extract(tmp_path: Path) -> None:
    """Minimal docx with external rel → office_hyperlink flag."""
    import io
    import zipfile

    from reliquary.core.office_extract import extract_office_urls

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>',
        )
        zf.writestr(
            "word/document.xml",
            '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>",
        )
        zf.writestr(
            "word/_rels/document.xml.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
            'Target="https://phish.evil.top/login" TargetMode="External"/>'
            "</Relationships>",
        )
    urls = extract_office_urls(buf.getvalue(), ".docx")
    assert any("phish.evil.top" in u for u in urls)
