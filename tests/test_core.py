"""Unit tests for Reliquary core — no network."""

from __future__ import annotations

from pathlib import Path

from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.exporters import export_csv, export_stix
from reliquary.core.ioc_extractor import defang, extract_iocs
from reliquary.core.pipeline import analyze_file, analyze_text
from reliquary.core.url_rewrite import unwrap_url
from reliquary.core.verdict import render_verdict
from reliquary.core.models import AnalysisResult, VerdictLevel

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_defang_and_extract():
    text = "Visit hxxps://bad[.]example.com/path and 1.2.3.4"
    cleaned = defang(text)
    assert "https://bad.example.com/path" in cleaned
    iocs = extract_iocs(text)
    types = {i.ioc_type.value for i in iocs}
    assert "url" in types or "domain" in types
    assert "ipv4" in types


def test_safelinks_unwrap():
    url = (
        "https://nam.safelinks.protection.outlook.com/"
        "?url=https%3A%2F%2Fevil.example.com%2Fx&data=01"
    )
    result = unwrap_url(url)
    assert result.changed
    assert result.rewriter == "microsoft_safelinks"
    assert result.unwrapped.startswith("https://evil.example.com")


def test_proofpoint_v2_unwrap():
    url = "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example.com_a&d=Dw"
    result = unwrap_url(url)
    assert result.rewriter == "proofpoint_v2"
    assert "evil.example.com" in result.unwrapped


def test_double_extension_attachment():
    info = inspect_bytes("report.pdf.exe", b"MZ\x90\x00fake")
    assert "double_extension" in info.risk_flags
    assert "dangerous_extension" in info.risk_flags
    assert len(info.sha256) == 64


def test_analyze_ticket_sample():
    result = analyze_file(SAMPLES / "ticket_sample.txt")
    assert result.verdict is not None
    values = {i.value for i in result.iocs}
    assert any("paypa1-secure.xyz" in v or "malicious.example.com" in v for v in values)
    assert any(i.ioc_type.value == "sha256" for i in result.iocs)
    assert any(i.ioc_type.value == "cve" for i in result.iocs)


def test_analyze_phishing_eml():
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    assert result.source_kind == "email"
    assert result.verdict is not None
    assert result.verdict.level in {
        VerdictLevel.SUSPICIOUS,
        VerdictLevel.MALICIOUS,
        VerdictLevel.UNKNOWN,
    }
    assert any(h.severity.value in ("high", "medium") for h in result.headers)
    assert any(u.changed for u in result.url_rewrites)
    assert any("invoice.pdf.exe" in a.filename for a in result.attachments)


def test_export_csv_and_stix(tmp_path: Path):
    result = analyze_text("Host 8.8.8.8 and https://example.org/a md5 44d88612fea8a8f36de82e1278abb02f")
    csv_path = tmp_path / "out.csv"
    stix_path = tmp_path / "out.json"
    export_csv(result, csv_path)
    export_stix(result, stix_path)
    assert csv_path.stat().st_size > 0
    assert "ipv4" in csv_path.read_text(encoding="utf-8")
    data = stix_path.read_text(encoding="utf-8")
    assert "indicator" in data.lower() or "bundle" in data.lower()


def test_verdict_actions_present():
    """Phishing verdict is optional add-on; still produced for emails."""
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    assert result.verdict is not None
    assert len(result.verdict.actions) >= 1
    # Core promise: IOCs are the main deliverable
    assert len(result.iocs) >= 1


def test_cli_defaults_to_ioc_list(capsys):
    from reliquary.cli import main

    code = main([str(SAMPLES / "ticket_sample.txt")])
    assert code == 0
    out = capsys.readouterr().out
    assert "ioc_type" in out or "sha256" in out.lower() or "domain" in out
