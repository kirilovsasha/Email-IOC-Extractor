"""Unit tests for Email IOC Extractor core — email triage, no network."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

from reliquary import __app_name__, __version__
from reliquary.core.allowlist import build_allowlist, domain_matches, tag_allowlist
from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.exporters import export_csv, export_report_json, filter_iocs
from reliquary.core.ioc_extractor import defang, extract_iocs
from reliquary.core.models import Ioc, IocType, VerdictLevel
from reliquary.core.office_extract import extract_office_text
from reliquary.core.paths import app_dir
from reliquary.core.pipeline import analyze_file, analyze_text, merge_results
from reliquary.core.prefs import load_prefs, prefs_path, save_prefs
from reliquary.core.url_rewrite import unwrap_url
from reliquary.core.verdict import VerdictConfig, load_verdict_config, render_verdict
from reliquary.gui.export_actions import EXPORT_CHOICES, default_export_filename, run_export
from reliquary.gui.tabs import desired_result_tabs

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_product_name():
    assert __app_name__ == "Email IOC Extractor"
    assert __version__ == "2.15.0"


def test_defang_and_extract():
    text = "Visit hxxps://bad[.]example.com/path and 1.2.3.4"
    cleaned = defang(text)
    assert "https://bad.example.com/path" in cleaned
    iocs = extract_iocs(text)
    types = {i.ioc_type.value for i in iocs}
    assert "url" in types or "domain" in types
    assert "ipv4" in types


def test_broad_tld_and_file_suffix_filter():
    iocs = extract_iocs("C2 at evil.corp.phishing and also report.pdf as noise")
    values = {i.value for i in iocs if i.ioc_type.value == "domain"}
    assert "evil.corp.phishing" in values
    assert "report.pdf" not in values


def test_soc_host_and_crypto_iocs():
    text = (
        "C2 185.199.108.153:443 path C:\\Users\\Public\\payload.exe "
        "UNC \\\\fileserver\\share\\drop.bin "
        "reg HKLM\\Software\\Evil\\Run "
        "mutex Global\\EvilMutex01 "
        "btc 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
        "tg https://t.me/evil_channel "
        "discord discord.gg/abcd1234 "
        "cmdline powershell.exe -enc SQBFAFgA"
    )
    iocs = extract_iocs(text)
    by_type = {i.ioc_type.value for i in iocs}
    assert "ip_port" in by_type
    assert "filepath" in by_type
    assert "unc" in by_type
    assert "registry" in by_type
    assert "mutex" in by_type
    assert "bitcoin" in by_type
    assert "messenger" in by_type
    assert "command_line" in by_type


def test_mail_identity_and_raw_headers():
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    assert result.mail_identity is not None
    assert result.mail_identity.spf == "fail"
    assert "From" in result.raw_headers
    assert "Message-ID" in result.raw_headers


def test_filter_and_exports(tmp_path: Path):
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    filtered = filter_iocs(result, hide_rewriter=True)
    assert all("url_rewriter" not in i.tags for i in filtered)
    export_csv(result, tmp_path / "out.csv")
    export_report_json(result, tmp_path / "out.json")
    assert (tmp_path / "out.csv").stat().st_size > 0
    assert (tmp_path / "out.json").stat().st_size > 0


def test_merge_results():
    a = analyze_file(SAMPLES / "phishing_sample.eml")
    b = analyze_file(SAMPLES / "phishing_sample.eml")
    merged = merge_results([a, b])
    assert merged.source_kind == "batch"
    assert merged.verdict is not None
    assert len(merged.iocs) >= max(len(a.iocs), len(b.iocs))


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


def test_zip_inventory_double_ext():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("docs/invoice.pdf.exe", b"MZ")
        zf.writestr("readme.txt", b"hi")
    info = inspect_bytes("drop.zip", buf.getvalue())
    assert "archive" in info.risk_flags or "zip_container" in info.risk_flags
    assert info.archive_entries
    assert any("invoice.pdf.exe" in e for e in info.archive_entries)
    assert "archive_double_extension" in info.risk_flags


def _minimal_docx_bytes(paragraph: str, url: str | None = None) -> bytes:
    document = Element(
        "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}document"
    )
    body = SubElement(
        document, "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}body"
    )
    p = SubElement(body, "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p")
    r = SubElement(p, "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}r")
    t = SubElement(r, "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t")
    t.text = paragraph
    doc_xml = tostring(document, encoding="utf-8", xml_declaration=True)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            """<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>""",
        )
        zf.writestr("word/document.xml", doc_xml)
        if url:
            zf.writestr(
                "word/_rels/document.xml.rels",
                f"""<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
   Target="{url}" TargetMode="External"/>
</Relationships>""",
            )
    return buf.getvalue()


def test_docx_and_xlsx_extract(tmp_path: Path):
    """Office content is extracted as attachment evidence, not as top-level input."""
    docx_bytes = _minimal_docx_bytes(
        "Contact host evil-unique-tld.corp.phishing ASAP",
        url="https://payload.evil-unique-tld.corp.phishing/a",
    )
    text, errors = extract_office_text(docx_bytes, ".docx")
    assert isinstance(errors, list)
    blob = text
    assert "evil-unique-tld.corp.phishing" in blob or "payload.evil-unique-tld" in blob
    iocs = extract_iocs(blob)
    assert any("evil-unique-tld" in i.value for i in iocs)

    ss = """<?xml version="1.0"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1">
  <si><t>https://xlsx-ioc.example.phishing/path</t></si>
</sst>"""
    sheet = """<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData><row><c t="s"><v>0</v></c></row></sheetData>
</worksheet>"""
    xbuf = io.BytesIO()
    with zipfile.ZipFile(xbuf, "w") as zf:
        zf.writestr("xl/sharedStrings.xml", ss)
        zf.writestr("xl/worksheets/sheet1.xml", sheet)
    xtext, _ = extract_office_text(xbuf.getvalue(), ".xlsx")
    assert "xlsx-ioc.example.phishing" in xtext

    docx_path = tmp_path / "note.docx"
    docx_path.write_bytes(docx_bytes)
    rejected = analyze_file(docx_path)
    assert rejected.source_kind == "unknown"
    assert rejected.verdict is None
    assert any(".eml" in e or ".msg" in e for e in rejected.errors)


def test_zip_document_parse(tmp_path: Path):
    zpath = tmp_path / "case.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("malware.pdf.exe", b"MZ")
        zf.writestr("notes/url.txt", b"https://inside-zip.example.phishing/")
    data = buf.getvalue()
    zpath.write_bytes(data)
    info = inspect_bytes(zpath.name, data)
    assert "archive" in info.risk_flags or "zip_container" in info.risk_flags
    assert any("malware.pdf.exe" in e for e in (info.archive_entries or []))
    rejected = analyze_file(zpath)
    assert rejected.source_kind == "unknown"


def test_paths_app_dir():
    assert app_dir().is_dir()


def test_builtin_allowlist_tags_microsoft():
    domains, ips = build_allowlist()
    assert domain_matches("safelinks.protection.outlook.com", domains)
    assert "8.8.8.8" in ips
    iocs = [Ioc("login.microsoftonline.com", IocType.DOMAIN, tags=[])]
    tag_allowlist(iocs, domains, ips)
    assert "allowlisted" in iocs[0].tags


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
    assert any(h.name == "From" for h in result.headers)
    assert any(u.changed for u in result.url_rewrites)
    assert any("invoice.pdf.exe" in a.filename for a in result.attachments)


def test_export_csv_bom_and_json(tmp_path: Path):
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    csv_path = tmp_path / "out.csv"
    json_path = tmp_path / "out.json"
    export_csv(result, csv_path)
    export_report_json(result, json_path)
    raw = csv_path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    assert len(result.iocs) >= 1
    assert "verdict" in json_path.read_text(encoding="utf-8")


def test_verdict_no_analyst_actions():
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    assert result.verdict is not None
    assert result.verdict.actions == []
    assert len(result.iocs) >= 1


def test_verdict_only_for_email():
    junk = analyze_text("Host 1.2.3.4 https://evil.example.phishing/a")
    assert junk.source_kind == "unknown"
    assert junk.verdict is None
    assert junk.errors

    rfc = (
        "From: a@b.test\r\n"
        "Subject: urgent verify your account\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Click https://evil.example.phishing/login\r\n"
    )
    mail_paste = analyze_text(rfc)
    assert mail_paste.source_kind == "email"
    assert mail_paste.verdict is not None

    mail = analyze_file(SAMPLES / "phishing_sample.eml")
    assert mail.source_kind == "email"
    assert mail.verdict is not None


def test_verdict_config_builtin():
    cfg = load_verdict_config()
    assert isinstance(cfg, VerdictConfig)
    assert cfg.threshold_malicious == 60


def test_desired_result_tabs_verdict_first():
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    tabs = desired_result_tabs(result, filtered_count=len(result.iocs))
    assert tabs[0][0] == "mail"
    keys = [k for k, _ in tabs]
    assert "ioc" in keys
    compact = desired_result_tabs(result, filtered_count=len(result.iocs), compact=True)
    assert compact[0] == ("mail", "Вердикт")
    assert all(len(label) <= 18 for _, label in compact)


def test_export_actions_json_csv(tmp_path: Path):
    assert "JSON" in EXPORT_CHOICES and "CSV" in EXPORT_CHOICES
    assert "Тикет" in EXPORT_CHOICES
    assert "Batch CSV" in EXPORT_CHOICES
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    out = run_export("json", result, tmp_path / default_export_filename("json"))
    assert out.is_file()
    out2 = run_export("csv", result, tmp_path / default_export_filename("csv"))
    assert out2.is_file()


def test_prefs_roundtrip(tmp_path: Path, monkeypatch):
    from reliquary.core import prefs as prefs_mod

    monkeypatch.setattr(prefs_mod, "app_dir", lambda: tmp_path)
    assert save_prefs({"ui_scale": 1.25})
    data = load_prefs()
    assert data["ui_scale"] == 1.25
    assert (tmp_path / "ui_prefs.json").is_file()
    assert prefs_path() == tmp_path / "ui_prefs.json"


def test_render_verdict_with_custom_cfg():
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    soft = VerdictConfig(
        threshold_malicious=99,
        threshold_suspicious=98,
        threshold_unknown=97,
        weight_header_critical=1,
        weight_header_high=1,
        weight_header_medium=1,
        weight_header_low=0,
        weight_attachment_flag=1,
        weight_attachment_soft=0,
        weight_url_rewrite=0,
        weight_url_raw_ip=0,
        weight_suspicious_tld=0,
        weight_urgency=0,
        weight_links_and_attachments=0,
    )
    v = render_verdict(result, soft)
    assert v is not None
    assert v.score <= 100
