"""Unit tests for IOC Extractor core — no network."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

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
    from reliquary.core.exporters import (
        export_misp,
        export_opencti,
        export_yara,
        filter_iocs,
    )

    result = analyze_file(SAMPLES / "phishing_sample.eml")
    filtered = filter_iocs(result, hide_rewriter=True)
    assert all("url_rewriter" not in i.tags for i in filtered)
    export_misp(result, tmp_path / "misp.json")
    export_opencti(result, tmp_path / "octi.json")
    yar = tmp_path / "iocs.yar"
    export_yara(result, yar)
    text = yar.read_text(encoding="utf-8")
    assert "rule " in text
    assert "condition:" in text
    assert (tmp_path / "misp.json").stat().st_size > 0


def test_merge_results():
    from reliquary.core.pipeline import merge_results

    a = analyze_file(SAMPLES / "ticket_sample.txt")
    b = analyze_file(SAMPLES / "phishing_sample.eml")
    merged = merge_results([a, b])
    assert merged.source_kind == "batch"
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
    docx_path = tmp_path / "note.docx"
    docx_path.write_bytes(
        _minimal_docx_bytes(
            "Contact host evil-unique-tld.corp.phishing ASAP",
            url="https://payload.evil-unique-tld.corp.phishing/a",
        )
    )
    result = analyze_file(docx_path)
    assert result.source_kind == "office"
    blob = " ".join(i.value for i in result.iocs)
    assert "evil-unique-tld.corp.phishing" in blob or "payload.evil-unique-tld" in blob

    # xlsx via sharedStrings
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
    xlsx_path = tmp_path / "sheet.xlsx"
    xlsx_path.write_bytes(xbuf.getvalue())
    xresult = analyze_file(xlsx_path)
    assert xresult.source_kind == "office"
    assert any("xlsx-ioc.example.phishing" in i.value for i in xresult.iocs)


def test_zip_document_parse(tmp_path: Path):
    zpath = tmp_path / "case.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("malware.pdf.exe", b"MZ")
        zf.writestr("notes/url.txt", b"https://inside-zip.example.phishing/")
    zpath.write_bytes(buf.getvalue())
    result = analyze_file(zpath)
    assert result.source_kind == "archive"
    names = {i.value for i in result.iocs if i.ioc_type.value == "filename"}
    assert any("malware.pdf.exe" in n for n in names)


def test_paths_app_dir_and_lists(tmp_path: Path, monkeypatch):
    from reliquary.core import paths as paths_mod
    from reliquary.core.allowlist import load_list_file

    monkeypatch.setattr(paths_mod, "app_dir", lambda: tmp_path)
    monkeypatch.setattr(paths_mod, "resource_dir", lambda: tmp_path)
    paths_mod.ensure_user_lists()
    assert (tmp_path / "allowlist.txt").is_file()
    assert (tmp_path / "denylist.txt").is_file()
    (tmp_path / "denylist.txt").write_text("bad.denylist.test\n", encoding="utf-8")
    assert "bad.denylist.test" in load_list_file("denylist.txt")


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
    assert any(h.name == "From" for h in result.headers)
    assert any(h.name in ("Subject", "Message-ID", "Date") for h in result.headers)
    assert any(u.changed for u in result.url_rewrites)
    assert any("invoice.pdf.exe" in a.filename for a in result.attachments)


def test_export_csv_bom_and_stix(tmp_path: Path):
    result = analyze_text("Host 8.8.8.8 and https://example.org/a md5 44d88612fea8a8f36de82e1278abb02f")
    csv_path = tmp_path / "out.csv"
    stix_path = tmp_path / "out.json"
    export_csv(result, csv_path)
    export_stix(result, stix_path)
    raw = csv_path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")  # UTF-8 BOM for Excel
    assert "ipv4" in raw.decode("utf-8-sig")
    data = stix_path.read_text(encoding="utf-8")
    assert "indicator" in data.lower() or "bundle" in data.lower()


def test_verdict_actions_present():
    """Phishing verdict is optional add-on; still produced for emails."""
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    assert result.verdict is not None
    assert len(result.verdict.actions) >= 1
    assert len(result.iocs) >= 1


def test_cli_defaults_to_ioc_list(capsys):
    from reliquary.cli import main

    code = main([str(SAMPLES / "ticket_sample.txt")])
    assert code == 0
    out = capsys.readouterr().out
    assert "ioc_type" in out or "sha256" in out.lower() or "domain" in out


def test_cli_yara_export(tmp_path: Path):
    from reliquary.cli import main

    out = tmp_path / "r.yar"
    code = main([str(SAMPLES / "ticket_sample.txt"), "--yara", str(out)])
    assert code == 0
    assert out.is_file()
    assert "rule " in out.read_text(encoding="utf-8")
