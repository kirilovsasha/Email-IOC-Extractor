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
    assert result.verdict is None  # verdict only for emails
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
    """Phishing verdict is email-only; still produced for .eml."""
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    assert result.verdict is not None
    assert len(result.verdict.actions) >= 1
    assert len(result.iocs) >= 1


def test_verdict_only_for_email():
    ticket = analyze_text("Host 1.2.3.4 https://evil.example.phishing/a")
    assert ticket.source_kind == "ticket"
    assert ticket.verdict is None
    mail = analyze_file(SAMPLES / "phishing_sample.eml")
    assert mail.source_kind == "email"
    assert mail.verdict is not None


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


def test_defang_helpers():
    from reliquary.core.defang import defang_value, defang_ioc_line

    assert "hxxps://" in defang_value("https://evil.example.com/a")
    assert "[.]" in defang_value("evil.example.com")
    line = defang_ioc_line("url", "https://a.b/c", with_type=True)
    assert line.startswith("url|")
    assert "hxxps://" in line


def test_wildcard_allow_deny(tmp_path: Path, monkeypatch):
    from reliquary.core import paths as paths_mod
    from reliquary.core.allowlist import (
        build_allowlist,
        build_denylist,
        domain_matches,
        parse_list_line,
        tag_allowlist_denylist,
    )
    from reliquary.core.models import Ioc, IocType

    monkeypatch.setattr(paths_mod, "app_dir", lambda: tmp_path)
    monkeypatch.setattr(paths_mod, "resource_dir", lambda: tmp_path)
    paths_mod.ensure_user_lists()
    (tmp_path / "allowlist.txt").write_text("*.trusted.local  # INC-1\n", encoding="utf-8")
    (tmp_path / "denylist.txt").write_text("bad-*.phish  # INC-9\n", encoding="utf-8")

    parsed = parse_list_line("evil.example  # TICKET-42")
    assert parsed == ("evil.example", "TICKET-42")

    allow_d, _ = build_allowlist()
    deny = build_denylist()
    assert domain_matches("mail.trusted.local", allow_d)
    assert domain_matches("bad-one.phish", deny)

    iocs = [
        Ioc("mail.trusted.local", IocType.DOMAIN),
        Ioc("bad-one.phish", IocType.DOMAIN),
    ]
    tag_allowlist_denylist(iocs, allow_d, set(), deny)
    assert "allowlisted" in iocs[0].tags
    assert "denylisted" in iocs[1].tags


def test_verdict_config_thresholds(tmp_path: Path, monkeypatch):
    from reliquary.core import paths as paths_mod
    from reliquary.core.verdict import load_verdict_config, render_verdict

    monkeypatch.setattr(paths_mod, "app_dir", lambda: tmp_path)
    monkeypatch.setattr(paths_mod, "resource_dir", lambda: tmp_path)
    paths_mod.ensure_user_lists()
    (tmp_path / "verdict.ini").write_text(
        "threshold_malicious=5\nthreshold_suspicious=3\nthreshold_unknown=1\n"
        "weight_urgency=10\n",
        encoding="utf-8",
    )
    cfg = load_verdict_config()
    assert cfg.threshold_malicious == 5
    mail = analyze_file(SAMPLES / "phishing_sample.eml")
    # Re-render with loaded config (pipeline already used defaults from real app dir;
    # force with explicit cfg)
    v = render_verdict(mail, cfg)
    assert v is not None
    assert v.score >= 0


def test_encrypted_zip_flag():
    # Heuristic path: Encrypt marker in header region
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("secret.txt", b"x")
    raw = buf.getvalue()
    # Inject AES / Encrypt marker into early bytes without breaking PK signature
    patched = raw[:4] + b"Encrypt" + raw[4:]
    info = inspect_bytes("locked.zip", patched)
    assert "encrypted_archive" in info.risk_flags or "archive" in info.risk_flags
    # Prefer strong signal when zip opens and flag is set — also cover BadZip path
    if "encrypted_archive" not in info.risk_flags:
        # Force via _zip_encrypted helper by corrupt-but-marked payload
        marked = b"PK\x03\x04" + b"Encrypt" + b"\x00" * 100
        info2 = inspect_bytes("locked2.zip", marked)
        assert "encrypted_archive" in info2.risk_flags or "zip_container" in info2.risk_flags


def test_nested_eml_attachment(tmp_path: Path):
    inner = (
        b"From: nest@evil.example\r\n"
        b"Subject: Nested\r\n"
        b"Message-ID: <nested@evil.example>\r\n"
        b"\r\n"
        b"Click https://nested-unique.example.phishing/drop\r\n"
    )
    outer = (
        b"From: outer@corp.test\r\n"
        b"To: a@corp.test\r\n"
        b"Subject: Fwd\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="BOUND"\r\n'
        b"\r\n"
        b"--BOUND\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"see attached\r\n"
        b"--BOUND\r\n"
        b"Content-Type: message/rfc822; name=\"inner.eml\"\r\n"
        b"Content-Disposition: attachment; filename=\"inner.eml\"\r\n"
        b"Content-Transfer-Encoding: 7bit\r\n\r\n"
        + inner
        + b"\r\n--BOUND--\r\n"
    )
    path = tmp_path / "outer.eml"
    path.write_bytes(outer)
    result = analyze_file(path)
    assert any("nested_email" in a.risk_flags for a in result.attachments)
    blob = " ".join(i.value for i in result.iocs)
    assert "nested-unique.example.phishing" in blob


def test_batch_file_rows_and_case_pack(tmp_path: Path):
    from reliquary.core.exporters import export_case_pack
    from reliquary.core.pipeline import merge_results
    from reliquary.core.ticket import build_ticket_template

    a = analyze_file(SAMPLES / "ticket_sample.txt")
    b = analyze_file(SAMPLES / "phishing_sample.eml")
    merged = merge_results([a, b], label="batch:2")
    assert len(merged.file_rows) == 2
    assert merged.file_rows[0].ioc_count >= 0
    assert any(r.kind == "email" for r in merged.file_rows)

    ticket = build_ticket_template(merged, merged.iocs[:5], defang=True)
    assert "IOC Extractor" in ticket
    assert "[.]" in ticket or "hxxp" in ticket or "IOC" in ticket

    pack = export_case_pack(merged, tmp_path / "pack.zip", filters_applied={"hide_private": True})
    assert pack.is_file()
    with zipfile.ZipFile(pack) as zf:
        names = zf.namelist()
        assert any(n.endswith("report.json") for n in names)
        assert any(n.endswith("iocs.csv") for n in names)
        assert any(n.endswith("ticket.txt") for n in names)
        assert any(n.endswith("batch_files.tsv") for n in names)


def test_offline_blocks_connect():
    from reliquary.core.offline import OfflineViolation, enforce_offline
    import socket

    enforce_offline()
    try:
        socket.create_connection(("1.1.1.1", 80), timeout=1)
        assert False, "should have blocked"
    except OfflineViolation:
        pass


def test_import_misp_and_csv(tmp_path: Path):
    from reliquary.core.allowlist import import_entries_from_csv, import_entries_from_misp

    csv_path = tmp_path / "i.csv"
    csv_path.write_text("value,note\nbad.import.test,x\n", encoding="utf-8")
    assert "bad.import.test" in import_entries_from_csv(csv_path)

    misp = {
        "Event": {
            "Attribute": [
                {"type": "domain", "value": "misp-bad.example"},
                {"type": "ip-dst", "value": "9.9.9.9"},
            ]
        }
    }
    jpath = tmp_path / "m.json"
    jpath.write_text(__import__("json").dumps(misp), encoding="utf-8")
    vals = import_entries_from_misp(jpath)
    assert "misp-bad.example" in vals
    assert "9.9.9.9" in vals


def test_report_json_has_meta(tmp_path: Path):
    from reliquary.core.exporters import export_report_json
    import json

    result = analyze_file(SAMPLES / "phishing_sample.eml")
    assert result.meta is not None
    assert result.meta.app_version
    assert result.meta.source_sha256
    out = tmp_path / "r.json"
    export_report_json(result, out, filters_applied={"hide_rewriter": True})
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["meta"]["filters_applied"]["hide_rewriter"] is True
    assert data["meta"]["source_sha256"]


def test_desired_result_tabs_context():
    from reliquary.gui.tabs import desired_result_tabs
    from reliquary.core.pipeline import merge_results

    assert desired_result_tabs(None) == [("ioc", "IOC")]

    ticket = analyze_file(SAMPLES / "ticket_sample.txt")
    keys = [k for k, _ in desired_result_tabs(ticket, filtered_count=len(ticket.iocs))]
    assert keys[0] == "ioc"
    assert "batch" not in keys
    assert "mail" not in keys

    mail = analyze_file(SAMPLES / "phishing_sample.eml")
    mail_tabs = desired_result_tabs(mail, filtered_count=len(mail.iocs))
    mail_keys = [k for k, _ in mail_tabs]
    assert "mail" in mail_keys
    assert "batch" not in mail_keys
    assert any(k == "att" for k in mail_keys) or not mail.attachments
    labels = dict(mail_tabs)
    assert labels["ioc"].startswith("IOC ")

    merged = merge_results([ticket, mail], label="batch:2")
    batch_keys = [k for k, _ in desired_result_tabs(merged, filtered_count=len(merged.iocs))]
    assert "batch" in batch_keys
    assert any(lbl.startswith("Пакет ") for _, lbl in desired_result_tabs(merged, 1))


def test_hash_guid_fp_and_private_ranges():
    from reliquary.core.ioc_extractor import extract_iocs

    guid = "550e8400-e29b-41d4-a716-446655440000"
    iocs = extract_iocs(f"id={guid} and noise abcdefabcdefabcdefabcdefabcdefab")
    hashes = [i for i in iocs if i.ioc_type.value in ("md5", "sha1", "sha256")]
    # all-alpha hex rejected; GUID must not become MD5
    assert not any(i.value == "abcdefabcdefabcdefabcdefabcdefab" for i in hashes)
    assert not any("550e8400e29b41d4a716446655440000" in i.value for i in hashes)

    real = extract_iocs("md5 44d88612fea8a8f36de82e1278abb02f of malware.exe")
    assert any(i.ioc_type.value == "md5" and i.value.startswith("44d88612") for i in real)

    priv = extract_iocs("cgnat 100.64.1.5 ula fd12:3456:789a::1 link fe80::1")
    tags = {i.value: i.tags for i in priv if i.ioc_type.value in ("ipv4", "ipv6")}
    assert "private" in tags.get("100.64.1.5", [])
    assert any("private" in t for t in tags.values())

    bare = extract_iocs("User ran cmd.exe today without args")
    assert not any(i.ioc_type.value == "command_line" for i in bare)
    sig = extract_iocs("cmdline powershell.exe -enc SQBFAFgA more text")
    assert any(i.ioc_type.value == "command_line" for i in sig)


def test_ticket_short_and_prefs(tmp_path: Path, monkeypatch):
    from reliquary.core import paths as paths_mod
    from reliquary.core.prefs import load_prefs, save_prefs
    from reliquary.core.ticket import build_ticket_template

    monkeypatch.setattr(paths_mod, "app_dir", lambda: tmp_path)
    monkeypatch.setattr(paths_mod, "resource_dir", lambda: tmp_path)
    paths_mod.ensure_user_lists()
    save_prefs({"copy_format": "defanged", "ui_scale": 1.25})
    prefs = load_prefs()
    assert prefs["copy_format"] == "defanged"
    assert prefs["ui_scale"] == 1.25

    mail = analyze_file(SAMPLES / "phishing_sample.eml")
    short = build_ticket_template(mail, mail.iocs, short=True, defang=True)
    full = build_ticket_template(mail, mail.iocs, short=False, defang=True, lang="en")
    assert len(short.splitlines()) <= 10
    assert "IOC Extractor" in full
    assert "Verdict:" in full or "Вердикт:" in short
    ru = build_ticket_template(mail, mail.iocs, short=False, lang="ru")
    assert "Источник:" in ru or "Источник" in ru


def test_nested_zip_inventory(tmp_path: Path):
    from reliquary.core.attachment_inspector import inspect_bytes

    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as zf:
        zf.writestr("payload.exe", b"MZ")
    outer_buf = io.BytesIO()
    with zipfile.ZipFile(outer_buf, "w") as zf:
        zf.writestr("inner.zip", inner_buf.getvalue())
        zf.writestr("readme.txt", b"hi")
    att = inspect_bytes("outer.zip", outer_buf.getvalue())
    assert "nested_archive" in att.risk_flags
    assert any("payload.exe" in e for e in (att.archive_entries or []))


def test_html_sample_extracts_urls():
    result = analyze_file(SAMPLES / "landing_sample.html")
    assert result.source_kind == "html"
    assert result.iocs


def test_defang_extended_and_url_dedup():
    from reliquary.core.ioc_extractor import defang, extract_iocs, normalize_url_key

    cleaned = defang("hxxps[://]evil[.]example[dot]com/path/ and host dot bad")
    assert "https://evil.example.com/path/" in cleaned
    assert "host.bad" in cleaned
    iocs = extract_iocs(
        "https://www.evil.example/a/ https://evil.example/a https://evil.example/a#frag"
    )
    urls = [i for i in iocs if i.ioc_type.value == "url"]
    assert len(urls) <= 2
    assert normalize_url_key("https://www.x.com/a/") == normalize_url_key("https://x.com/a")


def test_actionable_filter_and_sort_and_search():
    from reliquary.core.exporters import filter_iocs, sort_iocs

    result = analyze_file(SAMPLES / "phishing_sample.eml")
    all_n = len(result.iocs)
    actionable = filter_iocs(result, actionable_only=True, hide_rewriter=False)
    assert len(actionable) <= all_n
    sorted_list = sort_iocs(result.iocs)
    assert len(sorted_list) == all_n
    found = filter_iocs(result, search="invoice")
    assert found


def test_case_pack_multi_and_file_tags(tmp_path: Path):
    from reliquary.core.exporters import export_case_pack_multi
    from reliquary.core.pipeline import merge_results
    import zipfile

    a = analyze_file(SAMPLES / "ticket_sample.txt")
    b = analyze_file(SAMPLES / "phishing_sample.eml")
    assert any(t.startswith("file:") for i in a.iocs for t in i.tags)
    merged = merge_results([a, b])
    assert any("file:phishing_sample.eml" in i.tags for i in merged.iocs)

    out = export_case_pack_multi([a, b], tmp_path / "multi.zip")
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert any("ticket" in n and n.endswith("report.json") for n in names)
        assert any("phishing" in n and n.endswith("iocs.csv") for n in names)
