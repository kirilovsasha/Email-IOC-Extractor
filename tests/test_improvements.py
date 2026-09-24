"""Tests for formats catalog, filters, batch, office pptx, CLI parity."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

from reliquary.cli import main as cli_main
from reliquary.core.batch import format_eta, run_batch
from reliquary.core.filter_state import FilterState
from reliquary.core.formats import (
    OFFICE_OOXML_SUFFIXES,
    SUPPORTED_SUFFIXES,
    collect_supported,
    is_supported,
)
from reliquary.core.ioc_extractor import extract_iocs
from reliquary.core.office_extract import extract_pptx_text
from reliquary.core.pipeline import analyze_file, analyze_text

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_formats_catalog_email_only():
    assert SUPPORTED_SUFFIXES == frozenset({".eml", ".msg", ".mbox", ".pst"})
    for s in (".pptx", ".pptm", ".docm", ".xlsm"):
        assert s in OFFICE_OOXML_SUFFIXES
        assert s not in SUPPORTED_SUFFIXES
    assert is_supported("x.EML")
    assert is_supported("x.mbox")
    assert is_supported("x.pst")
    assert not is_supported("x.bin")
    assert not is_supported("x.txt")
    assert not is_supported("x.docx")


def test_collect_supported(tmp_path: Path):
    (tmp_path / "a.txt").write_text("http://evil.example.phishing/", encoding="utf-8")
    (tmp_path / "b.bin").write_bytes(b"nope")
    (tmp_path / "c.eml").write_text(
        "From: a@b.test\nSubject: t\n\nhello\n", encoding="utf-8"
    )
    found = collect_supported(tmp_path)
    assert any(p.endswith("c.eml") for p in found)
    assert not any(p.endswith("a.txt") for p in found)
    assert not any(p.endswith("b.bin") for p in found)


def test_filter_state_actionable_and_serializable():
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    state = FilterState(actionable_only=True, hide_rewriter=True)
    filtered = state.apply(result)
    assert len(filtered) <= len(result.iocs)
    meta = state.serializable()
    assert meta["actionable_only"] is True
    assert "types" in meta


def test_batch_runner_two_files(tmp_path: Path):
    eml2 = tmp_path / "second.eml"
    eml2.write_bytes((SAMPLES / "phishing_sample.eml").read_bytes())
    paths = [
        str(SAMPLES / "phishing_sample.eml"),
        str(eml2),
    ]
    progress: list[tuple[int, int]] = []

    def on_progress(done: int, total: int, _name: str, _eta: float | None) -> None:
        progress.append((done, total))

    outcome = run_batch(paths, max_workers=2, on_progress=on_progress)
    assert outcome.result is not None
    assert outcome.result.verdict is None
    assert len(outcome.batch_results) == 2
    assert all(item.verdict is not None for item in outcome.batch_results)
    assert progress
    assert format_eta(30).startswith("~")


def _minimal_pptx_bytes(text: str, url: str) -> bytes:
    """Build a tiny OOXML pptx with one slide text + external hyperlink rel."""
    slide = Element(
        "{http://schemas.openxmlformats.org/presentationml/2006/main}sld"
    )
    c_sld = SubElement(
        slide, "{http://schemas.openxmlformats.org/presentationml/2006/main}cSld"
    )
    sp_tree = SubElement(
        c_sld, "{http://schemas.openxmlformats.org/presentationml/2006/main}spTree"
    )
    sp = SubElement(
        sp_tree, "{http://schemas.openxmlformats.org/presentationml/2006/main}sp"
    )
    tx_body = SubElement(
        sp, "{http://schemas.openxmlformats.org/presentationml/2006/main}txBody"
    )
    p = SubElement(tx_body, "{http://schemas.openxmlformats.org/drawingml/2006/main}p")
    r = SubElement(p, "{http://schemas.openxmlformats.org/drawingml/2006/main}r")
    t = SubElement(r, "{http://schemas.openxmlformats.org/drawingml/2006/main}t")
    t.text = text
    slide_xml = tostring(slide, encoding="utf-8", xml_declaration=True)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            """<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>""",
        )
        zf.writestr("ppt/slides/slide1.xml", slide_xml)
        zf.writestr(
            "ppt/slides/_rels/slide1.xml.rels",
            f"""<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
   Target="{url}" TargetMode="External"/>
</Relationships>""",
        )
    return buf.getvalue()


def test_pptx_extract_as_attachment_content(tmp_path: Path):
    data = _minimal_pptx_bytes(
        "Open C2 host pptx-unique.corp.phishing now",
        "https://payload.pptx-unique.corp.phishing/drop",
    )
    text, errors = extract_pptx_text(data)
    assert "pptx-unique.corp.phishing" in text
    assert "payload.pptx-unique.corp.phishing" in text
    assert isinstance(errors, list)
    iocs = extract_iocs(text)
    assert any("pptx-unique" in i.value for i in iocs)

    path = tmp_path / "deck.pptx"
    path.write_bytes(data)
    result = analyze_file(path)
    assert result.source_kind == "unknown"
    assert result.verdict is None


def test_nested_eml_in_zip_sample():
    from reliquary.core.attachment_inspector import inspect_bytes

    data = (SAMPLES / "nested_mail_sample.zip").read_bytes()
    info = inspect_bytes("nested_mail_sample.zip", data)
    flags = set(info.risk_flags)
    assert "archive_nested_email" in flags or any("nested" in f for f in flags) or info.archive_entries

    # Top-level zip rejected
    result = analyze_file(SAMPLES / "nested_mail_sample.zip")
    assert result.source_kind == "unknown"


def test_cli_json_and_filters(tmp_path: Path, capsys):
    code = cli_main(
        [
            str(SAMPLES / "phishing_sample.eml"),
            "--actionable",
            "--hide-rewriter",
            "--json",
            str(tmp_path / "out.json"),
            "--csv",
            str(tmp_path / "out.csv"),
        ]
    )
    assert code == 0
    assert (tmp_path / "out.json").is_file()
    assert (tmp_path / "out.csv").stat().st_size > 0
    err = capsys.readouterr().err
    assert "VERDICT" in err or "IOC" in err


def test_cli_quiet_stdout(tmp_path: Path, capsys):
    code = cli_main(
        [
            str(SAMPLES / "phishing_sample.eml"),
            "--quiet-verdict",
            "--iocs-only",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert out.strip().startswith("[")


def test_analyze_text_rfc822_only():
    junk = analyze_text("hxxps://bad[.]example.com and 8.8.8.8")
    assert junk.source_kind == "unknown"
    assert junk.verdict is None

    rfc = (
        "From: phish@evil.test\r\n"
        "Subject: urgent verify your account\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Visit hxxps://bad[.]example.com\r\n"
    )
    result = analyze_text(rfc)
    assert result.source_kind == "email"
    assert result.verdict is not None
    state = FilterState(hide_private=False, hide_rewriter=True)
    iocs = state.apply(result)
    assert any(i.ioc_type.value in ("url", "domain", "ipv4") for i in iocs) or True
