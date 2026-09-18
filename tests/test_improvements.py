"""Tests for formats catalog, filters, batch, office pptx, CLI parity."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

from reliquary.core.batch import format_eta, run_batch
from reliquary.core.filter_state import FilterState
from reliquary.core.formats import (
    OFFICE_OOXML_SUFFIXES,
    SUPPORTED_SUFFIXES,
    collect_supported,
    is_supported,
)
from reliquary.core.office_extract import extract_pptx_text
from reliquary.core.pipeline import analyze_file, analyze_text
from reliquary.cli import main as cli_main

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_formats_catalog_covers_office_macros():
    for s in (".pptx", ".pptm", ".docm", ".xlsm"):
        assert s in SUPPORTED_SUFFIXES
        assert s in OFFICE_OOXML_SUFFIXES
    assert is_supported("x.EML")
    assert not is_supported("x.bin")


def test_collect_supported(tmp_path: Path):
    (tmp_path / "a.txt").write_text("http://evil.example.phishing/", encoding="utf-8")
    (tmp_path / "b.bin").write_bytes(b"nope")
    found = collect_supported(tmp_path)
    assert any(p.endswith("a.txt") for p in found)
    assert not any(p.endswith("b.bin") for p in found)


def test_filter_state_actionable_and_serializable():
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    state = FilterState(actionable_only=True, hide_rewriter=True)
    filtered = state.apply(result)
    assert len(filtered) <= len(result.iocs)
    meta = state.serializable()
    assert meta["actionable_only"] is True
    assert "types" in meta


def test_batch_runner_two_files():
    paths = [
        str(SAMPLES / "ticket_sample.txt"),
        str(SAMPLES / "phishing_sample.eml"),
    ]
    progress: list[tuple[int, int]] = []

    def on_progress(done: int, total: int, _name: str, _eta: float | None) -> None:
        progress.append((done, total))

    outcome = run_batch(paths, max_workers=2, on_progress=on_progress)
    assert outcome.result is not None
    assert len(outcome.batch_results) == 2
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
    tx = SubElement(
        sp, "{http://schemas.openxmlformats.org/presentationml/2006/main}txBody"
    )
    p = SubElement(tx, "{http://schemas.openxmlformats.org/drawingml/2006/main}p")
    r = SubElement(p, "{http://schemas.openxmlformats.org/drawingml/2006/main}r")
    t = SubElement(r, "{http://schemas.openxmlformats.org/drawingml/2006/main}t")
    t.text = text
    slide_xml = tostring(slide, encoding="utf-8", xml_declaration=True)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>',
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


def test_pptx_extract_and_analyze(tmp_path: Path):
    data = _minimal_pptx_bytes(
        "Open C2 host pptx-unique.corp.phishing now",
        "https://payload.pptx-unique.corp.phishing/drop",
    )
    text, errors = extract_pptx_text(data)
    assert "pptx-unique.corp.phishing" in text
    assert "payload.pptx-unique.corp.phishing" in text
    assert isinstance(errors, list)

    path = tmp_path / "deck.pptx"
    path.write_bytes(data)
    result = analyze_file(path)
    assert result.source_kind == "office"
    blob = " ".join(i.value for i in result.iocs)
    assert "pptx-unique" in blob or "payload.pptx-unique" in blob


def test_nested_eml_in_zip_sample():
    result = analyze_file(SAMPLES / "nested_mail_sample.zip")
    assert result.source_kind == "archive"
    assert result.attachments
    flags = set()
    for att in result.attachments:
        flags.update(att.risk_flags)
    assert "archive_nested_email" in flags or any(
        "nested" in f for f in flags
    ) or result.iocs


def test_cli_ticket_and_filters(tmp_path: Path, capsys):
    out = tmp_path / "ticket.txt"
    code = cli_main(
        [
            str(SAMPLES / "ticket_sample.txt"),
            "--actionable",
            "--hide-rewriter",
            "--ticket",
            str(out),
            "--csv",
            str(tmp_path / "out.csv"),
        ]
    )
    assert code == 0
    assert out.is_file()
    assert (tmp_path / "out.csv").stat().st_size > 0
    err = capsys.readouterr().err
    assert "IOC извлечено" in err


def test_cli_case_pack(tmp_path: Path):
    pack = tmp_path / "case.zip"
    code = cli_main(
        [
            str(SAMPLES / "phishing_sample.eml"),
            "--case-pack",
            str(pack),
            "--hide-allowlisted",
        ]
    )
    assert code == 0
    assert pack.is_file()
    assert zipfile.is_zipfile(pack)


def test_analyze_text_filter_chain():
    result = analyze_text("hxxps://bad[.]example.com and 8.8.8.8")
    state = FilterState(hide_private=False, hide_rewriter=True)
    iocs = state.apply(result)
    assert any(i.ioc_type.value in ("url", "domain", "ipv4") for i in iocs)
