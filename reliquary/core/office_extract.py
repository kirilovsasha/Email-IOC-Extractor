"""Extract text from Office Open XML (.docx/.xlsx/.pptx + macro variants) offline."""

from __future__ import annotations

import io
import re
import zipfile
from xml.etree import ElementTree as ET

_W_NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
_A_NS = {"a": "http://schemas.openxmlformats.org/drawingml/2006/main"}
_R_NS = {
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "pr": "http://schemas.openxmlformats.org/package/2006/relationships",
}


def _local(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _collect_text_nodes(root: ET.Element, text_local: str = "t") -> list[str]:
    parts: list[str] = []
    for el in root.iter():
        if _local(el.tag) == text_local and el.text:
            parts.append(el.text)
        if el.tail and el.tail.strip():
            parts.append(el.tail)
    return parts


def _external_targets_from_rels(zf: zipfile.ZipFile, rels_name: str) -> list[str]:
    urls: list[str] = []
    try:
        rels_xml = zf.read(rels_name)
    except KeyError:
        return urls
    try:
        root = ET.fromstring(rels_xml)
    except ET.ParseError:
        return urls
    for el in root.iter():
        if _local(el.tag) != "Relationship":
            continue
        target = el.attrib.get("Target") or ""
        mode = el.attrib.get("TargetMode") or ""
        if mode.lower() == "external" and target:
            urls.append(target)
        elif target.startswith("http://") or target.startswith("https://"):
            urls.append(target)
    return urls


def _hyperlinks_from_docx(zf: zipfile.ZipFile) -> list[str]:
    return _external_targets_from_rels(zf, "word/_rels/document.xml.rels")


def _ooxml_vba_notes(zf: zipfile.ZipFile) -> list[str]:
    names = set(zf.namelist())
    notes: list[str] = []
    if any("vbaProject.bin" in n for n in names):
        notes.append("OOXML: найден vbaProject.bin (макросы)")
    if any(n.lower().endswith("vbaData.xml") for n in names):
        notes.append("OOXML: присутствует vbaData.xml")
    return notes


def extract_docx_text(data: bytes) -> tuple[str, list[str]]:
    """Return (text, errors). Works for .docx and .docm."""
    errors: list[str] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        return "", [f"docx: не ZIP/OOXML ({exc})"]
    parts: list[str] = []
    try:
        errors.extend(_ooxml_vba_notes(zf))
        # Main document + headers/footers (often phishing links)
        xml_parts = ["word/document.xml"]
        xml_parts.extend(
            n
            for n in zf.namelist()
            if n.startswith("word/header") or n.startswith("word/footer")
        )
        for name in xml_parts:
            if name not in zf.namelist():
                continue
            try:
                root = ET.fromstring(zf.read(name))
            except ET.ParseError as exc:
                errors.append(f"{name}: {exc}")
                continue
            for p in root.iter():
                if _local(p.tag) == "p":
                    runs = _collect_text_nodes(p, "t")
                    if runs:
                        parts.append("".join(runs))
        if not parts:
            try:
                root = ET.fromstring(zf.read("word/document.xml"))
                parts = _collect_text_nodes(root, "t")
            except KeyError:
                errors.append("docx: нет word/document.xml")
        urls = _hyperlinks_from_docx(zf)
        # also scan other word/_rels
        for rels in zf.namelist():
            if rels.startswith("word/_rels/") and rels.endswith(".rels"):
                urls.extend(_external_targets_from_rels(zf, rels))
        if urls:
            parts.append("")
            parts.append("URLs:")
            parts.extend(dict.fromkeys(urls))
    except KeyError:
        errors.append("docx: нет word/document.xml")
    except ET.ParseError as exc:
        errors.append(f"docx XML: {type(exc).__name__}: {exc}")
    except (OSError, UnicodeDecodeError, ValueError, RuntimeError) as exc:
        errors.append(f"docx ({type(exc).__name__}): {exc}")
    finally:
        zf.close()
    return "\n".join(parts), errors


def extract_xlsx_text(data: bytes) -> tuple[str, list[str]]:
    """Return shared strings + inline cell values and sheet hyperlinks (.xlsx/.xlsm)."""
    errors: list[str] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        return "", [f"xlsx: не ZIP/OOXML ({exc})"]

    shared: list[str] = []
    parts: list[str] = []
    urls: list[str] = []
    try:
        errors.extend(_ooxml_vba_notes(zf))
        if "xl/sharedStrings.xml" in zf.namelist():
            root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
            for si in root.iter():
                if _local(si.tag) == "si":
                    shared.append("".join(_collect_text_nodes(si, "t")))

        sheet_names = [
            n for n in zf.namelist() if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")
        ]
        for sheet in sorted(sheet_names)[:20]:
            try:
                root = ET.fromstring(zf.read(sheet))
            except (ET.ParseError, KeyError, OSError) as exc:
                errors.append(f"{sheet} ({type(exc).__name__}): {exc}")
                continue
            for el in root.iter():
                tag = _local(el.tag)
                if tag == "v" and el.text:
                    parts.append(el.text)
                if tag == "t" and el.text:
                    parts.append(el.text)
                if tag == "hyperlink":
                    target = el.attrib.get("display") or ""
                    if target.startswith("http"):
                        urls.append(target)
            rels = sheet.replace("worksheets/", "worksheets/_rels/") + ".rels"
            if rels in zf.namelist():
                try:
                    urls.extend(_external_targets_from_rels(zf, rels))
                except (OSError, KeyError, ET.ParseError) as exc:
                    errors.append(f"{rels} ({type(exc).__name__}): {exc}")

        if "xl/_rels/workbook.xml.rels" in zf.namelist():
            urls.extend(_external_targets_from_rels(zf, "xl/_rels/workbook.xml.rels"))

        text_chunks = [s for s in shared if s and s.strip()]
        text_chunks.extend(p for p in parts if p and not p.isdigit())
        if urls:
            text_chunks.append("")
            text_chunks.append("URLs:")
            text_chunks.extend(dict.fromkeys(urls))
        return "\n".join(text_chunks), errors
    except (ET.ParseError, KeyError, OSError, UnicodeDecodeError, ValueError, RuntimeError) as exc:
        errors.append(f"xlsx ({type(exc).__name__}): {exc}")
        return "", errors
    finally:
        zf.close()


def extract_pptx_text(data: bytes) -> tuple[str, list[str]]:
    """Slides + notes + hyperlinks from .pptx / .pptm."""
    errors: list[str] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        return "", [f"pptx: не ZIP/OOXML ({exc})"]

    parts: list[str] = []
    urls: list[str] = []
    try:
        errors.extend(_ooxml_vba_notes(zf))
        names = zf.namelist()
        slide_files = sorted(
            n
            for n in names
            if n.startswith("ppt/slides/slide") and n.endswith(".xml") and "/_rels/" not in n
        )
        notes_files = sorted(
            n
            for n in names
            if n.startswith("ppt/notesSlides/notesSlide") and n.endswith(".xml") and "/_rels/" not in n
        )
        for slide in slide_files[:40]:
            try:
                root = ET.fromstring(zf.read(slide))
            except (ET.ParseError, KeyError, OSError) as exc:
                errors.append(f"{slide} ({type(exc).__name__}): {exc}")
                continue
            texts = _collect_text_nodes(root, "t")
            if texts:
                parts.append(" ".join(texts))
            for el in root.iter():
                href = el.attrib.get(
                    "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
                )
                if href and href.startswith("http"):
                    urls.append(href)
            rels = slide.replace("slides/", "slides/_rels/") + ".rels"
            if rels in names:
                try:
                    urls.extend(_external_targets_from_rels(zf, rels))
                except (OSError, KeyError, ET.ParseError) as exc:
                    errors.append(f"{rels} ({type(exc).__name__}): {exc}")

        for notes in notes_files[:40]:
            try:
                root = ET.fromstring(zf.read(notes))
                texts = _collect_text_nodes(root, "t")
                if texts:
                    parts.append(" ".join(texts))
            except (ET.ParseError, KeyError, OSError) as exc:
                errors.append(f"{notes} ({type(exc).__name__}): {exc}")

        if not slide_files:
            errors.append("pptx: слайды не найдены")

        if urls:
            parts.append("")
            parts.append("URLs:")
            parts.extend(dict.fromkeys(urls))
        return "\n".join(parts), errors
    except (ET.ParseError, KeyError, OSError, UnicodeDecodeError, ValueError, RuntimeError) as exc:
        errors.append(f"pptx ({type(exc).__name__}): {exc}")
        return "", errors
    finally:
        zf.close()


def extract_office_text(data: bytes, suffix: str) -> tuple[str, list[str]]:
    """Dispatch by file suffix (.docx/.docm/.xlsx/.xlsm/.pptx/.pptm)."""
    s = suffix.lower()
    if not s.startswith("."):
        s = f".{s}"
    if s in {".docx", ".docm"}:
        return extract_docx_text(data)
    if s in {".xlsx", ".xlsm"}:
        return extract_xlsx_text(data)
    if s in {".pptx", ".pptm"}:
        return extract_pptx_text(data)
    return "", [f"office: неподдерживаемый суффикс {suffix}"]


def extract_office_urls(data: bytes, suffix: str) -> list[str]:
    """Return external hyperlinks from OOXML (rels + inline) for first-class IOC evidence."""
    text, _errs = extract_office_text(data, suffix)
    urls: list[str] = []
    if not text:
        return urls
    capture = False
    for line in text.splitlines():
        if line.strip() == "URLs:":
            capture = True
            continue
        if capture:
            val = line.strip()
            if not val:
                continue
            if val.startswith(("http://", "https://", "mailto:")):
                urls.append(val)
            elif "://" in val:
                urls.append(val)
    # Dedup preserve order
    return list(dict.fromkeys(urls))


_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def clean_extracted(text: str) -> str:
    return _CTRL_RE.sub(" ", text)
