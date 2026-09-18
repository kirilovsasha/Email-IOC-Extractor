"""Extract text from Office Open XML (.docx / .xlsx) offline via zip + XML."""

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


def _hyperlinks_from_docx(zf: zipfile.ZipFile) -> list[str]:
    urls: list[str] = []
    # document.xml.rels
    rels_name = "word/_rels/document.xml.rels"
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


def extract_docx_text(data: bytes) -> tuple[str, list[str]]:
    """Return (text, errors)."""
    errors: list[str] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        return "", [f"docx: не ZIP/OOXML ({exc})"]
    parts: list[str] = []
    try:
        xml = zf.read("word/document.xml")
        root = ET.fromstring(xml)
        # Prefer paragraph breaks
        for p in root.iter():
            if _local(p.tag) == "p":
                runs = _collect_text_nodes(p, "t")
                if runs:
                    parts.append("".join(runs))
        if not parts:
            parts = _collect_text_nodes(root, "t")
        urls = _hyperlinks_from_docx(zf)
        if urls:
            parts.append("")
            parts.append("URLs:")
            parts.extend(urls)
    except KeyError:
        errors.append("docx: нет word/document.xml")
    except ET.ParseError as exc:
        errors.append(f"docx XML: {exc}")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"docx: {exc}")
    finally:
        zf.close()
    return "\n".join(parts), errors


def extract_xlsx_text(data: bytes) -> tuple[str, list[str]]:
    """Return shared strings + inline cell values and sheet hyperlinks."""
    errors: list[str] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        return "", [f"xlsx: не ZIP/OOXML ({exc})"]

    shared: list[str] = []
    parts: list[str] = []
    urls: list[str] = []
    try:
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
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{sheet}: {exc}")
                continue
            for el in root.iter():
                tag = _local(el.tag)
                if tag == "v" and el.text:
                    # shared string index or raw value
                    if el.text.isdigit() and int(el.text) < len(shared):
                        # only add when parent type is shared string — heuristic: always resolve if in range
                        pass
                    parts.append(el.text)
                if tag == "t" and el.text:
                    parts.append(el.text)
                if tag == "hyperlink":
                    ref = el.attrib.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id")
                    target = el.attrib.get("display") or ""
                    if target.startswith("http"):
                        urls.append(target)
            # relationships for this sheet
            rels = sheet.replace("worksheets/", "worksheets/_rels/") + ".rels"
            if rels in zf.namelist():
                try:
                    rel_root = ET.fromstring(zf.read(rels))
                    for rel in rel_root.iter():
                        if _local(rel.tag) != "Relationship":
                            continue
                        target = rel.attrib.get("Target") or ""
                        mode = rel.attrib.get("TargetMode") or ""
                        if mode.lower() == "external" and target:
                            urls.append(target)
                except Exception:
                    pass

        # Prefer shared strings as readable text
        text_chunks = [s for s in shared if s and s.strip()]
        text_chunks.extend(p for p in parts if p and not p.isdigit())
        if urls:
            text_chunks.append("")
            text_chunks.append("URLs:")
            text_chunks.extend(dict.fromkeys(urls))  # dedupe preserve order
        return "\n".join(text_chunks), errors
    except Exception as exc:  # noqa: BLE001
        errors.append(f"xlsx: {exc}")
        return "", errors
    finally:
        zf.close()


_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def clean_extracted(text: str) -> str:
    return _CTRL_RE.sub(" ", text)
