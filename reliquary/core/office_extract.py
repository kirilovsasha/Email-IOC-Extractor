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


def detect_office_remote_template(data: bytes) -> bool:
    """True if OOXML has remote template / attachedTemplate External http(s).

    Matches TargetMode=External http(s) on template-like relationships, or
    settings.xml attachedTemplate with External http(s) target.
    Plain hyperlinks (Type …/hyperlink) are handled by office_hyperlink instead.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return False
    try:
        names = set(zf.namelist())
        if "word/settings.xml" in names:
            try:
                raw = zf.read("word/settings.xml")
            except KeyError:
                raw = b""
            if b"attachedTemplate" in raw or b"AttachedTemplate" in raw:
                rels = "word/_rels/settings.xml.rels"
                if rels in names:
                    urls = _external_targets_from_rels(zf, rels)
                    if any(u.lower().startswith(("http://", "https://")) for u in urls):
                        return True
                if re.search(rb"(?i)Target\s*=\s*[\"']https?://", raw):
                    return True

        for rels in names:
            if not rels.endswith(".rels"):
                continue
            try:
                root = ET.fromstring(zf.read(rels))
            except (ET.ParseError, KeyError, OSError):
                continue
            for el in root.iter():
                if _local(el.tag) != "Relationship":
                    continue
                mode = (el.attrib.get("TargetMode") or "").lower()
                target = (el.attrib.get("Target") or "").lower()
                rel_type = (el.attrib.get("Type") or "").lower()
                if not (mode == "external" and target.startswith(("http://", "https://"))):
                    continue
                if any(
                    key in rel_type
                    for key in ("template", "attachedtemplate", "oleobject", "subdocument")
                ):
                    return True
                # settings.xml.rels External http is always remote-template surface
                if "settings.xml.rels" in rels.replace("\\", "/").lower():
                    return True
        return False
    finally:
        zf.close()


_DDE_RE = re.compile(
    rb"(?i)(DDEAUTO|DDE\s*\(|cmd\s*\||=cmd\||MSEXCEL\||"
    rb"=\s*CMD\s*\||CreateObject\s*\(\s*[\"']WScript|"
    rb"Shell\s*\(|powershell|mshta\.exe)"
)


def detect_office_dde(data: bytes) -> bool:
    """True if OOXML xlsx/xlsm (or zip) contains DDE / formula-injection markers."""
    if not data or data[:2] != b"PK":
        # Also catch plain OLE / XML fragments
        return bool(_DDE_RE.search(data[: min(len(data), 512 * 1024)]))
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return bool(_DDE_RE.search(data[: min(len(data), 256 * 1024)]))
    try:
        names = zf.namelist()
        targets = [
            n
            for n in names
            if n.endswith((".xml", ".rels"))
            and (
                "sharedStrings" in n
                or n.startswith("xl/worksheets/")
                or "workbook" in n
                or n.startswith("word/")
            )
        ]
        for name in targets[:40]:
            try:
                chunk = zf.read(name)
            except KeyError:
                continue
            if _DDE_RE.search(chunk):
                return True
        return False
    finally:
        zf.close()


_FORMULA_EXTERNAL_RE = re.compile(
    rb"(?i)(WEBSERVICE\s*\(|HYPERLINK\s*\(\s*[\"']https?://)"
)


def detect_office_external_data(data: bytes) -> bool:
    """Workbook connections, externalLinks, or WEBSERVICE/HYPERLINK formulas.

    Plain document hyperlinks stay on the office_hyperlink flag.
    """
    if not data or data[:2] != b"PK":
        return False
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return False
    try:
        names = [n.replace("\\", "/") for n in zf.namelist()]
        if any("xl/externallinks/" in n.lower() for n in names):
            return True
        checked = 0
        for name in names:
            low = name.lower()
            interesting = low.endswith("connections.xml") or (
                low.startswith("xl/") and low.endswith(".xml")
            )
            if not interesting:
                continue
            checked += 1
            if checked > 40:
                break
            try:
                chunk = zf.read(name)
            except KeyError:
                continue
            if low.endswith("connections.xml") and re.search(rb"(?i)https?://|\\\\", chunk):
                return True
            if _FORMULA_EXTERNAL_RE.search(chunk):
                return True
        return False
    finally:
        zf.close()


# Autostart or download/exec inside VBA. Bare CreateObject is too common in
# legitimate templates, so only dangerous progids count.
_VBA_LIVE_MARKERS: tuple[str, ...] = (
    "AutoOpen",
    "Auto_Open",
    "AutoExec",
    "Auto_Exec",
    "Document_Open",
    "Workbook_Open",
    "Workbook_Activate",
    "URLDownloadToFile",
    "WScript.Shell",
    "Shell.Application",
    "MSXML2.XMLHTTP",
    "WinHttp.WinHttpRequest",
    "ADODB.Stream",
)
_VBA_LIVE_SHELL_RE = re.compile(rb"(?i)\bShell\s*\(")
_VBA_LIVE_CREATE_RE = re.compile(
    rb"(?i)CreateObject\s*\(\s*[\"'](?:"
    rb"WScript\.Shell|Shell\.Application|MSXML2\.XMLHTTP|"
    rb"WinHttp\.WinHttpRequest|ADODB\.Stream)"
)
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _marker_in_blob(blob: bytes, text: str) -> bool:
    raw = text.encode("ascii")
    if raw.lower() in blob.lower():
        return True
    wide = text.encode("utf-16le")
    wide_lower = text.lower().encode("utf-16le")
    return wide in blob or wide_lower in blob


def _blob_has_vba_live(blob: bytes) -> bool:
    if not blob:
        return False
    if any(_marker_in_blob(blob, marker) for marker in _VBA_LIVE_MARKERS):
        return True
    if _VBA_LIVE_SHELL_RE.search(blob) or _VBA_LIVE_CREATE_RE.search(blob):
        return True
    return False


def _ole_stream_blobs(data: bytes) -> list[bytes]:
    try:
        import olefile
    except ImportError:
        return []
    try:
        if not olefile.isOleFile(data):
            return []
        ole = olefile.OleFileIO(io.BytesIO(data))
    except (OSError, RuntimeError, ValueError, TypeError):
        return []
    blobs: list[bytes] = []
    try:
        for stream in ole.listdir():
            joined = "/".join(stream).lower()
            if "vba" not in joined and "macro" not in joined:
                continue
            try:
                blobs.append(ole.openstream(stream).read())
            except (OSError, RuntimeError, ValueError, TypeError):
                continue
    finally:
        ole.close()
    return blobs


def detect_office_vba_live(data: bytes) -> bool:
    """True when vbaProject / VBA streams contain autostart or a download/exec API.

    Presence of ``vbaProject.bin`` alone is not enough. Strings are matched in
    the raw project (VBA literals stay readable) and in OLE VBA streams.
    """
    if not data:
        return False
    blobs: list[bytes] = []
    if data[:2] == b"PK":
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            return False
        try:
            for name in zf.namelist():
                if name.replace("\\", "/").lower().endswith("vbaproject.bin"):
                    try:
                        blobs.append(zf.read(name))
                    except KeyError:
                        continue
        finally:
            zf.close()
    elif data[:8] == _OLE_MAGIC:
        blobs.append(data)
    for blob in blobs:
        if _blob_has_vba_live(blob):
            return True
        for stream in _ole_stream_blobs(blob):
            if _blob_has_vba_live(stream):
                return True
    return False


_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def clean_extracted(text: str) -> str:
    return _CTRL_RE.sub(" ", text)
