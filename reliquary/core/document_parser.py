"""Parse emails, tickets, PDF and HTML into analyzable content."""

from __future__ import annotations

import email
import email.policy
import io
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path

from bs4 import BeautifulSoup

from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.formats import (
    ARCHIVE_SUFFIXES,
    EMAIL_SUFFIXES,
    HTML_SUFFIXES,
    OFFICE_OOXML_SUFFIXES,
    TEXT_SUFFIXES,
)
from reliquary.core.models import AttachmentInfo
from reliquary.core.office_extract import clean_extracted, extract_office_text

# Guardrails for large documents (IOC extract still useful on the head of the file).
MAX_TEXT_CHARS = 2_000_000
MAX_HTML_CHARS = 2_000_000
MAX_PDF_PAGES = 80


@dataclass
class ParsedDocument:
    kind: str
    path: str
    text: str
    html: str = ""
    subject: str = ""
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    message: Message | None = None
    attachments: list[AttachmentInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _clip_text(text: str, limit: int = MAX_TEXT_CHARS) -> tuple[str, list[str]]:
    if len(text) <= limit:
        return text, []
    return text[:limit], [f"Текст обрезан до {limit:,} символов для разбора".replace(",", " ")]


def _read_bytes(path: Path, data: bytes | None) -> bytes:
    if data is not None:
        return data
    return path.read_bytes()


def _decode_bytes(raw: bytes) -> str:
    try:
        import chardet

        encoding = (chardet.detect(raw).get("encoding") or "utf-8")
    except Exception:
        encoding = "utf-8"
    return raw.decode(encoding, errors="replace")


def _html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style"]):
        tag.decompose()
    text = soup.get_text("\n")
    # Keep hrefs — critical for IOC extraction.
    hrefs = []
    for a in soup.find_all("a", href=True):
        hrefs.append(a["href"])
    if hrefs:
        text += "\n\nURLs:\n" + "\n".join(hrefs)
    return text


def _collect_recipients(msg: Message) -> list[str]:
    out: list[str] = []
    for header in ("To", "Cc", "Bcc"):
        val = msg.get(header)
        if val:
            out.append(f"{header}: {val}")
    return out


def _walk_attachments(msg: Message) -> tuple[str, str, list[AttachmentInfo]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[AttachmentInfo] = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()
            if filename:
                try:
                    payload = part.get_payload(decode=True) or b""
                    attachments.append(inspect_bytes(filename, payload))
                except Exception as exc:  # noqa: BLE001
                    attachments.append(
                        AttachmentInfo(
                            filename=filename,
                            size=0,
                            mime_guess=ctype,
                            md5="",
                            sha1="",
                            sha256="",
                            risk_flags=["read_error"],
                            notes=[str(exc)],
                        )
                    )
                continue
            if "attachment" in disp.lower():
                continue
            try:
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace")
            except Exception as exc:  # noqa: BLE001
                attachments.append(
                    AttachmentInfo(
                        filename=f"(inline:{ctype})",
                        size=0,
                        mime_guess=ctype,
                        md5="",
                        sha1="",
                        sha256="",
                        risk_flags=["decode_error"],
                        notes=[f"Не удалось декодировать часть письма: {exc}"],
                    )
                )
                continue
            if ctype == "text/plain":
                text_parts.append(decoded)
            elif ctype == "text/html":
                html_parts.append(decoded)
    else:
        ctype = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True) or b""
            charset = msg.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")
        except Exception as exc:  # noqa: BLE001
            decoded = str(msg.get_payload())
            attachments.append(
                AttachmentInfo(
                    filename="(body)",
                    size=0,
                    mime_guess=ctype,
                    md5="",
                    sha1="",
                    sha256="",
                    risk_flags=["decode_error"],
                    notes=[f"Декод тела письма с ошибкой: {exc}"],
                )
            )
        if ctype == "text/html":
            html_parts.append(decoded)
        else:
            text_parts.append(decoded)

    return "\n".join(text_parts), "\n".join(html_parts), attachments


def parse_eml(path: Path, data: bytes | None = None) -> ParsedDocument:
    raw = _read_bytes(path, data)
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    text, html, attachments = _walk_attachments(msg)
    if html and not text.strip():
        text = _html_to_text(html)
    elif html:
        text = text + "\n" + _html_to_text(html)
    notes: list[str] = []
    text, clip_notes = _clip_text(text)
    notes.extend(clip_notes)
    html, html_notes = _clip_text(html, MAX_HTML_CHARS)
    notes.extend(html_notes)
    return ParsedDocument(
        kind="email",
        path=str(path),
        text=text,
        html=html,
        subject=str(msg.get("Subject", "")),
        sender=str(msg.get("From", "")),
        recipients=_collect_recipients(msg),
        message=msg,
        attachments=attachments,
        errors=notes,
    )


def parse_msg(path: Path, data: bytes | None = None) -> ParsedDocument:
    _ = data  # extract-msg needs a path on disk
    try:
        import extract_msg
    except ImportError as exc:
        return ParsedDocument(
            kind="email",
            path=str(path),
            text="",
            errors=[f"extract-msg не установлен: {exc}"],
        )

    errors: list[str] = []
    try:
        msg_file = extract_msg.Message(str(path))
    except Exception as exc:  # noqa: BLE001
        return ParsedDocument(kind="email", path=str(path), text="", errors=[str(exc)])

    body = msg_file.body or ""
    html = getattr(msg_file, "htmlBody", None) or ""
    if isinstance(html, bytes):
        html = html.decode("utf-8", errors="replace")
    text = body
    if html:
        text = (text + "\n" + _html_to_text(html)).strip()

    attachments: list[AttachmentInfo] = []
    try:
        for att in msg_file.attachments:
            name = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or "attachment"
            adata = att.data or b""
            attachments.append(inspect_bytes(str(name), adata))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"Вложения MSG: {exc}")

    eml_bytes = None
    try:
        eml_bytes = msg_file.asEmailMessage() if hasattr(msg_file, "asEmailMessage") else None
    except Exception:
        eml_bytes = None

    message: Message | None = None
    if eml_bytes is not None:
        message = eml_bytes
    else:
        synthetic = email.message.EmailMessage()
        if msg_file.sender:
            synthetic["From"] = str(msg_file.sender)
        if msg_file.subject:
            synthetic["Subject"] = str(msg_file.subject)
        if msg_file.to:
            synthetic["To"] = str(msg_file.to)
        message = synthetic

    subject = str(msg_file.subject or "")
    sender = str(msg_file.sender or "")
    recipients = [str(msg_file.to)] if msg_file.to else []
    try:
        msg_file.close()
    except Exception:
        pass

    text, clip_notes = _clip_text(text)
    errors.extend(clip_notes)
    html_s = html if isinstance(html, str) else ""
    html_s, html_notes = _clip_text(html_s, MAX_HTML_CHARS)
    errors.extend(html_notes)

    return ParsedDocument(
        kind="email",
        path=str(path),
        text=text,
        html=html_s,
        subject=subject,
        sender=sender,
        recipients=recipients,
        message=message,
        attachments=attachments,
        errors=errors,
    )


def parse_pdf(path: Path, data: bytes | None = None) -> ParsedDocument:
    raw = _read_bytes(path, data)
    errors: list[str] = []
    text_parts: list[str] = []
    try:
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(raw))
        pages = list(reader.pages)
        if len(pages) > MAX_PDF_PAGES:
            errors.append(f"PDF: разобраны первые {MAX_PDF_PAGES} из {len(pages)} страниц")
            pages = pages[:MAX_PDF_PAGES]
        for page in pages:
            try:
                text_parts.append(page.extract_text() or "")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"Страница PDF: {exc}")
        for page in pages:
            annots = page.get("/Annots") or []
            for annot in annots:
                try:
                    obj = annot.get_object()
                    action = obj.get("/A")
                    if action and action.get("/URI"):
                        text_parts.append(str(action["/URI"]))
                except Exception:
                    continue
    except Exception as exc:  # noqa: BLE001
        errors.append(str(exc))

    text, clip_notes = _clip_text("\n".join(text_parts))
    errors.extend(clip_notes)
    attachments = [inspect_bytes(path.name, raw)]
    return ParsedDocument(
        kind="pdf",
        path=str(path),
        text=text,
        attachments=attachments,
        errors=errors,
    )


def parse_html(path: Path, data: bytes | None = None) -> ParsedDocument:
    raw = _read_bytes(path, data)
    html = _decode_bytes(raw)
    notes: list[str] = []
    html, html_notes = _clip_text(html, MAX_HTML_CHARS)
    notes.extend(html_notes)
    text = _html_to_text(html)
    text, clip_notes = _clip_text(text)
    notes.extend(clip_notes)
    return ParsedDocument(
        kind="html",
        path=str(path),
        text=text,
        html=html,
        attachments=[inspect_bytes(path.name, raw)],
        errors=notes,
    )


def parse_text(path: Path, data: bytes | None = None) -> ParsedDocument:
    raw = _read_bytes(path, data)
    text = _decode_bytes(raw)
    text, notes = _clip_text(text)
    return ParsedDocument(
        kind="ticket",
        path=str(path),
        text=text,
        attachments=[inspect_bytes(path.name, raw)],
        errors=notes,
    )


def parse_office(path: Path, data: bytes | None = None) -> ParsedDocument:
    raw = _read_bytes(path, data)
    text, errors = extract_office_text(raw, path.suffix.lower())
    text, clip_notes = _clip_text(clean_extracted(text))
    errors.extend(clip_notes)
    return ParsedDocument(
        kind="office",
        path=str(path),
        text=text,
        attachments=[inspect_bytes(path.name, raw)],
        errors=errors,
    )


# Back-compat aliases
def parse_docx(path: Path, data: bytes | None = None) -> ParsedDocument:
    return parse_office(path, data)


def parse_xlsx(path: Path, data: bytes | None = None) -> ParsedDocument:
    return parse_office(path, data)


def parse_zip(path: Path, data: bytes | None = None) -> ParsedDocument:
    """Inventory zip as a document — names become analyzable text, no unpack."""
    raw = _read_bytes(path, data)
    att = inspect_bytes(path.name, raw)
    lines = ["ZIP archive inventory:", path.name, ""]
    lines.extend(e for e in (att.archive_entries or []) if not e.startswith("QR:"))
    errors: list[str] = []
    if "encrypted_archive" in att.risk_flags:
        errors.append("⚠ Архив защищён паролем — содержимое не извлечено, только имена/флаги")
    errors.extend(n for n in att.notes if "парол" in n.lower() or "encrypted" in n.lower())
    return ParsedDocument(
        kind="archive",
        path=str(path),
        text="\n".join(lines),
        attachments=[att],
        errors=errors,
    )


def parse_archive_generic(path: Path, data: bytes | None = None) -> ParsedDocument:
    """RAR/7z as archive document via attachment inspector inventory."""
    raw = _read_bytes(path, data)
    att = inspect_bytes(path.name, raw)
    lines = [f"{path.suffix.upper().lstrip('.')} archive inventory:", path.name, ""]
    lines.extend(e for e in (att.archive_entries or []) if not e.startswith("QR:"))
    errors: list[str] = list(att.notes) if not att.archive_entries else []
    if "encrypted_archive" in att.risk_flags:
        errors.insert(
            0,
            "⚠ Архив защищён паролем — inventory ограничен, данные не извлечены",
        )
    return ParsedDocument(
        kind="archive",
        path=str(path),
        text="\n".join(lines),
        attachments=[att],
        errors=errors,
    )


def parse_document(path: str | Path, data: bytes | None = None) -> ParsedDocument:
    p = Path(path)
    if data is None and not p.exists():
        return ParsedDocument(kind="unknown", path=str(p), text="", errors=["Файл не найден"])
    if data is None and not p.is_file():
        return ParsedDocument(kind="unknown", path=str(p), text="", errors=["Не файл"])
    suffix = p.suffix.lower()
    if suffix in EMAIL_SUFFIXES:
        return parse_eml(p, data) if suffix == ".eml" else parse_msg(p, data)
    if suffix == ".pdf":
        return parse_pdf(p, data)
    if suffix in HTML_SUFFIXES:
        return parse_html(p, data)
    if suffix in OFFICE_OOXML_SUFFIXES:
        return parse_office(p, data)
    if suffix == ".zip":
        return parse_zip(p, data)
    if suffix in ARCHIVE_SUFFIXES:
        return parse_archive_generic(p, data)
    if suffix in TEXT_SUFFIXES:
        return parse_text(p, data)
    return parse_text(p, data)
