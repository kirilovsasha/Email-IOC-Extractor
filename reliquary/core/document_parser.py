"""Parse emails, tickets, PDF and HTML into analyzable content."""

from __future__ import annotations

import email
import email.policy
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path

from bs4 import BeautifulSoup

from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.models import AttachmentInfo


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
            except Exception:
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
        except Exception:
            decoded = str(msg.get_payload())
        if ctype == "text/html":
            html_parts.append(decoded)
        else:
            text_parts.append(decoded)

    return "\n".join(text_parts), "\n".join(html_parts), attachments


def parse_eml(path: Path) -> ParsedDocument:
    raw = path.read_bytes()
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    text, html, attachments = _walk_attachments(msg)
    if html and not text.strip():
        text = _html_to_text(html)
    elif html:
        text = text + "\n" + _html_to_text(html)
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
    )


def parse_msg(path: Path) -> ParsedDocument:
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
            data = att.data or b""
            attachments.append(inspect_bytes(str(name), data))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"Вложения MSG: {exc}")

    # Build a minimal RFC822-like message for header analysis
    eml_bytes = None
    try:
        eml_bytes = msg_file.asEmailMessage() if hasattr(msg_file, "asEmailMessage") else None
    except Exception:
        eml_bytes = None

    message: Message | None = None
    if eml_bytes is not None:
        message = eml_bytes
    else:
        # Synthesize headers for analysis.
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

    return ParsedDocument(
        kind="email",
        path=str(path),
        text=text,
        html=html if isinstance(html, str) else "",
        subject=subject,
        sender=sender,
        recipients=recipients,
        message=message,
        attachments=attachments,
        errors=errors,
    )


def parse_pdf(path: Path) -> ParsedDocument:
    errors: list[str] = []
    text_parts: list[str] = []
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path))
        for page in reader.pages:
            try:
                text_parts.append(page.extract_text() or "")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"Страница PDF: {exc}")
        # Annotations / URIs
        for page in reader.pages:
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

    attachments = [inspect_bytes(path.name, path.read_bytes())]
    return ParsedDocument(
        kind="pdf",
        path=str(path),
        text="\n".join(text_parts),
        attachments=attachments,
        errors=errors,
    )


def parse_html(path: Path) -> ParsedDocument:
    raw = path.read_bytes()
    try:
        import chardet

        detected = chardet.detect(raw)
        encoding = detected.get("encoding") or "utf-8"
    except Exception:
        encoding = "utf-8"
    html = raw.decode(encoding, errors="replace")
    text = _html_to_text(html)
    return ParsedDocument(
        kind="html",
        path=str(path),
        text=text,
        html=html,
        attachments=[inspect_bytes(path.name, raw)],
    )


def parse_text(path: Path) -> ParsedDocument:
    raw = path.read_bytes()
    try:
        import chardet

        encoding = (chardet.detect(raw).get("encoding") or "utf-8")
    except Exception:
        encoding = "utf-8"
    text = raw.decode(encoding, errors="replace")
    return ParsedDocument(
        kind="ticket",
        path=str(path),
        text=text,
        attachments=[inspect_bytes(path.name, raw)],
    )


def parse_document(path: str | Path) -> ParsedDocument:
    p = Path(path)
    if not p.exists():
        return ParsedDocument(kind="unknown", path=str(p), text="", errors=["Файл не найден"])
    suffix = p.suffix.lower()
    if suffix == ".eml":
        return parse_eml(p)
    if suffix == ".msg":
        return parse_msg(p)
    if suffix == ".pdf":
        return parse_pdf(p)
    if suffix in {".html", ".htm"}:
        return parse_html(p)
    if suffix in {".txt", ".csv", ".log", ".md", ".json"}:
        return parse_text(p)
    # Fallback: treat as ticket/text
    return parse_text(p)
