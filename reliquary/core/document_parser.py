"""Parse emails (.eml / .msg) into analyzable content.

Attachment formats (Office, archives, nested mail) are inspected in
``attachment_inspector``, not as root inputs.
"""

from __future__ import annotations

import email
import email.policy
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path

from bs4 import BeautifulSoup

from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.formats import EMAIL_SUFFIXES
from reliquary.core.models import AttachmentInfo

# Guardrails for large documents (IOC extract still useful on the head of the file).
MAX_TEXT_CHARS = 2_000_000
MAX_HTML_CHARS = 2_000_000


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
    except (ImportError, LookupError, TypeError, ValueError, AttributeError):
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
                except (TypeError, ValueError, AttributeError, OSError, RuntimeError) as exc:
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
            except (LookupError, UnicodeError, TypeError, ValueError, AttributeError) as exc:
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
    """Parse .msg; ``data`` bytes are written to a temp file when path is missing/virtual."""
    import tempfile

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
    tmp_path: Path | None = None
    open_path = path
    try:
        if data is not None:
            fd, name = tempfile.mkstemp(suffix=".msg", prefix="reliquary_msg_")
            import os

            os.close(fd)
            tmp_path = Path(name)
            tmp_path.write_bytes(data)
            open_path = tmp_path
        elif not path.exists():
            return ParsedDocument(
                kind="email", path=str(path), text="", errors=["MSG-файл не найден"]
            )
        try:
            msg_file = extract_msg.Message(str(open_path))
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            return ParsedDocument(kind="email", path=str(path), text="", errors=[str(exc)])
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
                name = (
                    getattr(att, "longFilename", None)
                    or getattr(att, "shortFilename", None)
                    or "attachment"
                )
                adata = att.data or b""
                attachments.append(inspect_bytes(str(name), adata))
        except (OSError, ValueError, TypeError, AttributeError, RuntimeError) as exc:
            errors.append(f"Вложения MSG: {exc}")

        message: Message | None = None
        try:
            eml_bytes = msg_file.asEmailMessage() if hasattr(msg_file, "asEmailMessage") else None
        except (OSError, ValueError, TypeError, AttributeError, RuntimeError):
            eml_bytes = None
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
        except (OSError, AttributeError, RuntimeError):
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
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass




def parse_document(path: str | Path, data: bytes | None = None) -> ParsedDocument:
    """Parse a top-level email artifact (.eml / .msg). Other types are rejected."""
    p = Path(path)
    if data is None and not p.exists():
        return ParsedDocument(kind="unknown", path=str(p), text="", errors=["Файл не найден"])
    if data is None and not p.is_file():
        return ParsedDocument(kind="unknown", path=str(p), text="", errors=["Не файл"])
    suffix = p.suffix.lower()
    if suffix in EMAIL_SUFFIXES:
        return parse_eml(p, data) if suffix == ".eml" else parse_msg(p, data)
    return ParsedDocument(
        kind="unknown",
        path=str(p),
        text="",
        errors=[
            f"Поддерживаются только письма (.eml / .msg), получено: {suffix or '(без расширения)'}"
        ],
    )
