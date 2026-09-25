"""Parse emails (.eml / .msg) into analyzable content.

Attachment formats (Office, archives, nested mail) are inspected in
``attachment_inspector``, not as root inputs.
"""

from __future__ import annotations

import email
import email.policy
import re
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path

from bs4 import BeautifulSoup

from reliquary.core.attachment_inspector import decode_payload_text, inspect_bytes
from reliquary.core.formats import EMAIL_SUFFIXES
from reliquary.core.models import AttachmentInfo

# Guardrails for large documents (IOC extract still useful on the head of the file).
MAX_TEXT_CHARS = 2_000_000
MAX_HTML_CHARS = 2_000_000

# Analysts often paste Gmail/Outlook/RU forwards that start with a banner or
# blank lines before the real RFC822 headers. Python's parser then treats the
# whole blob as body → empty From / Received. Byte-safe: only touch the head.
_HEADER_LINE_RE = re.compile(rb"(?i)^[A-Za-z][\w-]*\s*:")
_HEADER_ANCHOR_RE = re.compile(
    rb"(?im)^(return-path|received|from|sender|reply-to|message-id|"
    rb"authentication-results|dkim-signature|mime-version|date|subject|"
    rb"to|cc|bcc|x-mailer|user-agent|resent-from)\s*:"
)
_HEADER_SCAN_BYTES = 16_384


def normalize_email_bytes(raw: bytes) -> bytes:
    """Strip BOM / leading blanks / forward preamble so headers are parseable."""
    if not raw:
        return raw
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    elif raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        try:
            text = raw.decode("utf-16")
        except UnicodeError:
            return raw
        return normalize_email_bytes(text.encode("utf-8", errors="replace"))
    raw = raw.lstrip(b"\r\n")
    head = raw[:_HEADER_SCAN_BYTES]
    if _HEADER_LINE_RE.match(head):
        return raw
    match = _HEADER_ANCHOR_RE.search(head)
    if match:
        return raw[match.start() :]
    return raw


def normalize_email_text(text: str) -> str:
    """Text-side wrapper for paste / clipboard paths."""
    if not text:
        return text
    return normalize_email_bytes(text.encode("utf-8", errors="replace")).decode(
        "utf-8", errors="replace"
    )


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


def _delivery_status_text(part: Message) -> str:
    """DSN body. ``decode=True`` is empty: the fields live in the part content."""
    try:
        content = part.get_content()
    except (AttributeError, TypeError, ValueError, LookupError, KeyError):
        content = None
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    if isinstance(content, str) and content.strip():
        return content
    raw = part.as_string()
    return raw.split("\n\n", 1)[-1]


def _part_payload(part: Message) -> bytes:
    """Bytes of a MIME part, including a nameless message/rfc822 sub-message."""
    try:
        payload = part.get_payload(decode=True)
    except (TypeError, ValueError, AttributeError, OSError):
        payload = None
    if isinstance(payload, (bytes, bytearray)) and payload:
        return bytes(payload)
    inner = part.get_payload()
    if isinstance(inner, list) and inner and hasattr(inner[0], "as_bytes"):
        try:
            return inner[0].as_bytes()
        except (TypeError, ValueError, AttributeError, OSError):
            pass
    if isinstance(inner, str) and inner.strip():
        return inner.encode("utf-8", errors="replace")
    return b""


def _is_inline_or_cid_image(part: Message, ctype: str, disp: str) -> bool:
    """Image kept for QR that is not a file attachment."""
    if not ctype.startswith("image/"):
        return False
    if "attachment" in (disp or "").lower():
        return False
    if str(part.get("Content-ID") or "").strip():
        return True
    if "inline" in (disp or "").lower():
        return True
    return not part.get_filename()


def _mark_inline_image(info: AttachmentInfo) -> AttachmentInfo:
    if "inline_image" not in info.risk_flags:
        info.risk_flags.append("inline_image")
    return info


# Nameless Office should reach the same inspect_bytes path as a named .docx/.xlsx.
_NAMELESS_EXT = {
    "application/msword": "doc",
    "application/vnd.ms-excel": "xls",
    "application/vnd.ms-powerpoint": "ppt",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    "application/rtf": "rtf",
    "text/rtf": "rtf",
    "application/zip": "zip",
    "application/x-zip-compressed": "zip",
}


def _nameless_attachment_name(ctype: str) -> str:
    if ctype == "message/rfc822":
        return "nested.eml"
    if ctype == "text/calendar":
        return "invite.ics"
    mapped = _NAMELESS_EXT.get(ctype)
    if mapped:
        return f"attachment.{mapped}"
    subtype = ctype.split("/")[-1].split("+")[0]
    safe = re.sub(r"[^A-Za-z0-9]+", "", subtype) or "bin"
    return f"attachment.{safe[:20]}"


def _decode_part_text(payload: bytes, charset: str | None) -> str:
    return decode_payload_text(payload, charset)


def _append_named_plain_text(part: Message, text_parts: list[str]) -> None:
    """text/plain with a filename still feeds the extractor and the verdict."""
    try:
        payload = part.get_payload(decode=True) or b""
        decoded = _decode_part_text(payload, part.get_content_charset())
    except (LookupError, UnicodeError, TypeError, ValueError, AttributeError):
        return
    if decoded.strip():
        text_parts.append(decoded)


def _append_enriched_or_rtf(part: Message, ctype: str, text_parts: list[str]) -> None:
    """text/enriched, text/rtf and application/rtf text go to the body extractor."""
    if ctype not in {"text/enriched", "text/rtf", "application/rtf"}:
        return
    try:
        payload = part.get_payload(decode=True) or b""
        decoded = _decode_part_text(payload, part.get_content_charset())
    except (LookupError, UnicodeError, TypeError, ValueError, AttributeError):
        return
    if decoded.strip():
        text_parts.append(decoded)


def _walk_attachments(msg: Message) -> tuple[str, str, list[AttachmentInfo]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[AttachmentInfo] = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()
            cid = str(part.get("Content-ID", "") or "").strip("<> ")
            if filename:
                try:
                    if ctype == "message/rfc822":
                        payload = _part_payload(part)
                    else:
                        payload = part.get_payload(decode=True) or b""
                    info = inspect_bytes(filename, payload)
                    if _is_inline_or_cid_image(part, ctype, disp):
                        _mark_inline_image(info)
                    attachments.append(info)
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
                # A named text/plain part is still body text for the extractor and verdict.
                if ctype == "text/plain":
                    _append_named_plain_text(part, text_parts)
                continue
            # CID / inline images without filename → still inspect for QR
            if ctype.startswith("image/") and "attachment" not in disp.lower():
                try:
                    payload = part.get_payload(decode=True) or b""
                except (TypeError, ValueError, AttributeError, OSError):
                    payload = b""
                if payload:
                    synth = f"cid-{cid[:40] or 'inline'}.{ctype.split('/')[-1].split('+')[0]}"
                    attachments.append(_mark_inline_image(inspect_bytes(synth, payload)))
                continue
            # TNEF without filename
            if ctype in {"application/ms-tnef", "application/vnd.ms-tnef"}:
                try:
                    payload = part.get_payload(decode=True) or b""
                except (TypeError, ValueError, AttributeError, OSError):
                    payload = b""
                if payload:
                    attachments.append(inspect_bytes("winmail.dat", payload, keep_bytes=True))
                continue
            if ctype in {"message/rfc822", "text/calendar"}:
                payload = _part_payload(part)
                if payload:
                    name = "nested.eml" if ctype == "message/rfc822" else "invite.ics"
                    attachments.append(inspect_bytes(name, payload, keep_bytes=True))
                continue
            if "attachment" in disp.lower():
                payload = _part_payload(part)
                if payload:
                    attachments.append(inspect_bytes(_nameless_attachment_name(ctype), payload))
                _append_enriched_or_rtf(part, ctype, text_parts)
                continue
            if ctype == "message/delivery-status":
                text = _delivery_status_text(part)
                if text.strip():
                    text_parts.append(text)
                continue
            # Nameless PDF, including Content-Disposition: inline. Same path as a named PDF.
            if ctype == "application/pdf":
                payload = _part_payload(part)
                if payload:
                    attachments.append(inspect_bytes(_nameless_attachment_name(ctype), payload))
                continue
            # text/enriched and text/rtf are body text for the extractor.
            if ctype in {"text/enriched", "text/rtf"}:
                _append_enriched_or_rtf(part, ctype, text_parts)
                continue
            # Nameless ZIP / Office / application/rtf, including Content-Disposition: inline.
            if not ctype.startswith("text/") and not ctype.startswith("multipart/"):
                payload = _part_payload(part)
                if payload:
                    attachments.append(inspect_bytes(_nameless_attachment_name(ctype), payload))
                _append_enriched_or_rtf(part, ctype, text_parts)
                continue
            try:
                payload = part.get_payload(decode=True) or b""
                decoded = _decode_part_text(payload, part.get_content_charset())
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
            if ctype in {"text/plain", "text/rfc822-headers"}:
                text_parts.append(decoded)
            elif ctype == "text/html":
                html_parts.append(decoded)
    else:
        ctype = msg.get_content_type()
        # A lone PDF / pkcs7 / other non-text root is an attachment, not the body.
        if ctype == "message/delivery-status":
            text = _delivery_status_text(msg)
            if text.strip():
                text_parts.append(text)
        elif not ctype.startswith("text/"):
            filename = msg.get_filename() or _nameless_attachment_name(ctype)
            try:
                payload = msg.get_payload(decode=True) or b""
            except (TypeError, ValueError, AttributeError, OSError):
                payload = b""
            if isinstance(payload, str):
                payload = payload.encode("utf-8", errors="replace")
            attachments.append(inspect_bytes(filename, bytes(payload)))
        else:
            try:
                payload = msg.get_payload(decode=True) or b""
                decoded = _decode_part_text(payload, msg.get_content_charset())
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
    raw = normalize_email_bytes(_read_bytes(path, data))
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
        subject=str(msg.get("Subject", "") or ""),
        sender=str(msg.get("From", "") or ""),
        recipients=_collect_recipients(msg),
        message=msg,
        attachments=attachments,
        errors=notes,
    )


def _header_dict_values(hdrs: dict, key: str) -> list[str]:
    """Return all values for a header name from extract-msg headerDict."""
    raw = hdrs.get(key)
    if raw is None:
        raw = hdrs.get(key.lower())
    if raw is None:
        # Case-insensitive fallback (Outlook headerDict keys vary)
        for k, v in hdrs.items():
            if str(k).lower() == key.lower():
                raw = v
                break
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(v) for v in raw if str(v).strip()]
    text = str(raw).strip()
    return [text] if text else []


def _message_header_empty(msg: Message, name: str) -> bool:
    values = msg.get_all(name, [])
    if not values:
        return True
    return not any(str(v).strip() for v in values)


def _set_header(message: Message, name: str, value: str) -> None:
    """Set a header, replacing an empty unique header if present."""
    if not value.strip():
        return
    if name in message:
        if not _message_header_empty(message, name):
            return
        try:
            message.replace_header(name, value)
            return
        except KeyError:
            del message[name]
    message[name] = value


def _fill_msg_transport_headers(
    message: Message,
    msg_file: object,
    hdrs: dict | None,
) -> None:
    """Backfill From / Received / auth headers from extract-msg metadata."""
    if _message_header_empty(message, "From"):
        sender = getattr(msg_file, "sender", None) or getattr(msg_file, "senderEmail", None)
        if sender and str(sender).strip():
            _set_header(message, "From", str(sender))
        elif isinstance(hdrs, dict):
            from_vals = _header_dict_values(hdrs, "From")
            if from_vals:
                _set_header(message, "From", from_vals[0])

    if not isinstance(hdrs, dict):
        return

    # Copy multi-value transport headers; keep all Received hops.
    for key in (
        "Received",
        "Authentication-Results",
        "DKIM-Signature",
        "References",
        "List-Unsubscribe",
        "Return-Path",
        "Reply-To",
        "Sender",
        "Message-ID",
        "Date",
    ):
        values = _header_dict_values(hdrs, key)
        if not values:
            continue
        if key == "Received":
            existing = [str(v).strip() for v in message.get_all("Received", []) if str(v).strip()]
            if existing:
                continue
            for value in values:
                message.add_header("Received", value)
            continue
        if _message_header_empty(message, key):
            _set_header(message, key, values[0])


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
        hdrs = getattr(msg_file, "headerDict", None) or getattr(msg_file, "headers", None)
        if eml_bytes is not None:
            message = eml_bytes
            _fill_msg_transport_headers(message, msg_file, hdrs if isinstance(hdrs, dict) else None)
        else:
            synthetic = email.message.EmailMessage()
            if msg_file.sender:
                synthetic["From"] = str(msg_file.sender)
            if msg_file.subject:
                synthetic["Subject"] = str(msg_file.subject)
            if msg_file.to:
                synthetic["To"] = str(msg_file.to)
            # Best-effort transport headers for offline MSG dumps
            for attr, hdr in (
                ("messageId", "Message-ID"),
                ("date", "Date"),
                ("inReplyTo", "In-Reply-To"),
                ("replyTo", "Reply-To"),
                ("returnPath", "Return-Path"),
            ):
                val = getattr(msg_file, attr, None)
                if val and hdr not in synthetic:
                    synthetic[hdr] = str(val)
            _fill_msg_transport_headers(synthetic, msg_file, hdrs if isinstance(hdrs, dict) else None)
            message = synthetic
            errors.append("MSG: transport-заголовки частично синтезированы (asEmailMessage недоступен)")

        subject = str(msg_file.subject or "")
        sender = str(msg_file.sender or "") or str(message.get("From", "") or "")
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
