"""Best-effort read-only .pst → temporary .eml expansion (optional pypff)."""

from __future__ import annotations

import re
import tempfile
from email.message import EmailMessage
from pathlib import Path

# Outlook PST/OST magic (!BDN)
PST_MAGIC = b"!BDN"
_MAX_PST_ATTACHMENTS = 8
_MAX_PST_ATTACHMENT_BYTES = 2 * 1024 * 1024


class PstUnavailableError(RuntimeError):
    """Raised when .pst is detected but no extractor library is installed."""


def is_pst(path: str | Path) -> bool:
    return Path(path).suffix.lower() == ".pst"


def looks_like_pst(path: str | Path) -> bool:
    """True if suffix is .pst or file starts with PST magic."""
    p = Path(path)
    if p.suffix.lower() == ".pst":
        return True
    if not p.is_file():
        return False
    try:
        with p.open("rb") as fh:
            return fh.read(4) == PST_MAGIC
    except OSError:
        return False


def pst_library_available() -> bool:
    try:
        import pypff  # noqa: F401

        return True
    except ImportError:
        try:
            import libratom  # noqa: F401

            return True
        except ImportError:
            return False


def _ru_missing_lib_message(path: Path) -> str:
    return (
        f"PST «{path.name}»: разбор недоступен без опциональной библиотеки. "
        "Установите `pip install reliquary[pst]` (libratom) или pypff. "
        "Файл пропущен — разбор не прерван."
    )


def expand_pst_to_emls(
    path: str | Path,
    *,
    dest: Path | None = None,
    limit: int = 500,
) -> tuple[list[str], Path, list[str]]:
    """Extract messages from a .pst into temporary .eml files.

    Returns (eml_paths, dest_dir, notes). On missing library returns empty list
    and a clear RU note (no crash). On corrupt PST returns notes and whatever
    was extracted.
    """
    src = Path(path)
    notes: list[str] = []
    if dest is None:
        dest = Path(tempfile.mkdtemp(prefix="reliquary_pst_"))
    else:
        dest.mkdir(parents=True, exist_ok=True)

    if not src.is_file():
        notes.append(f"PST: файл не найден — {src}")
        return [], dest, notes

    try:
        with src.open("rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        notes.append(f"PST: не удалось прочитать ({exc})")
        return [], dest, notes

    if magic != PST_MAGIC and src.suffix.lower() == ".pst":
        notes.append(
            f"PST «{src.name}»: нет сигнатуры !BDN — возможно не PST/OST; попытка разбора продолжена"
        )
    elif magic != PST_MAGIC:
        notes.append(f"Не PST (магия {magic!r}) — пропуск")
        return [], dest, notes

    if not pst_library_available():
        notes.append(_ru_missing_lib_message(src))
        return [], dest, notes

    out: list[str] = []
    try:
        out = _extract_with_pypff(src, dest, limit=limit, notes=notes)
    except Exception as exc:  # noqa: BLE001 — optional native lib may raise anything
        notes.append(f"PST pypff: {type(exc).__name__}: {exc}")
        try:
            out = _extract_with_libratom(src, dest, limit=limit, notes=notes)
        except Exception as exc2:  # noqa: BLE001
            notes.append(f"PST libratom: {type(exc2).__name__}: {exc2}")
    if not out and not any("недоступен" in n for n in notes):
        notes.append(f"PST «{src.name}»: сообщений не извлечено")
    return out, dest, notes


def compose_eml(
    headers: str,
    body: bytes,
    attachments: list[tuple[str, bytes]],
    *,
    html: bool = False,
) -> bytes:
    """RFC822 bytes. Attachments become a multipart message; otherwise headers+body."""
    payload = [(n, d) for n, d in attachments if d][:_MAX_PST_ATTACHMENTS]
    hdr = headers or ""
    if hdr and not hdr.endswith("\n"):
        hdr += "\n"
    if not payload:
        return (hdr + "\n").encode("utf-8", errors="replace") + (body or b"")
    msg = EmailMessage()
    seen: set[str] = set()
    for line in hdr.splitlines():
        if ":" not in line or line[:1].isspace():
            continue
        name, val = line.split(":", 1)
        key = name.strip()
        low = key.lower()
        if not key or low.startswith("content-") or low == "mime-version" or low in seen:
            continue
        try:
            msg[key] = val.strip()
        except (ValueError, IndexError, KeyError):
            continue
        seen.add(low)
    text = (body or b"").decode("utf-8", errors="replace")
    msg.set_content(text, subtype="html" if html else "plain", charset="utf-8")
    for name, data in payload:
        msg.add_attachment(
            data[:_MAX_PST_ATTACHMENT_BYTES],
            maintype="application",
            subtype="octet-stream",
            filename=name,
        )
    return msg.as_bytes()


def _folder_label(folder) -> str:
    try:
        name = folder.get_name() or ""
    except Exception:  # noqa: BLE001
        name = ""
    cleaned = re.sub(r"[^\w.-]+", "_", str(name), flags=re.UNICODE).strip("._")
    return cleaned[:24]


def _attachment_bytes(att, index: int) -> tuple[str, bytes] | None:
    name = f"attachment-{index}.bin"
    for attr in ("get_name", "name", "filename"):
        val = getattr(att, attr, None)
        try:
            val = val() if callable(val) else val
        except Exception:  # noqa: BLE001
            val = None
        if val:
            name = Path(str(val).replace("\x00", "")).name.strip() or name
            break
    name = name[:180] or f"attachment-{index}.bin"
    data = b""
    size = 0
    get_size = getattr(att, "get_size", None)
    if callable(get_size):
        try:
            size = int(get_size() or 0)
        except Exception:  # noqa: BLE001
            size = 0
    read_buffer = getattr(att, "read_buffer", None)
    if callable(read_buffer):
        try:
            n = size if 0 < size <= _MAX_PST_ATTACHMENT_BYTES else _MAX_PST_ATTACHMENT_BYTES
            data = read_buffer(n) or b""
        except Exception:  # noqa: BLE001
            data = b""
    if not data:
        for meth in ("read", "get_data"):
            fn = getattr(att, meth, None)
            if not callable(fn):
                continue
            try:
                data = fn() or b""
            except Exception:  # noqa: BLE001
                data = b""
            if data:
                break
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    if not isinstance(data, (bytes, bytearray)) or not data:
        return None
    return name, bytes(data[:_MAX_PST_ATTACHMENT_BYTES])


def _collect_attachments(msg) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    getter = getattr(msg, "get_number_of_attachments", None)
    if callable(getter):
        try:
            count = int(getter() or 0)
        except Exception:  # noqa: BLE001
            count = 0
        for i in range(min(count, _MAX_PST_ATTACHMENTS)):
            try:
                att = msg.get_attachment(i)
            except Exception:  # noqa: BLE001
                continue
            item = _attachment_bytes(att, i)
            if item:
                out.append(item)
        return out
    raw = getattr(msg, "attachments", None)
    if raw is None:
        return out
    try:
        seq = list(raw)
    except Exception:  # noqa: BLE001
        return out
    for i, att in enumerate(seq[:_MAX_PST_ATTACHMENTS]):
        item = _attachment_bytes(att, i)
        if item:
            out.append(item)
    return out


def _message_to_eml(msg) -> bytes:
    """RFC822 from a pypff/libratom message, including attachment bytes when present."""
    headers = ""
    body = b""
    html = False
    try:
        transport = msg.get_transport_headers()
    except Exception:  # noqa: BLE001
        transport = getattr(msg, "headers", None)
    if transport:
        headers = transport if isinstance(transport, str) else bytes(transport).decode("utf-8", "replace")
    plain = ""
    try:
        plain = msg.get_plain_text_body() or ""
    except Exception:  # noqa: BLE001
        plain = getattr(msg, "plain_text_body", None) or ""
    if plain:
        body = plain if isinstance(plain, bytes) else str(plain).encode("utf-8", "replace")
    else:
        html_body = ""
        try:
            html_body = msg.get_html_body() or ""
        except Exception:  # noqa: BLE001
            html_body = getattr(msg, "html_body", None) or ""
        if html_body:
            html = True
            body = html_body if isinstance(html_body, bytes) else str(html_body).encode("utf-8", "replace")
    if not headers:
        subject = ""
        sender = ""
        try:
            subject = msg.get_subject() or ""
        except Exception:  # noqa: BLE001
            subject = str(getattr(msg, "subject", "") or "")
        try:
            sender = msg.get_sender_name() or ""
        except Exception:  # noqa: BLE001
            sender = str(getattr(msg, "sender_name", "") or "")
        headers = f"From: {sender}\nSubject: {subject}\n"
    try:
        return compose_eml(headers, body, _collect_attachments(msg), html=html)
    except Exception:  # noqa: BLE001
        if headers and not headers.endswith("\n"):
            headers += "\n"
        return (headers + "\n").encode("utf-8", errors="replace") + body


def _extract_with_pypff(
    src: Path, dest: Path, *, limit: int, notes: list[str]
) -> list[str]:
    import pypff

    out: list[str] = []
    with_att = 0
    pst = pypff.file()
    pst.open(str(src))
    try:
        root = pst.get_root_folder()
        with_att = _walk_pypff_folder(root, dest, out, limit=limit, prefix="")
    finally:
        try:
            pst.close()
        except Exception:  # noqa: BLE001
            pass
    notes.append(
        f"PST pypff: извлечено {len(out)} писем из «{src.name}»"
        + (f", с вложениями: {with_att}" if with_att else "")
    )
    return out


def _walk_pypff_folder(
    folder, dest: Path, out: list[str], *, limit: int, prefix: str
) -> int:
    """Walk the folder tree. Returns how many written messages had attachments."""
    if len(out) >= limit:
        return 0
    label = _folder_label(folder)
    here = f"{prefix}{label}__" if label else prefix
    written_att = 0
    try:
        n = folder.get_number_of_sub_messages()
    except Exception:  # noqa: BLE001
        n = 0
    for i in range(n):
        if len(out) >= limit:
            return written_att
        try:
            msg = folder.get_sub_message(i)
        except Exception:  # noqa: BLE001
            continue
        raw = _message_to_eml(msg)
        if not raw:
            continue
        if b"Content-Disposition: attachment" in raw or b'filename="' in raw:
            written_att += 1
        name = dest / f"{here}{len(out):04d}.eml"
        name.write_bytes(raw)
        out.append(str(name))
    try:
        n_sub = folder.get_number_of_sub_folders()
    except Exception:  # noqa: BLE001
        n_sub = 0
    for i in range(n_sub):
        if len(out) >= limit:
            return written_att
        try:
            sub = folder.get_sub_folder(i)
        except Exception:  # noqa: BLE001
            continue
        written_att += _walk_pypff_folder(sub, dest, out, limit=limit, prefix=here)
    return written_att


def _extract_with_libratom(
    src: Path, dest: Path, *, limit: int, notes: list[str]
) -> list[str]:
    from libratom.lib.pff import PffArchive

    out: list[str] = []
    with_att = 0
    with PffArchive(str(src)) as archive:
        for i, message in enumerate(archive.messages()):
            if i >= limit:
                break
            try:
                raw = _message_to_eml(message)
            except Exception:  # noqa: BLE001
                continue
            if not raw:
                continue
            if b"Content-Disposition: attachment" in raw or b'filename="' in raw:
                with_att += 1
            folder = ""
            try:
                folder = str(getattr(message, "folder_name", "") or getattr(message, "folder", "") or "")
            except Exception:  # noqa: BLE001
                folder = ""
            label = re.sub(r"[^\w.-]+", "_", folder, flags=re.UNICODE).strip("._")[:24]
            prefix = f"{label}__" if label else ""
            name = dest / f"{prefix}{len(out):04d}.eml"
            name.write_bytes(raw)
            out.append(str(name))
    notes.append(
        f"PST libratom: извлечено {len(out)} писем из «{src.name}»"
        + (f", с вложениями: {with_att}" if with_att else "")
    )
    return out
