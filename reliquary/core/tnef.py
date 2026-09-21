"""Minimal offline TNEF (winmail.dat) attachment extractor — no network, no DB."""

from __future__ import annotations

import struct
from pathlib import Path

# TNEF signature
_TNEF_SIG = 0x223E9F78

# Attribute levels / ids (subset)
_ATT_ATTACH_TITLE = 0x00018010  # sometimes file name
_ATT_ATTACH_DATA = 0x0006800F
_ATT_ATTACH_REND = 0x00069002
# Common MAPI-ish ids seen in the wild
_ATT_FILENAME = 0x00018010
_ATT_LONG_FILENAME = 0x00018012  # not always present
_ATT_DATA = 0x0006800F


def is_tnef(data: bytes) -> bool:
    if len(data) < 6:
        return False
    try:
        sig = struct.unpack_from("<I", data, 0)[0]
    except struct.error:
        return False
    return sig == _TNEF_SIG


def extract_tnef_attachments(data: bytes) -> tuple[list[tuple[str, bytes]], list[str]]:
    """Return ([(filename, payload), ...], notes). Best-effort pure-Python walk."""
    notes: list[str] = []
    if not is_tnef(data):
        return [], ["TNEF: не winmail.dat (нет сигнатуры)"]
    out: list[tuple[str, bytes]] = []
    # Skip signature (4) + key (2)
    pos = 6
    current_name = "winmail_part.bin"
    current_data: bytes | None = None

    def _flush() -> None:
        nonlocal current_name, current_data
        if current_data:
            name = current_name or f"tnef_att_{len(out)+1}.bin"
            # sanitize
            name = Path(name).name.replace("\x00", "")[:180] or f"tnef_att_{len(out)+1}.bin"
            out.append((name, current_data))
        current_name = "winmail_part.bin"
        current_data = None

    while pos + 9 <= len(data):
        try:
            _level = data[pos]
            attr_type_id = struct.unpack_from("<I", data, pos + 1)[0]
            size = struct.unpack_from("<I", data, pos + 5)[0]
        except struct.error:
            notes.append("TNEF: обрыв заголовка атрибута")
            break
        pos += 9
        if size < 0 or pos + size + 2 > len(data):
            notes.append("TNEF: повреждённый размер атрибута")
            break
        payload = data[pos : pos + size]
        pos += size
        # checksum WORD
        pos += 2

        # Low 16 bits often encode the attribute id
        attr_id = attr_type_id & 0xFFFF
        # Heuristics: filename-like small strings
        if size < 512 and size > 0:
            try:
                text = payload.split(b"\x00", 1)[0].decode("latin-1", errors="ignore").strip()
            except UnicodeError:
                text = ""
            if text and ("." in text or "\\" in text or "/" in text) and len(text) < 200:
                # Prefer longer / more path-like names
                base = Path(text.replace("\\", "/")).name
                if base and len(base) > 1:
                    current_name = base
        # Large payloads → attachment data
        if (size >= 32 and attr_id in (0x800F, 0x000F)) or (
            size >= 64 and attr_type_id in (_ATT_ATTACH_DATA, _ATT_DATA)
        ):
            current_data = payload
            _flush()
        elif size >= 256 and current_data is None and not _looks_like_header_only(payload):
            # Fallback: treat sizable blobs as attachments
            current_data = payload
            _flush()

    if current_data:
        _flush()

    if not out:
        # Last-resort: scrape embedded PE/ZIP/PDF magic + nearby ASCII names
        notes.append("TNEF: структурированные вложения не найдены — эвристика magic")
        for magic, suffix in (
            (b"PK\x03\x04", ".zip"),
            (b"%PDF", ".pdf"),
            (b"\xd0\xcf\x11\xe0", ".doc"),
            (b"Rar!", ".rar"),
            (b"\x89PNG", ".png"),
            (b"\xff\xd8\xff", ".jpg"),
        ):
            idx = data.find(magic)
            if idx > 0:
                chunk = data[idx : idx + min(len(data) - idx, 2 * 1024 * 1024)]
                out.append((f"tnef_embedded{suffix}", chunk))
                break

    notes.append(f"TNEF: извлечено вложений: {len(out)}")
    return out[:40], notes


def _looks_like_header_only(payload: bytes) -> bool:
    if len(payload) < 64:
        return True
    # Mostly printable / nulls → likely string map, not binary file
    printable = sum(1 for b in payload[:200] if 32 <= b < 127 or b in (9, 10, 13, 0))
    return printable / max(1, min(len(payload), 200)) > 0.92
