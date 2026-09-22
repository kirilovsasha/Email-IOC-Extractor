"""Unlock encrypted ZIP/7z members with analyst-supplied passwords (offline).

RAR unlock is unsupported (no rarfile/UnRAR).
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from typing import Iterable

from reliquary.core.models import AttachmentInfo

NESTED_MAIL_EXT = frozenset({".eml", ".msg"})
MAX_MEMBER = 8 * 1024 * 1024
MAX_MEMBERS = 12


def _pwd_bytes(passwords: Iterable[str]) -> list[bytes]:
    out: list[bytes] = []
    for p in passwords:
        s = (p or "").strip()
        if not s:
            continue
        raw = s.encode("utf-8")
        if raw not in out:
            out.append(raw)
        # ZIP often uses CP437 / latin-1 for legacy passwords
        try:
            alt = s.encode("cp437", errors="ignore")
        except LookupError:
            alt = b""
        if alt and alt not in out:
            out.append(alt)
    return out


def extract_zip_with_passwords(
    data: bytes, passwords: Iterable[str]
) -> tuple[list[tuple[str, bytes]], list[str]]:
    """Try passwords against encrypted ZIP; return (members, notes)."""
    notes: list[str] = []
    members: list[tuple[str, bytes]] = []
    pwds = _pwd_bytes(passwords)
    if not pwds:
        return members, ["Нет паролей для расшифровки ZIP"]
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        return members, [f"ZIP: {exc}"]
    try:
        encrypted = [zi for zi in zf.infolist() if not zi.is_dir() and (zi.flag_bits & 0x1)]
        targets = encrypted or [zi for zi in zf.infolist() if not zi.is_dir()]
        if not targets:
            notes.append("ZIP: нет файлов для извлечения")
            return members, notes
        # Probe first encrypted member for working password
        working: bytes | None = None
        probe = targets[0]
        for pwd in pwds:
            try:
                zf.setpassword(pwd)
                _ = zf.read(probe)
                working = pwd
                break
            except (RuntimeError, zipfile.BadZipFile, OSError):
                continue
        if working is None:
            notes.append("ZIP: ни один пароль не подошёл")
            return members, notes
        notes.append("ZIP: пароль принят — содержимое извлечено")
        zf.setpassword(working)
        for zi in targets:
            if len(members) >= MAX_MEMBERS:
                notes.append(f"ZIP: лимит {MAX_MEMBERS} членов")
                break
            if zi.file_size > MAX_MEMBER:
                notes.append(f"Пропуск крупного: {zi.filename}")
                continue
            try:
                payload = zf.read(zi)
            except (RuntimeError, zipfile.BadZipFile, OSError, KeyError) as exc:
                notes.append(f"{zi.filename}: {exc}")
                continue
            if len(payload) > MAX_MEMBER:
                continue
            members.append((Path(zi.filename).name or zi.filename, payload))
    finally:
        zf.close()
    return members, notes


def extract_7z_with_passwords(
    data: bytes, passwords: Iterable[str]
) -> tuple[list[tuple[str, bytes]], list[str]]:
    notes: list[str] = []
    members: list[tuple[str, bytes]] = []
    try:
        import py7zr  # type: ignore[import-untyped]
    except ImportError:
        return members, ["7z: py7zr недоступен"]
    for pwd in passwords:
        s = (pwd or "").strip()
        if not s:
            continue
        try:
            with py7zr.SevenZipFile(io.BytesIO(data), mode="r", password=s) as zf:
                names = [n for n in zf.getnames() if n and not n.endswith("/")]
                files = zf.read(names[:MAX_MEMBERS]) or {}
                for name, bio in files.items():
                    payload = bio.read() if hasattr(bio, "read") else bytes(bio)
                    if len(payload) > MAX_MEMBER:
                        continue
                    members.append((Path(name).name or name, payload))
                if members:
                    notes.append("7z: пароль принят — содержимое извлечено")
                    return members, notes
        except Exception as exc:  # noqa: BLE001 — py7zr raises varied types
            notes.append(f"7z pwd try: {type(exc).__name__}")
            continue
    if not members:
        notes.append("7z: ни один пароль не подошёл")
    return members, notes


def extract_archive_members(
    data: bytes, *, filename: str = "", passwords: Iterable[str] | None = None
) -> tuple[list[tuple[str, bytes]], list[str]]:
    pwds = list(passwords or [])
    if not pwds:
        return [], ["Пароль не задан"]
    lower = (filename or "").lower()
    if data[:2] == b"PK" or lower.endswith(".zip"):
        return extract_zip_with_passwords(data, pwds)
    if data[:6] == b"7z\xbc\xaf'\x1c" or lower.endswith(".7z"):
        return extract_7z_with_passwords(data, pwds)
    if data[:4] == b"Rar!" or lower.endswith(".rar"):
        return [], ["RAR: расшифровка не поддерживается"]
    # Fallback probe ZIP
    return extract_zip_with_passwords(data, pwds)


def unlock_attachment(
    att: AttachmentInfo, passwords: Iterable[str]
) -> tuple[AttachmentInfo, list[AttachmentInfo], list[str]]:
    """Re-inventory encrypted attachment; return (updated att, nested mail kids, notes)."""
    from reliquary.core.attachment_inspector import inspect_bytes

    notes: list[str] = []
    kids: list[AttachmentInfo] = []
    if not att.data:
        return att, kids, ["Нет байтов вложения для расшифровки"]
    members, xnotes = extract_archive_members(
        att.data, filename=att.filename, passwords=passwords
    )
    notes.extend(xnotes)
    if not members:
        return att, kids, notes

    # Clear encrypted flag if we unlocked; keep history in notes
    if "encrypted_archive" in att.risk_flags:
        att.risk_flags = [f for f in att.risk_flags if f != "encrypted_archive"]
    att.risk_flags.append("archive_unlocked")
    att.notes.append("Архив расшифрован паролем аналитика (сессия)")
    for name, payload in members:
        if name not in att.archive_entries:
            att.archive_entries.append(name)
        if Path(name).suffix.lower() in NESTED_MAIL_EXT:
            kid = inspect_bytes(name, payload, keep_bytes=True)
            if "nested_email" not in kid.risk_flags:
                kid.risk_flags.append("nested_email")
            kid.notes.append(f"Извлечено из «{att.filename}» после пароля")
            kids.append(kid)
        else:
            # Surface dangerous members as sibling attachments for scoring
            kid = inspect_bytes(name, payload, keep_bytes=True)
            kid.notes.append(f"Извлечено из «{att.filename}» после пароля")
            kids.append(kid)
    return att, kids, notes
