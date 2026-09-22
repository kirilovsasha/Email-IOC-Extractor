"""Encrypted archives are a verdict signal. Contents are never extracted."""

from __future__ import annotations

from typing import Iterable

from reliquary.core.models import AttachmentInfo

_NOTE = "Запароленный архив — сигнал: содержимое не извлекается"


def extract_zip_with_passwords(
    data: bytes, passwords: Iterable[str]
) -> tuple[list[tuple[str, bytes]], list[str]]:
    """Refuse ZIP decryption. An encrypted archive is a signal, not a payload."""
    del data, passwords
    return [], [_NOTE]


def extract_7z_with_passwords(
    data: bytes, passwords: Iterable[str]
) -> tuple[list[tuple[str, bytes]], list[str]]:
    """Refuse 7z decryption. An encrypted archive is a signal, not a payload."""
    del data, passwords
    return [], [_NOTE]


def extract_archive_members(
    data: bytes, *, filename: str = "", passwords: Iterable[str] | None = None
) -> tuple[list[tuple[str, bytes]], list[str]]:
    """Refuse archive decryption for every container type."""
    del data, filename, passwords
    return [], [_NOTE]


def unlock_attachment(
    att: AttachmentInfo, passwords: Iterable[str]
) -> tuple[AttachmentInfo, list[AttachmentInfo], list[str]]:
    """Do not decrypt. The ``encrypted_archive`` flag stays on the attachment."""
    del passwords
    return att, [], [_NOTE]
