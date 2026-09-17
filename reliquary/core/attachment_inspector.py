"""Local attachment risk inspection — hashes and heuristic flags only."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

import filetype

from reliquary.core.models import AttachmentInfo

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".cpl",
    ".msi",
    ".msp",
    ".com",
    ".pif",
    ".jar",
    ".iso",
    ".img",
    ".lnk",
    ".reg",
    ".scf",
    ".chm",
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".iso"}
MACRO_OFFICE = {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf"}
DOUBLE_EXT_RE = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|txt|jpg|png|gif)\.(?:exe|scr|bat|cmd|js|vbs|ps1|jar)$",
    re.IGNORECASE,
)


def _hashes(data: bytes) -> tuple[str, str, str]:
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha1(data).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def _guess_mime(data: bytes, filename: str) -> str:
    kind = filetype.guess(data)
    if kind:
        return kind.mime
    ext = Path(filename).suffix.lower()
    fallback = {
        ".eml": "message/rfc822",
        ".msg": "application/vnd.ms-outlook",
        ".pdf": "application/pdf",
        ".html": "text/html",
        ".htm": "text/html",
        ".txt": "text/plain",
        ".csv": "text/csv",
        ".zip": "application/zip",
        ".doc": "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }
    return fallback.get(ext, "application/octet-stream")


def inspect_bytes(filename: str, data: bytes) -> AttachmentInfo:
    md5, sha1, sha256 = _hashes(data)
    mime = _guess_mime(data, filename)
    flags: list[str] = []
    notes: list[str] = []

    lower = filename.lower()
    ext = Path(lower).suffix

    if DOUBLE_EXT_RE.search(lower):
        flags.append("double_extension")
        notes.append("Двойное расширение — классическая маскировка malware")

    if ext in DANGEROUS_EXTENSIONS:
        flags.append("dangerous_extension")
        notes.append(f"Исполняемое/опасное расширение: {ext}")

    if ext in ARCHIVE_EXTENSIONS:
        flags.append("archive")
        notes.append("Архив — проверьте содержимое в изолированной среде")

    if ext in MACRO_OFFICE:
        flags.append("office_macro_capable")
        notes.append("Формат Office может содержать макросы")

    if lower.endswith(".docm") or lower.endswith(".xlsm") or lower.endswith(".pptm"):
        flags.append("macro_enabled_office")
        notes.append("Macro-enabled Office документ")

    # OLE magic
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        flags.append("ole_compound")
        notes.append("OLE Compound File (старый Office / вложения)")
        try:
            import olefile

            if olefile.isOleFile(data):
                ole = olefile.OleFileIO(data)
                streams = ["/".join(p) for p in ole.listdir()]
                ole.close()
                if any("macro" in s.lower() or "vba" in s.lower() for s in streams):
                    flags.append("ole_macros_suspected")
                    notes.append("В OLE обнаружены потоки, похожие на VBA/macros")
        except Exception as exc:  # noqa: BLE001
            notes.append(f"OLE разбор ограничен: {exc}")

    # ZIP / OOXML
    if data[:2] == b"PK":
        flags.append("zip_container")
        if b"word/vbaProject.bin" in data or b"xl/vbaProject.bin" in data:
            flags.append("ooxml_vba")
            notes.append("В OOXML найден vbaProject.bin — макросы")

    # Password-protected zip heuristic
    if ext == ".zip" and b"Encrypt" in data[:4096]:
        flags.append("possibly_encrypted")
        notes.append("Возможно зашифрованный архив")

    if len(data) == 0:
        flags.append("empty_file")
        notes.append("Пустой файл")

    if " " in filename or filename.startswith("."):
        notes.append("Необычное имя файла")

    # Hidden executable via MIME mismatch
    if ext in {".pdf", ".jpg", ".png", ".txt", ".docx"} and mime in {
        "application/x-msdownload",
        "application/x-executable",
        "application/vnd.microsoft.portable-executable",
    }:
        flags.append("mime_mismatch")
        notes.append(f"Расширение {ext}, но MIME похож на executable ({mime})")

    return AttachmentInfo(
        filename=filename,
        size=len(data),
        mime_guess=mime,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        risk_flags=flags,
        notes=notes,
    )


def inspect_file(path: str | os.PathLike[str]) -> AttachmentInfo:
    p = Path(path)
    data = p.read_bytes()
    return inspect_bytes(p.name, data)
