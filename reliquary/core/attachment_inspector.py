"""Local attachment risk inspection — hashes and heuristic flags only."""

from __future__ import annotations

import hashlib
import io
import os
import re
import zipfile
from pathlib import Path

import filetype

from reliquary.core.models import AttachmentInfo

# Keep raw bytes for "Save attachments" only up to this size (avoid OOM on big mailboxes).
MAX_KEEP_BYTES = 15 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 200

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
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }
    return fallback.get(ext, "application/octet-stream")


def _inventory_zip(data: bytes) -> tuple[list[str], list[str], list[str]]:
    """Return (entries, risk_flags, notes) for a ZIP/OOXML container. No full extract."""
    entries: list[str] = []
    flags: list[str] = []
    notes: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [zi.filename for zi in zf.infolist() if not zi.is_dir()]
    except zipfile.BadZipFile:
        notes.append("ZIP: повреждённый или нестандартный контейнер")
        return entries, flags, notes
    except Exception as exc:  # noqa: BLE001
        notes.append(f"ZIP inventory: {exc}")
        return entries, flags, notes

    entries = names[:MAX_ARCHIVE_ENTRIES]
    if len(names) > MAX_ARCHIVE_ENTRIES:
        notes.append(f"В архиве {len(names)} файлов — показаны первые {MAX_ARCHIVE_ENTRIES}")
    else:
        notes.append(f"Содержимое архива: {len(names)} файл(ов)")

    dangerous_hits: list[str] = []
    double_hits: list[str] = []
    for name in names:
        base = Path(name).name
        lower = base.lower()
        if DOUBLE_EXT_RE.search(lower):
            double_hits.append(base)
        ext = Path(lower).suffix
        if ext in DANGEROUS_EXTENSIONS:
            dangerous_hits.append(base)

    if double_hits:
        flags.append("archive_double_extension")
        notes.append("Двойное расширение внутри архива: " + ", ".join(double_hits[:8]))
    if dangerous_hits:
        flags.append("archive_dangerous_member")
        notes.append("Опасные члены архива: " + ", ".join(dangerous_hits[:8]))

    # Nested archive heuristic
    if any(Path(n).suffix.lower() in ARCHIVE_EXTENSIONS for n in names):
        flags.append("nested_archive")
        notes.append("Внутри есть вложенный архив")

    return entries, flags, notes


def inspect_bytes(filename: str, data: bytes) -> AttachmentInfo:
    md5, sha1, sha256 = _hashes(data)
    mime = _guess_mime(data, filename)
    flags: list[str] = []
    notes: list[str] = []
    archive_entries: list[str] = []

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

    # ZIP / OOXML inventory (no full extract)
    if data[:2] == b"PK":
        flags.append("zip_container")
        if b"word/vbaProject.bin" in data or b"xl/vbaProject.bin" in data:
            flags.append("ooxml_vba")
            notes.append("В OOXML найден vbaProject.bin — макросы")
        # Inventory plain zip archives (not every OOXML — still useful for .docx names)
        if ext in ARCHIVE_EXTENSIONS or ext == ".zip" or mime == "application/zip":
            entries, zflags, znotes = _inventory_zip(data)
            archive_entries = entries
            flags.extend(zflags)
            notes.extend(znotes)
        elif ext in {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}:
            # Light namelist for Office packages
            entries, zflags, znotes = _inventory_zip(data)
            archive_entries = entries
            flags.extend(zflags)
            notes.extend(znotes)

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

    keep = data if len(data) <= MAX_KEEP_BYTES else None
    if keep is None and data:
        notes.append(
            f"Содержимое не сохранено в памяти (>{MAX_KEEP_BYTES // (1024 * 1024)} МБ) — только хеши"
        )

    return AttachmentInfo(
        filename=filename,
        size=len(data),
        mime_guess=mime,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        risk_flags=flags,
        notes=notes,
        archive_entries=archive_entries,
        data=keep,
    )


def inspect_file(path: str | os.PathLike[str]) -> AttachmentInfo:
    p = Path(path)
    data = p.read_bytes()
    return inspect_bytes(p.name, data)
