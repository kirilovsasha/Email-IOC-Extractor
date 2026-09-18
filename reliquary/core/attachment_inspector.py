"""Local attachment risk inspection — hashes, archives, OLE, QR heuristics."""

from __future__ import annotations

import hashlib
import io
import os
import re
import zipfile
from pathlib import Path

import filetype

from reliquary.core.models import AttachmentInfo

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
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"}
NESTED_MAIL_EXT = {".eml", ".msg"}
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
        ".rar": "application/vnd.rar",
        ".7z": "application/x-7z-compressed",
        ".doc": "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
    }
    return fallback.get(ext, "application/octet-stream")


def _zip_encrypted(data: bytes) -> bool:
    """Detect traditional/ZipCrypto or AES encrypted members via flag bits."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x1:
                    return True
    except Exception:  # noqa: BLE001
        pass
    # AES extra field / Encrypt marker heuristic
    if b"Encrypt" in data[:8192] or b"AE\x01" in data[:16384] or b"AE\x02" in data[:16384]:
        return True
    return False


def _inventory_zip(data: bytes) -> tuple[list[str], list[str], list[str]]:
    """Return (entries, risk_flags, notes) for a ZIP/OOXML container. No full extract."""
    entries: list[str] = []
    flags: list[str] = []
    notes: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [zi.filename for zi in zf.infolist() if not zi.is_dir()]
            encrypted = any(zi.flag_bits & 0x1 for zi in zf.infolist())
    except zipfile.BadZipFile:
        notes.append("ZIP: повреждённый или нестандартный контейнер")
        if _zip_encrypted(data):
            flags.append("encrypted_archive")
            notes.append("Возможно зашифрованный ZIP (не удалось открыть)")
        return entries, flags, notes
    except Exception as exc:  # noqa: BLE001
        notes.append(f"ZIP inventory: {exc}")
        return entries, flags, notes

    if encrypted or _zip_encrypted(data):
        flags.append("encrypted_archive")
        notes.append("ZIP с паролем / encrypted members — inventory по именам без извлечения")

    entries = names[:MAX_ARCHIVE_ENTRIES]
    if len(names) > MAX_ARCHIVE_ENTRIES:
        notes.append(f"В архиве {len(names)} файлов — показаны первые {MAX_ARCHIVE_ENTRIES}")
    else:
        notes.append(f"Содержимое архива: {len(names)} файл(ов)")

    dangerous_hits: list[str] = []
    double_hits: list[str] = []
    nested_mail: list[str] = []
    for name in names:
        base = Path(name).name
        lower = base.lower()
        if DOUBLE_EXT_RE.search(lower):
            double_hits.append(base)
        ext = Path(lower).suffix
        if ext in DANGEROUS_EXTENSIONS:
            dangerous_hits.append(base)
        if ext in NESTED_MAIL_EXT:
            nested_mail.append(base)

    if double_hits:
        flags.append("archive_double_extension")
        notes.append("Двойное расширение внутри архива: " + ", ".join(double_hits[:8]))
    if dangerous_hits:
        flags.append("archive_dangerous_member")
        notes.append("Опасные члены архива: " + ", ".join(dangerous_hits[:8]))
    if nested_mail:
        flags.append("archive_nested_email")
        notes.append("Вложенные письма в архиве: " + ", ".join(nested_mail[:8]))

    if any(Path(n).suffix.lower() in ARCHIVE_EXTENSIONS for n in names):
        flags.append("nested_archive")
        notes.append("Внутри есть вложенный архив")

    return entries, flags, notes


def _inventory_7z(data: bytes) -> tuple[list[str], list[str], list[str]]:
    entries: list[str] = []
    flags: list[str] = ["archive", "seven_zip"]
    notes: list[str] = []
    try:
        import py7zr  # type: ignore[import-untyped]
    except ImportError:
        notes.append("7z: установлен py7zr для inventory; пока только сигнатура")
        flags.append("archive_unlisted")
        return entries, flags, notes
    try:
        with py7zr.SevenZipFile(io.BytesIO(data), mode="r") as zf:
            names = [n for n in zf.getnames() if n and not n.endswith("/")]
            needs_pw = False
            try:
                needs_pw = bool(zf.needs_password())
            except Exception:  # noqa: BLE001
                needs_pw = False
            if needs_pw:
                flags.append("encrypted_archive")
                notes.append("7z защищён паролем")
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).lower()
        if "password" in msg:
            flags.append("encrypted_archive")
            notes.append("7z: требуется пароль")
        else:
            notes.append(f"7z inventory: {exc}")
            flags.append("archive_unlisted")
        return entries, flags, notes

    entries = names[:MAX_ARCHIVE_ENTRIES]
    notes.append(f"Содержимое 7z: {len(names)} файл(ов)")
    dangerous = [Path(n).name for n in names if Path(n).suffix.lower() in DANGEROUS_EXTENSIONS]
    if dangerous:
        flags.append("archive_dangerous_member")
        notes.append("Опасные члены: " + ", ".join(dangerous[:8]))
    return entries, flags, notes


def _inventory_rar(data: bytes) -> tuple[list[str], list[str], list[str]]:
    entries: list[str] = []
    flags: list[str] = ["archive", "rar_archive"]
    notes: list[str] = []
    # RAR5 / RAR4 magic
    if data[:7] == b"Rar!\x1a\x07\x01":
        notes.append("RAR5 контейнер")
    elif data[:7] == b"Rar!\x1a\x07\x00":
        notes.append("RAR4 контейнер")
    else:
        notes.append("RAR-подобная сигнатура")

    try:
        import rarfile  # type: ignore[import-untyped]
    except ImportError:
        flags.append("archive_unlisted")
        notes.append("RAR: для полного inventory нужен rarfile+unrar; имена не извлечены")
        # Heuristic: encrypted header bit often near start in RAR4
        if b"encrypted" in data[:4096].lower() or data[0x18:0x1A] == b"\x04\x00":
            flags.append("encrypted_archive")
            notes.append("Возможно зашифрованный RAR (эвристика)")
        return entries, flags, notes

    try:
        rf = rarfile.RarFile(io.BytesIO(data))
        if rf.needs_password():
            flags.append("encrypted_archive")
            notes.append("RAR защищён паролем")
        names = [i.filename for i in rf.infolist() if not i.is_dir()]
        rf.close()
    except Exception as exc:  # noqa: BLE001
        flags.append("archive_unlisted")
        notes.append(f"RAR inventory: {exc}")
        return entries, flags, notes

    entries = names[:MAX_ARCHIVE_ENTRIES]
    notes.append(f"Содержимое RAR: {len(names)} файл(ов)")
    dangerous = [Path(n).name for n in names if Path(n).suffix.lower() in DANGEROUS_EXTENSIONS]
    if dangerous:
        flags.append("archive_dangerous_member")
        notes.append("Опасные члены: " + ", ".join(dangerous[:8]))
    return entries, flags, notes


def _ole_streams(data: bytes) -> tuple[list[str], list[str], list[str]]:
    flags: list[str] = ["ole_compound"]
    notes: list[str] = ["OLE Compound File (старый Office / вложения)"]
    streams: list[str] = []
    try:
        import olefile

        if not olefile.isOleFile(data):
            return streams, flags, notes
        ole = olefile.OleFileIO(data)
        streams = ["/".join(p) for p in ole.listdir()]
        ole.close()
        if any("macro" in s.lower() or "vba" in s.lower() for s in streams):
            flags.append("ole_macros_suspected")
            notes.append("В OLE обнаружены потоки VBA/macros")
        if any("objectpool" in s.lower() or "ole10native" in s.lower() for s in streams):
            flags.append("ole_embedded_object")
            notes.append("В OLE есть встроенные OLE-объекты")
        notes.append(f"OLE потоков: {len(streams)}")
    except Exception as exc:  # noqa: BLE001
        notes.append(f"OLE разбор ограничен: {exc}")
    return streams, flags, notes


def _qr_urls_from_image(data: bytes) -> list[str]:
    """Best-effort offline QR decode. Returns URLs/text payloads."""
    try:
        from reliquary.core.qr_scan import decode_qr_payloads

        return decode_qr_payloads(data)
    except Exception:  # noqa: BLE001
        return []


def inspect_bytes(filename: str, data: bytes) -> AttachmentInfo:
    md5, sha1, sha256 = _hashes(data)
    mime = _guess_mime(data, filename)
    flags: list[str] = []
    notes: list[str] = []
    archive_entries: list[str] = []
    ole_streams: list[str] = []
    nested_kind = ""

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

    if ext in NESTED_MAIL_EXT or mime in {"message/rfc822", "application/vnd.ms-outlook"}:
        flags.append("nested_email")
        nested_kind = "email"
        notes.append("Вложенное письмо (.eml/.msg) — будет разобрано в pipeline")

    if ext in IMAGE_EXTENSIONS or (mime or "").startswith("image/"):
        flags.append("image_attachment")
        notes.append("Изображение — проверьте QR / скриншоты фишинга")
        qr_hits = _qr_urls_from_image(data)
        if qr_hits:
            flags.append("qr_url")
            notes.append("QR: " + "; ".join(qr_hits[:5]))
            # Stash payloads in archive_entries-like field for pipeline IOC lift
            archive_entries.extend(f"QR:{q}" for q in qr_hits[:20])

    # OLE magic
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        streams, oflags, onotes = _ole_streams(data)
        ole_streams = streams
        flags.extend(oflags)
        notes.extend(onotes)

    # ZIP / OOXML
    if data[:2] == b"PK":
        flags.append("zip_container")
        if b"word/vbaProject.bin" in data or b"xl/vbaProject.bin" in data:
            flags.append("ooxml_vba")
            notes.append("В OOXML найден vbaProject.bin — макросы")
        if ext in ARCHIVE_EXTENSIONS or ext == ".zip" or mime == "application/zip":
            entries, zflags, znotes = _inventory_zip(data)
            archive_entries = entries + archive_entries
            flags.extend(zflags)
            notes.extend(znotes)
        elif ext in {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}:
            entries, zflags, znotes = _inventory_zip(data)
            archive_entries = entries + archive_entries
            flags.extend(zflags)
            notes.extend(znotes)

    # 7z magic: 37 7A BC AF 27 1C
    if data[:6] == b"\x37\x7a\xbc\xaf\x27\x1c" or ext == ".7z":
        entries, sflags, snotes = _inventory_7z(data)
        archive_entries = entries or archive_entries
        for f in sflags:
            if f not in flags:
                flags.append(f)
        notes.extend(snotes)

    # RAR magic
    if data[:4] == b"Rar!" or ext == ".rar":
        entries, rflags, rnotes = _inventory_rar(data)
        archive_entries = entries or archive_entries
        for f in rflags:
            if f not in flags:
                flags.append(f)
        notes.extend(rnotes)

    if ext == ".zip" and "encrypted_archive" not in flags and _zip_encrypted(data):
        flags.append("encrypted_archive")
        notes.append("Зашифрованный ZIP")

    if len(data) == 0:
        flags.append("empty_file")
        notes.append("Пустой файл")

    if " " in filename or filename.startswith("."):
        notes.append("Необычное имя файла")

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

    # Dedup flags preserving order
    seen_f: set[str] = set()
    uniq_flags: list[str] = []
    for f in flags:
        if f not in seen_f:
            seen_f.add(f)
            uniq_flags.append(f)

    return AttachmentInfo(
        filename=filename,
        size=len(data),
        mime_guess=mime,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        risk_flags=uniq_flags,
        notes=notes,
        archive_entries=archive_entries,
        ole_streams=ole_streams[:80],
        nested_kind=nested_kind,
        data=keep,
    )


def inspect_file(path: str | os.PathLike[str]) -> AttachmentInfo:
    p = Path(path)
    data = p.read_bytes()
    return inspect_bytes(p.name, data)
