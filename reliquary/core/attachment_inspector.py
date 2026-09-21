"""Local attachment risk inspection — hashes, archives, OLE, QR heuristics."""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from pathlib import Path

import filetype

from reliquary.core.models import AttachmentInfo

MAX_KEEP_BYTES = 8 * 1024 * 1024  # hard cap for nested-email payload
MAX_ARCHIVE_ENTRIES = 200
MAX_NEST_DEPTH = 4
MAX_NESTED_MEMBER_BYTES = 5 * 1024 * 1024
MAX_NESTED_MEMBERS = 12
# Zip-bomb heuristics: reject members with extreme inflate ratios / cumulative bytes
MAX_INFLATE_RATIO = 100
MAX_TOTAL_INFLATED_BYTES = 40 * 1024 * 1024
MAX_ARCHIVE_UNCOMPRESSED_SUM = 80 * 1024 * 1024

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
    ".one",
    ".onepkg",
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".iso"}
MACRO_OFFICE = {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"}
NESTED_MAIL_EXT = {".eml", ".msg"}
WEB_PAYLOAD_EXT = {".html", ".htm", ".shtml", ".mht", ".mhtml", ".svg"}
PDF_EXT = {".pdf"}
DOUBLE_EXT_RE = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|txt|jpg|png|gif)\.(?:exe|scr|bat|cmd|js|vbs|ps1|jar)$",
    re.IGNORECASE,
)

_PDF_JS_RE = re.compile(rb"/(?:JavaScript|JS|OpenAction|AA|Launch)\b")
_PDF_URI_RE = re.compile(rb"/URI\s*\(")
_HTML_SMUGGLE_RE = re.compile(
    rb"(?i)(data:text/html|atob\s*\(|Blob\s*\(|msSaveOrOpenBlob|"
    rb"ActiveXObject|fromCharCode|unescape\s*\(|String\.fromCharCode|"
    rb"HTML smuggling|download\s*=)"
)
_DATA_URI_BIG_RE = re.compile(rb"(?i)data:(?:application|text)[^,]{0,80},[A-Za-z0-9+/=]{800,}")



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
        ".mht": "multipart/related",
        ".mhtml": "multipart/related",
        ".svg": "image/svg+xml",
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
    except zipfile.BadZipFile as exc:
        # Fall through to heuristics; caller may still see BadZipFile notes
        _ = exc
    except OSError as exc:
        _ = exc
    # AES extra field / Encrypt marker heuristic
    if b"Encrypt" in data[:8192] or b"AE\x01" in data[:16384] or b"AE\x02" in data[:16384]:
        return True
    return False


def _inventory_zip(
    data: bytes,
    *,
    depth: int = 0,
    inflated_budget: list[int] | None = None,
) -> tuple[list[str], list[str], list[str]]:
    """Return (entries, risk_flags, notes) for a ZIP/OOXML container. No full extract."""
    entries: list[str] = []
    flags: list[str] = []
    notes: list[str] = []
    if inflated_budget is None:
        inflated_budget = [0]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = [zi for zi in zf.infolist() if not zi.is_dir()]
            names = [zi.filename for zi in infos]
            encrypted = any(zi.flag_bits & 0x1 for zi in zf.infolist())

            if encrypted or _zip_encrypted(data):
                flags.append("encrypted_archive")
                notes.append(
                    "⚠ ЗАЩИЩЁН ПАРОЛЕМ: ZIP encrypted — имена видны, содержимое не извлечено"
                )

            # Declared uncompressed sum (zip-bomb signal without reading)
            try:
                declared = sum(max(0, int(zi.file_size)) for zi in infos)
            except Exception:  # noqa: BLE001
                declared = 0
            if declared > MAX_ARCHIVE_UNCOMPRESSED_SUM:
                flags.append("zip_bomb_suspect")
                notes.append(
                    f"⚠ Zip-bomb: сумма file_size={declared} > {MAX_ARCHIVE_UNCOMPRESSED_SUM}"
                )
                entries = names[:MAX_ARCHIVE_ENTRIES]
                return entries, flags, notes

            entries = names[:MAX_ARCHIVE_ENTRIES]
            if len(names) > MAX_ARCHIVE_ENTRIES:
                notes.append(
                    f"В архиве {len(names)} файлов — показаны первые {MAX_ARCHIVE_ENTRIES}"
                )
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

            nested_archives = [
                zi
                for zi in infos
                if Path(zi.filename).suffix.lower() in ARCHIVE_EXTENSIONS
            ]
            if nested_archives:
                flags.append("nested_archive")
                notes.append("Внутри есть вложенный архив")

            if depth < MAX_NEST_DEPTH and nested_archives:
                peeked = 0
                for zi in nested_archives:
                    if peeked >= MAX_NESTED_MEMBERS:
                        notes.append(
                            f"Вложенные архивы: разобраны первые {MAX_NESTED_MEMBERS}"
                        )
                        break
                    if inflated_budget[0] >= MAX_TOTAL_INFLATED_BYTES:
                        flags.append("zip_bomb_suspect")
                        notes.append("⚠ Zip-bomb: лимит раздутых байт — вложенные пропущены")
                        break
                    if zi.file_size > MAX_NESTED_MEMBER_BYTES:
                        notes.append(
                            f"Пропуск крупного вложенного архива: {Path(zi.filename).name}"
                        )
                        continue
                    csize = max(1, int(zi.compress_size or 0))
                    fsize = max(0, int(zi.file_size or 0))
                    if fsize and (fsize / csize) > MAX_INFLATE_RATIO:
                        flags.append("zip_bomb_suspect")
                        notes.append(
                            f"⚠ Zip-bomb ratio: {Path(zi.filename).name} "
                            f"({fsize}/{csize})"
                        )
                        continue
                    try:
                        nested_data = zf.read(zi)
                    except (KeyError, RuntimeError, OSError, zipfile.BadZipFile) as exc:
                        notes.append(
                            f"Не прочитан {zi.filename} ({type(exc).__name__}): {exc}"
                        )
                        continue
                    if len(nested_data) > MAX_NESTED_MEMBER_BYTES:
                        notes.append(
                            f"Пропуск: inflated {Path(zi.filename).name} "
                            f"> {MAX_NESTED_MEMBER_BYTES}"
                        )
                        continue
                    inflated_budget[0] += len(nested_data)
                    peeked += 1
                    n_entries, n_flags, n_notes = _inventory_zip(
                        nested_data, depth=depth + 1, inflated_budget=inflated_budget
                    )
                    prefix = zi.filename.rstrip("/")
                    entries.extend(f"{prefix}::{e}" for e in n_entries[:80])
                    for fl in n_flags:
                        if fl not in flags:
                            flags.append(fl)
                    for note in n_notes[:4]:
                        notes.append(f"[{Path(zi.filename).name}] {note}")

    except zipfile.BadZipFile:
        notes.append("ZIP: повреждённый или нестандартный контейнер")
        if _zip_encrypted(data):
            flags.append("encrypted_archive")
            notes.append("Возможно зашифрованный ZIP (не удалось открыть)")
        return entries, flags, notes
    except (OSError, RuntimeError, ValueError) as exc:
        notes.append(f"ZIP inventory ({type(exc).__name__}): {exc}")
        return entries, flags, notes

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
            except (AttributeError, OSError, RuntimeError):
                needs_pw = False
            if needs_pw:
                flags.append("encrypted_archive")
                notes.append("⚠ ЗАЩИЩЁН ПАРОЛЕМ: 7z — содержимое недоступно без пароля")
    except (OSError, RuntimeError, ValueError) as exc:
        msg = str(exc).lower()
        if "password" in msg:
            flags.append("encrypted_archive")
            notes.append("7z: требуется пароль")
        else:
            notes.append(f"7z inventory ({type(exc).__name__}): {exc}")
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
        if b"encrypted" in data[:4096].lower() or data[0x18:0x1A] == b"\x04\x00":
            flags.append("encrypted_archive")
            notes.append("Возможно зашифрованный RAR (эвристика)")
        return entries, flags, notes

    # Tool binary may still be missing even if rarfile is installed
    try:
        tool = getattr(rarfile, "UNRAR_TOOL", None) or getattr(rarfile, "ALT_TOOL", None)
        if tool:
            notes.append(f"RAR tool: {tool}")
    except (AttributeError, TypeError):
        pass

    try:
        rf = rarfile.RarFile(io.BytesIO(data))
        if rf.needs_password():
            flags.append("encrypted_archive")
            notes.append("⚠ ЗАЩИЩЁН ПАРОЛЕМ: RAR — содержимое недоступно без пароля")
        names = [i.filename for i in rf.infolist() if not i.is_dir()]
        rf.close()
    except (OSError, RuntimeError, ValueError) as exc:
        flags.append("archive_unlisted")
        err = str(exc).lower()
        if "unrar" in err or "cannot find" in err or "tool" in err:
            flags.append("unrar_missing")
            notes.append("UnRAR.exe/tool не найден — inventory RAR недоступен")
        notes.append(f"RAR inventory ({type(exc).__name__}): {exc}")
        return entries, flags, notes

    entries = names[:MAX_ARCHIVE_ENTRIES]
    notes.append(f"Содержимое RAR: {len(names)} файл(ов)")
    dangerous: list[str] = []
    double_hits: list[str] = []
    nested_mail: list[str] = []
    for name in names:
        base = Path(name).name
        lower = base.lower()
        if DOUBLE_EXT_RE.search(lower):
            double_hits.append(base)
        ext = Path(lower).suffix
        if ext in DANGEROUS_EXTENSIONS:
            dangerous.append(base)
        if ext in NESTED_MAIL_EXT:
            nested_mail.append(base)
    if double_hits:
        flags.append("archive_double_extension")
        notes.append("Двойное расширение внутри RAR: " + ", ".join(double_hits[:8]))
    if dangerous:
        flags.append("archive_dangerous_member")
        notes.append("Опасные члены: " + ", ".join(dangerous[:8]))
    if nested_mail:
        flags.append("archive_nested_email")
        notes.append("Вложенные письма в RAR: " + ", ".join(nested_mail[:8]))
    return entries, flags, notes


def _inventory_cab(data: bytes) -> tuple[list[str], list[str], list[str]]:
    """Lightweight CAB listing via filename string scrape (no full CAB parser)."""
    entries: list[str] = []
    flags: list[str] = ["archive", "cab_archive"]
    notes: list[str] = ["CAB контейнер — офлайн listing по строкам имён"]
    if data[:4] != b"MSCF":
        notes.append("Сигнатура не MSCF — возможно не CAB")
    # Filenames in CFFILE are often null-terminated ASCII near the start
    sample = data[: min(len(data), 256 * 1024)]
    found: list[str] = []
    for m in re.finditer(rb"([\w.\- ]{3,80}\.(?:exe|dll|lnk|bat|cmd|js|vbs|ps1|dll|sys|msi|iso|img))", sample, re.I):
        name = m.group(1).decode("ascii", errors="ignore").strip()
        if name and name not in found:
            found.append(name)
    entries = found[:MAX_ARCHIVE_ENTRIES]
    if entries:
        notes.append(f"Имена в CAB (эвристика): {len(entries)}")
    dangerous = [n for n in entries if Path(n.lower()).suffix in DANGEROUS_EXTENSIONS]
    if dangerous:
        flags.append("archive_dangerous_member")
        notes.append("Опасные члены CAB: " + ", ".join(dangerous[:8]))
    if any(n.lower().endswith(".lnk") for n in entries):
        flags.append("cab_contains_lnk")
        notes.append("CAB содержит .lnk")
    return entries, flags, notes


def _parse_lnk_target(data: bytes) -> tuple[list[str], list[str]]:
    """Best-effort Shell Link target extraction (paths / URLs) without pywin32."""
    flags: list[str] = []
    notes: list[str] = []
    if len(data) < 0x4C or data[:4] != b"L\x00\x00\x00":
        notes.append("LNK: нестандартный заголовок")
        return flags, notes
    targets: list[str] = []
    # ASCII paths / URLs
    for m in re.finditer(
        rb"(?i)((?:[A-Za-z]:\\|\\\\|https?://|file://)[^\x00\r\n]{4,240})",
        data[: min(len(data), 64 * 1024)],
    ):
        try:
            t = m.group(1).decode("ascii", errors="ignore").strip(" \t\"'")
        except UnicodeError:
            continue
        if t and t not in targets:
            targets.append(t)
    # UTF-16LE paths
    try:
        wide = data[: min(len(data), 64 * 1024)].decode("utf-16-le", errors="ignore")
        for m in re.finditer(
            r"(?i)((?:[A-Za-z]:\\|\\\\|https?://|file://)[^\x00\r\n]{4,240})",
            wide,
        ):
            t = m.group(1).strip(" \t\"'")
            if t and t not in targets:
                targets.append(t)
    except UnicodeError:
        pass
    if targets:
        flags.append("lnk_target")
        notes.append("LNK цель: " + "; ".join(targets[:3]))
        for t in targets[:5]:
            notes.append(f"LNK→ {t}")
    else:
        notes.append("LNK: цель не извлечена (проверьте в песочнице)")
    return flags, notes


def _scan_pdf_payload(data: bytes) -> tuple[list[str], list[str]]:
    """Byte heuristics for PDF JS / OpenAction / URI (no full PDF parser)."""
    flags: list[str] = []
    notes: list[str] = []
    head = data[: min(len(data), 512 * 1024)]
    if _PDF_JS_RE.search(head):
        flags.append("pdf_javascript")
        notes.append("PDF: найдены /JS · /JavaScript · /OpenAction · /Launch")
    if _PDF_URI_RE.search(head):
        flags.append("pdf_uri_action")
        notes.append("PDF: найдены /URI-действия (возможны внешние ссылки)")
    return flags, notes


def _scan_web_payload(filename: str, data: bytes) -> tuple[list[str], list[str], str]:
    """Flag HTML/SVG/MHT surface + smuggling heuristics. Returns (flags, notes, nested_kind)."""
    flags: list[str] = []
    notes: list[str] = []
    ext = Path(filename.lower()).suffix
    kind = ""
    if ext in {".html", ".htm", ".shtml"} or b"<html" in data[:4096].lower():
        flags.append("html_attachment")
        kind = "html"
        notes.append("HTML-вложение — офлайн-разбор ссылок/форм")
    elif ext in {".mht", ".mhtml"}:
        flags.append("mht_attachment")
        kind = "mht"
        notes.append("MHTML-вложение — возможен встроенный фишинговый HTML")
    elif ext == ".svg" or b"<svg" in data[:4096].lower():
        flags.append("svg_attachment")
        kind = "svg"
        notes.append("SVG-вложение — возможны script/xlink")
    sample = data[: min(len(data), 1024 * 1024)]
    if _HTML_SMUGGLE_RE.search(sample) or _DATA_URI_BIG_RE.search(sample):
        flags.append("html_smuggling")
        notes.append("Признаки HTML-smuggling (data: URI / atob / Blob / ActiveX)")
    if kind == "svg" and (b"<script" in sample.lower() or b"onload=" in sample.lower()):
        flags.append("svg_script")
        notes.append("SVG содержит script/onload")
    return flags, notes, kind


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
    except (OSError, RuntimeError, ValueError, ImportError) as exc:
        notes.append(f"OLE разбор ограничен ({type(exc).__name__}): {exc}")
    return streams, flags, notes


def _qr_urls_from_image(data: bytes) -> tuple[list[str], list[str]]:
    """Best-effort offline QR decode. Returns (payloads, notes)."""
    try:
        from reliquary.core.qr_scan import decode_qr_payloads

        payloads, notes = decode_qr_payloads(data)
        return payloads, notes
    except (OSError, RuntimeError, ValueError, ImportError) as exc:
        return [], [f"QR: сбой декодера ({type(exc).__name__}: {exc})"]


def inspect_bytes(filename: str, data: bytes, *, keep_bytes: bool | None = None) -> AttachmentInfo:
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

    if ext in {".iso", ".img"}:
        flags.append("iso_image")
        notes.append("Образ диска ISO/IMG — часто доставляет LNK/malware")

    if ext == ".lnk":
        flags.append("shortcut_lnk")
        notes.append("Ярлык Windows (.lnk) — проверьте цель в песочнице")
        lflags, lnotes = _parse_lnk_target(data)
        flags.extend(lflags)
        notes.extend(lnotes)
        for note in lnotes:
            if note.startswith("LNK→ "):
                archive_entries.append(note[5:])

    if ext == ".cab" or data[:4] == b"MSCF":
        flags.append("cab_archive")
        entries, cflags, cnotes = _inventory_cab(data)
        archive_entries = entries + archive_entries
        for f in cflags:
            if f not in flags:
                flags.append(f)
        notes.extend(cnotes)

    if ext in {".one", ".onepkg"} or lower.endswith(".one.tmp"):
        flags.append("onenote_attachment")
        notes.append("OneNote-вложение — возможен встроенный фишинговый контент")

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

    if ext in WEB_PAYLOAD_EXT or (
        mime in {"text/html", "image/svg+xml", "multipart/related"}
        and ext in WEB_PAYLOAD_EXT.union({".html", ".htm", ".svg", ".mht", ".mhtml", ""})
    ):
        if ext in WEB_PAYLOAD_EXT or b"<html" in data[:4096].lower() or b"<svg" in data[:4096].lower():
            wflags, wnotes, wkind = _scan_web_payload(filename, data)
            flags.extend(wflags)
            notes.extend(wnotes)
            if wkind and not nested_kind:
                nested_kind = wkind

    if ext in PDF_EXT or mime == "application/pdf" or data[:5] == b"%PDF-":
        flags.append("pdf_attachment")
        pflags, pnotes = _scan_pdf_payload(data)
        flags.extend(pflags)
        notes.extend(pnotes)

    if (ext in IMAGE_EXTENSIONS or (mime or "").startswith("image/")) and "svg_attachment" not in flags:
        flags.append("image_attachment")
        notes.append("Изображение — проверьте QR / скриншоты фишинга")
        qr_hits, qr_notes = _qr_urls_from_image(data)
        notes.extend(qr_notes)
        if qr_hits:
            flags.append("qr_url")
            notes.append("QR: " + "; ".join(qr_hits[:5]))
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
        if b"word/vbaProject.bin" in data or b"xl/vbaProject.bin" in data or b"ppt/vbaProject.bin" in data:
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
        notes.append("⚠ ЗАЩИЩЁН ПАРОЛЕМ: зашифрованный ZIP")

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

    # Keep payload for nested email, HTML/SVG/MHT, and Office OOXML text extract.
    if keep_bytes is None:
        need_keep = bool(
            {
                "nested_email",
                "html_attachment",
                "mht_attachment",
                "svg_attachment",
            }.intersection(flags)
            or ext in {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
        )
    else:
        need_keep = keep_bytes
    keep = data if need_keep and len(data) <= MAX_KEEP_BYTES else None
    if need_keep and keep is None and data:
        notes.append(
            f"Содержимое не сохранено в памяти (>{MAX_KEEP_BYTES // (1024 * 1024)} МБ) — "
            "вложенный разбор без payload"
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
