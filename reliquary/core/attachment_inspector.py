"""Local attachment risk inspection — hashes, archives, OLE, QR heuristics."""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from pathlib import Path

import filetype

from reliquary.core.models import AttachmentInfo

MAX_KEEP_BYTES = 8 * 1024 * 1024  # hard cap for bytes kept on the attachment
MAX_ARCHIVE_ENTRIES = 200
# Declared sizes only — member bytes are not inflated (sandbox does that).
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
SCRIPT_EXT = {".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".ps1", ".bat", ".cmd"}
DISK_IMAGE_EXT = {".vhd", ".vhdx", ".wim", ".esd"}
LURE_SUFFIXES = (
    ".settingcontent-ms",
    ".searchconnector-ms",
    ".library-ms",
    ".appref-ms",
    ".diagcab",
    ".iqy",
    ".slk",
    ".url",
    ".scf",
    ".chm",
)
DOUBLE_EXT_RE = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|txt|jpg|png|gif)\.(?:exe|scr|bat|cmd|js|vbs|ps1|jar)$",
    re.IGNORECASE,
)
SCRIPT_URL_RE = re.compile(
    r"(?i)(https?://[^\s\"'<>]+|\\\\[a-z0-9._-]+\\[^\s\"'<>]+|"
    r"powershell|wscript|cscript|mshta|cmd\.exe|/c\s+curl|/c\s+wget|"
    r"CreateObject\s*\(\s*[\"']WScript\.Shell|"
    r"ActiveXObject\s*\(|\beval\s*\(|\bFromBase64String\b)"
)

_PDF_JS_RE = re.compile(rb"/(?:JavaScript|JS|OpenAction|AA)\b")
_PDF_OPENACTION_RE = re.compile(rb"/OpenAction\b")
_PDF_URI_RE = re.compile(rb"/URI\s*\(")
_PDF_LAUNCH_RE = re.compile(rb"/Launch\b")
_PDF_SUBMIT_RE = re.compile(rb"/SubmitForm\b")
_PDF_GOTOR_RE = re.compile(rb"/GoToR\b")
_ONENOTE_EMBED_RE = re.compile(
    rb"(?i)(FileData|embeddedFile|EmbeddedFile|OneNote\.Package|ONEDOC|"
    rb"fileDataStore|Embedded File Object)"
)
_HTML_SMUGGLE_RE = re.compile(
    rb"(?i)(data:text/html|atob\s*\(|Blob\s*\(|msSaveOrOpenBlob|"
    rb"ActiveXObject|fromCharCode|unescape\s*\(|String\.fromCharCode|"
    rb"HTML smuggling|download\s*=)"
)
_DATA_URI_BIG_RE = re.compile(rb"(?i)data:(?:application|text)[^,]{0,80},[A-Za-z0-9+/=]{800,}")



# Same order as script / lure shortcut decoders.
PAYLOAD_TEXT_ENCODINGS = ("utf-8", "utf-16", "utf-16-le", "cp1251", "koi8-r", "latin-1")

# These codecs accept every byte, so a declared latin-1/cp1252/koi8-r body can hide another Cyrillic encoding.
_PERMISSIVE_CHARSETS = frozenset(
    {
        "iso-8859-1",
        "iso8859-1",
        "latin-1",
        "latin1",
        "windows-1252",
        "cp1252",
        "windows1252",
        "koi8-r",
        "koi8",
    }
)


def _cyrillic_count(text: str) -> int:
    return sum(1 for ch in text if "\u0400" <= ch <= "\u04FF")


def _cyrillic_lower_count(text: str) -> int:
    """Lowercase Cyrillic. cp1251 and koi8-r both yield letters; the right one is mostly lower."""
    return sum(1 for ch in text if ("\u0430" <= ch <= "\u044f") or ch == "ё")


def _best_cyrillic_text(decoded: dict[str, str], declared: str) -> str:
    best = ""
    best_key = (-1, -1, -1)
    for enc in ("cp1251", "koi8-r"):
        text = decoded.get(enc)
        if not text:
            continue
        prefer = 1 if enc == declared or (enc == "koi8-r" and declared == "koi8") else 0
        key = (_cyrillic_lower_count(text), _cyrillic_count(text), prefer)
        if key > best_key:
            best_key = key
            best = text
    return best


def decode_payload_text(data: bytes, charset: str | None = None) -> str:
    """Decode a mail part. Empty or broken charset uses the attachment encodings.

    A declared charset that decodes cleanly is kept. Encodings that accept every
    byte (latin-1, iso-8859-1, windows-1252, koi8-r) use the same Cyrillic
    comparison as an empty charset. Otherwise UTF-8 wins when it is valid, and
    cp1251 or koi8-r wins when the bytes are clearly Cyrillic.
    """
    if not data:
        return ""
    name = (charset or "").strip().strip('"').strip("'")
    key = name.lower().replace("_", "-")
    if name and key not in _PERMISSIVE_CHARSETS:
        try:
            return data.decode(name)
        except (LookupError, UnicodeError):
            pass
    try:
        return data.decode("utf-8")
    except UnicodeError:
        pass
    decoded: dict[str, str] = {}
    for enc in PAYLOAD_TEXT_ENCODINGS:
        if enc == "utf-8":
            continue
        try:
            decoded[enc] = data.decode(enc)
        except (LookupError, UnicodeError):
            continue
    best = _best_cyrillic_text(decoded, key)
    cyr = _cyrillic_count(best)
    wide = max(
        (_cyrillic_count(decoded.get("utf-16", "")), _cyrillic_count(decoded.get("utf-16-le", "")))
    )
    if cyr >= 4 and cyr > wide:
        return best
    for enc in ("utf-16", "utf-16-le", "latin-1"):
        text = decoded.get(enc)
        if text is None:
            continue
        if text.count("\x00") / max(len(text), 1) < 0.05:
            return text
    if decoded:
        return next(iter(decoded.values()))
    return data.decode("utf-8", errors="replace")


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
        ".ics": "text/calendar",
        ".ical": "text/calendar",
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


def _inventory_zip(data: bytes) -> tuple[list[str], list[str], list[str]]:
    """Names and flags from the ZIP directory. Member bytes are not unpacked."""
    entries: list[str] = []
    flags: list[str] = []
    notes: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = [zi for zi in zf.infolist() if not zi.is_dir()]
            names = [zi.filename for zi in infos]
            encrypted = any(zi.flag_bits & 0x1 for zi in zf.infolist())

            if encrypted or _zip_encrypted(data):
                flags.append("encrypted_archive")
                notes.append(
                    "⚠ ЗАЩИЩЁН ПАРОЛЕМ: ZIP encrypted — сигнал, содержимое не распаковывается"
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
            if any(
                "macrosheets" in n.replace("\\", "/").lower()
                for n in names
            ):
                flags.append("office_xlm")
                notes.append("Excel 4.0 / XLM: xl/macrosheets")

            nested_archives = [
                zi
                for zi in infos
                if Path(zi.filename).suffix.lower() in ARCHIVE_EXTENSIONS
            ]
            if nested_archives:
                flags.append("nested_archive")
                notes.append(
                    "Внутри есть вложенный архив — содержимое не распаковывается (песочница)"
                )

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
    except (OSError, RuntimeError, ValueError, Exception) as exc:  # noqa: BLE001
        # py7zr.Bad7zFile and similar are not always OSError subclasses
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
    """RAR magic + CAB-like filename scrape (no UnRAR / rarfile)."""
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
    sample = data[: min(len(data), 256 * 1024)]
    found: list[str] = []
    for m in re.finditer(
        rb"([\w.\- ]{3,80}\.(?:exe|dll|scr|lnk|bat|cmd|js|vbs|ps1|hta|msi|"
        rb"iso|img|eml|msg|doc|docx|pdf|zip|rar)(?:;1)?)",
        sample,
        re.I,
    ):
        name = m.group(1).decode("ascii", errors="ignore").strip().split(";")[0]
        if name and name not in found:
            found.append(name)
    entries = found[:MAX_ARCHIVE_ENTRIES]
    if entries:
        notes.append(f"Имена в RAR (эвристика): {len(entries)}")
    else:
        flags.append("archive_unlisted")
        notes.append("RAR: inventory членов не выполняется (имена не извлечены)")
    dangerous = [n for n in entries if Path(n.lower()).suffix in DANGEROUS_EXTENSIONS]
    if dangerous:
        flags.append("archive_dangerous_member")
        notes.append("Опасные члены RAR: " + ", ".join(dangerous[:8]))
    double_hits = [n for n in entries if DOUBLE_EXT_RE.search(n.lower())]
    if double_hits:
        flags.append("archive_double_extension")
        notes.append("Двойное расширение в RAR: " + ", ".join(double_hits[:8]))
    nested_mail = [n for n in entries if Path(n.lower()).suffix in NESTED_MAIL_EXT]
    if nested_mail:
        flags.append("archive_nested_email")
        notes.append("Вложенные письма в RAR: " + ", ".join(nested_mail[:8]))
    if b"encrypted" in data[:4096].lower() or data[0x18:0x1A] == b"\x04\x00":
        flags.append("encrypted_archive")
        notes.append("Возможно зашифрованный RAR (эвристика)")
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


def _inventory_iso(data: bytes) -> tuple[list[str], list[str], list[str]]:
    """Best-effort ISO9660 / Joliet name scrape (no full mount)."""
    flags: list[str] = ["iso_image"]
    notes: list[str] = ["ISO/IMG — эвристический listing имён"]
    entries: list[str] = []
    head = data[: min(len(data), 1024 * 1024)]
    found: list[str] = []
    for m in re.finditer(
        rb"([A-Za-z0-9_\-\.]{3,80}\.(?:EXE|DLL|LNK|JS|JSE|VBS|VBE|WSF|WSH|BAT|CMD|PS1|HTA|SCR|HTML?|HTM|ZIP|RAR|ISO|IMG|PDF|DOC|DOCX|URL|IQY|SLK)(?:;1)?)",
        head,
        flags=re.IGNORECASE,
    ):
        try:
            name = m.group(1).decode("ascii", errors="ignore").split(";")[0]
        except UnicodeError:
            continue
        if name and name not in found:
            found.append(name)
    try:
        wide = head.decode("utf-16-le", errors="ignore")
        for wm in re.finditer(
            r"([A-Za-z0-9_\-\.]{3,80}\.(?:exe|dll|lnk|js|jse|vbs|vbe|wsf|wsh|bat|cmd|ps1|hta|scr|html?|htm|zip|rar|iso|img|pdf|doc|docx|url|iqy|slk))",
            wide,
            flags=re.IGNORECASE,
        ):
            name = wm.group(1)
            if name and name not in found:
                found.append(name)
    except UnicodeError:
        pass
    entries = found[:MAX_ARCHIVE_ENTRIES]
    if entries:
        notes.append(f"Имена в ISO (эвристика): {len(entries)}")
    else:
        notes.append("ISO: имена членов не извлечены (проверьте в песочнице)")
    dangerous = [n for n in entries if Path(n.lower()).suffix in DANGEROUS_EXTENSIONS]
    if dangerous:
        flags.append("archive_dangerous_member")
        notes.append("Опасные члены ISO: " + ", ".join(dangerous[:8]))
    if any(n.lower().endswith(".lnk") for n in entries):
        flags.append("iso_contains_lnk")
        notes.append("ISO содержит .lnk")
    if any(Path(n.lower()).suffix in {".exe", ".dll", ".scr"} for n in entries):
        flags.append("iso_contains_exe")
        notes.append("ISO содержит .exe/.dll/.scr")
    if any(Path(n.lower()).suffix in SCRIPT_EXT for n in entries):
        flags.append("iso_contains_script")
        notes.append("ISO содержит скрипт (.js/.vbs/.hta/…)")
    return entries, flags, notes


def _inventory_disk_image(data: bytes, *, ext: str) -> tuple[list[str], list[str], list[str]]:
    """Best-effort VHD/VHDX/WIM name scrape (offline heuristics, no mount)."""
    label = ext.lstrip(".").upper() or "DISK"
    flags: list[str] = ["disk_image"]
    notes: list[str] = [f"{label} — эвристический listing имён (без монтирования)"]
    head = data[: min(len(data), 2 * 1024 * 1024)]
    found: list[str] = []
    for m in re.finditer(
        rb"([A-Za-z0-9_\-\.]{3,80}\.(?:EXE|DLL|LNK|JS|JSE|VBS|VBE|WSF|WSH|BAT|CMD|PS1|HTA|SCR|HTML?|HTM|ZIP|RAR|ISO|IMG|PDF|URL|IQY|SLK)(?:;1)?)",
        head,
        flags=re.IGNORECASE,
    ):
        try:
            name = m.group(1).decode("ascii", errors="ignore").split(";")[0]
        except UnicodeError:
            continue
        if name and name not in found:
            found.append(name)
    try:
        wide = head.decode("utf-16-le", errors="ignore")
        for wm in re.finditer(
            r"([A-Za-z0-9_\-\.]{3,80}\.(?:exe|dll|lnk|js|jse|vbs|vbe|wsf|wsh|bat|cmd|ps1|hta|scr|html?|htm|zip|rar|iso|img|pdf|url|iqy|slk))",
            wide,
            flags=re.IGNORECASE,
        ):
            name = wm.group(1)
            if name and name not in found:
                found.append(name)
    except UnicodeError:
        pass
    entries = found[:MAX_ARCHIVE_ENTRIES]
    if entries:
        notes.append(f"Имена в {label} (эвристика): {len(entries)}")
    else:
        notes.append(f"{label}: имена членов не извлечены — разберите в песочнице")
    dangerous = [n for n in entries if Path(n.lower()).suffix in DANGEROUS_EXTENSIONS]
    if dangerous:
        flags.append("archive_dangerous_member")
        notes.append("Опасные члены: " + ", ".join(dangerous[:8]))
    if any(n.lower().endswith(".lnk") for n in entries):
        flags.append("iso_contains_lnk")
        notes.append(f"{label} содержит .lnk")
    if any(Path(n.lower()).suffix in {".exe", ".dll", ".scr"} for n in entries):
        flags.append("disk_contains_exe")
        notes.append(f"{label} содержит .exe/.dll/.scr")
    if any(Path(n.lower()).suffix in SCRIPT_EXT for n in entries):
        flags.append("disk_contains_script")
        notes.append(f"{label} содержит скрипт (.js/.vbs/.hta/…)")
    return entries, flags, notes


def _scan_script_payload(filename: str, data: bytes) -> tuple[list[str], list[str], list[str]]:
    """Scan HTA/JS/VBS/WSF/PS1/BAT for URLs and classic living-off-the-land markers."""
    flags: list[str] = ["script_attachment"]
    notes: list[str] = [f"Скрипт-вложение «{Path(filename).name}» — разбор офлайн"]
    entries: list[str] = []
    # Decode as text (UTF-8 / CP1251 / latin-1 fallback)
    text = ""
    for enc in ("utf-8", "utf-16-le", "cp1251", "latin-1"):
        try:
            text = data[: min(len(data), 512 * 1024)].decode(enc)
            break
        except UnicodeError:
            continue
    if not text:
        notes.append("Скрипт: не удалось декодировать текст")
        return entries, flags, notes
    hits = SCRIPT_URL_RE.findall(text)
    urls = [h for h in hits if isinstance(h, str) and h.lower().startswith(("http://", "https://", "\\\\"))]
    if not urls:
        # findall with one group returns strings; without may return tuples — normalize
        for h in hits:
            s = h if isinstance(h, str) else (h[0] if h else "")
            if s.lower().startswith(("http://", "https://", "\\\\")):
                urls.append(s)
    for u in urls[:20]:
        entries.append(f"SCRIPT→ {u[:180]}")
    if urls:
        flags.append("script_url")
        notes.append(f"URL/UNC в скрипте: {len(urls)}")
    if any(
        x in text.lower()
        for x in ("powershell", "wscript", "mshta", "frombase64string", "createobject")
    ):
        notes.append("Маркеры WSH/PowerShell/LOLBin в теле скрипта")
    return entries, flags, notes


def extract_nested_mail_from_archive(
    data: bytes,
    *,
    container_name: str = "archive",
) -> tuple[list["AttachmentInfo"], list[str]]:
    """Do not unpack archive members. That belongs in a sandbox."""
    del data, container_name
    return [], ["Архив не распаковывается: содержимое разбирается в песочнице"]


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
    # UTF-16LE paths (separate match var — mypy: Match[bytes] vs Match[str])
    try:
        wide = data[: min(len(data), 64 * 1024)].decode("utf-16-le", errors="ignore")
        for wm in re.finditer(
            r"(?i)((?:[A-Za-z]:\\|\\\\|https?://|file://)[^\x00\r\n]{4,240})",
            wide,
        ):
            t = wm.group(1).strip(" \t\"'")
            if t and t not in targets:
                targets.append(t)
    except UnicodeError:
        pass
    if targets:
        flags.append("lnk_target")
        notes.append("LNK цель: " + "; ".join(targets[:3]))
        for t in targets[:5]:
            notes.append(f"LNK→ {t}")
        joined = "\n".join(targets)
        if re.search(
            r"(?i)(cmd\.exe|powershell|pwsh(\.exe)?|wscript|cscript|mshta|rundll32|"
            r"certutil|bitsadmin|msiexec|regsvr32|forfiles|conhost|finger(?:\.exe)?)",
            joined,
        ):
            flags.append("lnk_dangerous")
            notes.append("LNK: цель указывает на интерпретатор / cmd")
        if re.search(r"(?i)(https?://|file://|\\\\)", joined):
            flags.append("lnk_http_target")
            notes.append("LNK: цель — URL или UNC-путь")
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
        notes.append("PDF: найдены /JS · /JavaScript · /OpenAction")
    if _PDF_LAUNCH_RE.search(head):
        flags.append("pdf_launch")
        notes.append("PDF: /Launch — запуск внешней программы")
    if _PDF_SUBMIT_RE.search(head):
        flags.append("pdf_submitform")
        notes.append("PDF: /SubmitForm — отправка формы наружу")
    if _PDF_GOTOR_RE.search(head):
        flags.append("pdf_gotor")
        notes.append("PDF: /GoToR — переход в удалённый PDF")
    if _PDF_URI_RE.search(head):
        flags.append("pdf_uri_action")
        notes.append("PDF: найдены /URI-действия (возможны внешние ссылки)")
    if _PDF_OPENACTION_RE.search(head) and _PDF_URI_RE.search(head):
        flags.append("pdf_openaction_uri")
        notes.append("PDF: OpenAction + /URI вместе — типичный PDF-lure")
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
    if kind in {"html", "mht", "svg"} and _html_form_action_suspicious(sample):
        flags.append("html_form_action")
        notes.append("HTML: form action на IP или подозрительный TLD")
    # HTML polyglot: HTML magic near start + ZIP/PDF magic later in first 8KB
    head8 = data[: min(len(data), 8192)]
    htmlish = bool(
        re.search(rb"(?i)<!DOCTYPE\s+html|<html[\s>]|<head[\s>]|<body[\s>]", head8[:512])
        or ext in {".html", ".htm", ".shtml"}
    )
    if htmlish and (b"PK\x03\x04" in head8[32:] or b"%PDF" in head8[32:]):
        flags.append("html_polyglot")
        notes.append("HTML-polyglot: HTML + ZIP/PDF magic в первых 8 КБ")
    return flags, notes, kind


_HTML_FORM_ACTION_RE = re.compile(
    rb"(?is)<form\b[^>]{0,500}?\baction\s*=\s*['\"]([^'\"]{1,240})"
)


def _html_form_action_suspicious(data: bytes) -> bool:
    """Form in an HTML/MHT/SVG attachment posts to an IP or a suspicious TLD."""
    from reliquary.core.verdict_config import DEFAULT_SUSPICIOUS_TLDS

    for match in _HTML_FORM_ACTION_RE.finditer(data[: min(len(data), 256 * 1024)]):
        action = match.group(1).decode("ascii", errors="ignore").strip().lower()
        if not action or action.startswith(("#", "mailto:")):
            continue
        host = action.split("://", 1)[-1] if "://" in action else action
        host = host.split("/", 1)[0].split("?", 1)[0].split("@")[-1].strip("[]")
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
            return True
        if any(host.endswith(tld) for tld in DEFAULT_SUSPICIOUS_TLDS):
            return True
    return False


def _detect_html_polyglot(data: bytes) -> bool:
    """True if HTML magic near start and ZIP/PDF magic later within first 8KB."""
    if not data:
        return False
    head8 = data[: min(len(data), 8192)]
    if not re.search(rb"(?i)<!DOCTYPE\s+html|<html[\s>]|<head[\s>]|<body[\s>]", head8[:512]):
        return False
    return b"PK\x03\x04" in head8[32:] or b"%PDF" in head8[32:]


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
        if any(
            "ole10native" in s.lower() or s.lower().endswith("/package") or s.lower() == "package"
            for s in streams
        ):
            flags.append("ole_package")
            notes.append("OLE Package / Ole10Native — встроенный исполняемый пакет")
        notes.append(f"OLE потоков: {len(streams)}")
    except (OSError, RuntimeError, ValueError, ImportError) as exc:
        notes.append(f"OLE разбор ограничен ({type(exc).__name__}): {exc}")
    return streams, flags, notes


def _qr_urls_from_image(data: bytes) -> tuple[list[str], list[str]]:
    """Best-effort offline QR decode. Returns (payloads, notes)."""
    try:
        from reliquary.core.qr_scan import decode_qr_payloads

        payloads, notes = decode_qr_payloads(data)
        if notes and not payloads and not any("сбой декодера" in n for n in notes):
            notes.append("QR: сбой декодера")
        return payloads, notes
    except (OSError, RuntimeError, ValueError, ImportError) as exc:
        return [], [f"QR: сбой декодера ({type(exc).__name__}: {exc})"]


def _qr_from_pdf_bytes(data: bytes) -> tuple[list[str], list[str]]:
    """Best-effort: find embedded JPEG/PNG streams in PDF and run QR decode."""
    notes: list[str] = []
    hits: list[str] = []
    if not data.startswith(b"%PDF"):
        return hits, notes
    try:
        from reliquary.core.qr_scan import decode_qr_payloads, qr_decoder_available
    except ImportError:
        return hits, ["QR PDF: модуль недоступен"]
    if not qr_decoder_available():
        return hits, []
    decoder_failed = False
    for magic, label in ((b"\xff\xd8\xff", "jpeg"), (b"\x89PNG\r\n\x1a\n", "png")):
        start = 0
        found = 0
        while True:
            idx = data.find(magic, start)
            if idx < 0:
                break
            if found >= 4:
                notes.append(f"QR PDF {label}: просмотрено 4, дальше не декодировалось")
                break
            if label == "jpeg":
                end = data.find(b"\xff\xd9", idx + 2)
                chunk = data[
                    idx : (end + 2 if end > idx else idx + min(512_000, len(data) - idx))
                ]
            else:
                end = data.find(b"IEND", idx + 8)
                chunk = data[
                    idx : (end + 8 if end > idx else idx + min(512_000, len(data) - idx))
                ]
            if len(chunk) >= 64:
                payloads, dec_notes = decode_qr_payloads(chunk)
                if dec_notes and not payloads:
                    decoder_failed = True
                for p in payloads:
                    if p not in hits:
                        hits.append(p)
            start = idx + 4
            found += 1
    if decoder_failed:
        notes.append("QR: сбой декодера")
    if hits:
        notes.append("QR PDF: " + "; ".join(hits))
    return hits[:20], notes


def _lure_suffix(filename: str) -> str:
    lower = filename.lower()
    for suffix in LURE_SUFFIXES:
        if lower.endswith(suffix):
            return suffix
    return ""


def _scan_lure_shortcut(filename: str, data: bytes) -> tuple[list[str], list[str], list[str]]:
    """Internet Shortcut / IQY / SYLK / settings / SCF / CHM — pull URL or UNC target."""
    flags = ["lure_shortcut"]
    notes: list[str] = [f"Файл-ярлык «{Path(filename).name}»"]
    entries: list[str] = []
    text = ""
    sample = data[: min(len(data), 512 * 1024)]
    for enc in ("utf-8", "utf-16", "utf-16-le", "cp1251", "latin-1"):
        try:
            text = sample.decode(enc)
            break
        except UnicodeError:
            continue
    found: list[str] = []
    ini = re.search(r"(?im)^(?:URL|IconFile|DeepLink)\s*=\s*(\S+)", text)
    if ini:
        found.append(ini.group(1).strip())
    for match in re.finditer(r"(?i)(?:https?://|file://|search-ms:|ms-msdt:|\\\\)[^\s\"'<>]{3,200}", text):
        value = match.group(0).rstrip(").,;]")
        if value not in found:
            found.append(value)
    if found:
        flags.append("lure_shortcut_target")
        entries.extend(found[:8])
        notes.append("Цель ярлыка: " + found[0][:120])
    else:
        notes.append("Цель ярлыка не извлечена")
    return flags, notes, entries


def _scan_rtf(data: bytes) -> tuple[list[str], list[str]]:
    """RTF object update / Equation Editor / embedded OLE."""
    head = data[: min(len(data), 1024 * 1024)].lower()
    flags: list[str] = []
    notes: list[str] = []
    if b"\\objupdate" in head:
        flags.append("rtf_objupdate")
        notes.append("RTF: \\objupdate — объект обновляется при открытии")
    if b"equation.3" in head or b"equation.2" in head:
        flags.append("rtf_equation")
        notes.append("RTF: Equation Editor OLE")
    if b"\\objdata" in head and (b"\\objupdate" in head or b"equation" in head or b"package" in head):
        flags.append("rtf_ole")
        notes.append("RTF: встроенный OLE (\\objdata)")
    if flags:
        flags.append("rtf_exploit")
    return flags, notes


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

    lure = _lure_suffix(lower)
    if lure:
        lflags, lnotes, lentries = _scan_lure_shortcut(filename, data)
        for flag in lflags:
            if flag not in flags:
                flags.append(flag)
        notes.extend(lnotes)
        archive_entries.extend(lentries)

    if ext == ".rtf" or data[:6].lower().startswith(b"{\\rtf"):
        rflags, rnotes = _scan_rtf(data)
        for flag in rflags:
            if flag not in flags:
                flags.append(flag)
        notes.extend(rnotes)

    if ext in {".iso", ".img"}:
        flags.append("iso_image")
        notes.append("Образ диска ISO/IMG — часто доставляет LNK/malware")
        entries, iflags, inotes = _inventory_iso(data)
        archive_entries = entries + archive_entries
        for f in iflags:
            if f not in flags:
                flags.append(f)
        notes.extend(inotes)

    if ext in DISK_IMAGE_EXT:
        flags.append("disk_image")
        notes.append(f"Образ {ext} — часто доставляет LNK/malware (VHD/WIM)")
        entries, dflags, dnotes = _inventory_disk_image(data, ext=ext)
        archive_entries = entries + archive_entries
        for f in dflags:
            if f not in flags:
                flags.append(f)
        notes.extend(dnotes)

    if ext in SCRIPT_EXT or (
        ext in DANGEROUS_EXTENSIONS and ext in {".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".ps1", ".bat", ".cmd"}
    ):
        s_entries, sflags, snotes = _scan_script_payload(filename, data)
        archive_entries = s_entries + archive_entries
        for f in sflags:
            if f not in flags:
                flags.append(f)
        notes.extend(snotes)

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
        sample = data[: min(len(data), 1024 * 1024)]
        if _ONENOTE_EMBED_RE.search(sample):
            flags.append("onenote_embedded_file")
            notes.append("OneNote: маркеры FileData / embeddedFile — встроенный файл")
        elif b"FileData" in sample or b"embeddedFile" in sample:
            flags.append("onenote_embedded_file")
            notes.append("OneNote: маркеры встроенного файла")

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
    elif _detect_html_polyglot(data):
        flags.append("html_polyglot")
        notes.append("HTML-polyglot: HTML + ZIP/PDF magic в первых 8 КБ")
        wflags, wnotes, wkind = _scan_web_payload(filename, data)
        for f in wflags:
            if f not in flags:
                flags.append(f)
        notes.extend(wnotes)
        if wkind and not nested_kind:
            nested_kind = wkind

    if ext in PDF_EXT or mime == "application/pdf" or data[:5] == b"%PDF-":
        flags.append("pdf_attachment")
        pflags, pnotes = _scan_pdf_payload(data)
        flags.extend(pflags)
        notes.extend(pnotes)
        # Best-effort: decode embedded raster as QR
        qr_hits, qr_notes = _qr_from_pdf_bytes(data)
        notes.extend(qr_notes)
        if qr_hits:
            flags.append("qr_url")
            notes.append("QR в PDF: " + "; ".join(qr_hits))
            archive_entries.extend(f"QR:{q}" for q in qr_hits)

    # TNEF / winmail.dat
    if (
        lower in {"winmail.dat", "win.dat"}
        or mime in {"application/ms-tnef", "application/vnd.ms-tnef"}
        or (ext == ".dat" and data[:4] == b"\x78\x9f\x3e\x22")
    ):
        flags.append("tnef_attachment")
        notes.append("TNEF / winmail.dat — вложения будут извлечены офлайн")


    if (ext in IMAGE_EXTENSIONS or (mime or "").startswith("image/")) and "svg_attachment" not in flags:
        flags.append("image_attachment")
        notes.append("Изображение — проверьте QR / скриншоты фишинга")
        qr_hits, qr_notes = _qr_urls_from_image(data)
        notes.extend(qr_notes)
        if qr_hits:
            flags.append("qr_url")
            notes.append("QR: " + "; ".join(qr_hits))
            archive_entries.extend(f"QR:{q}" for q in qr_hits)

    # OLE magic
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        streams, oflags, onotes = _ole_streams(data)
        ole_streams = streams
        flags.extend(oflags)
        notes.extend(onotes)
        if b"Excel 4.0" in data[: min(len(data), 1_500_000)] and "office_xlm" not in flags:
            flags.append("office_xlm")
            notes.append("OLE: маркер Excel 4.0 (XLM)")
        if b"Ole10Native" in data[: min(len(data), 512 * 1024)] and "ole_package" not in flags:
            flags.append("ole_package")
            notes.append("OLE: найден поток Ole10Native (Package)")
        if b"Package" in data[:4096] and "ole_package" not in flags and b"Ole10Native" in data:
            flags.append("ole_package")
            notes.append("OLE Package stream")

    # ZIP / OOXML
    if data[:2] == b"PK":
        flags.append("zip_container")
        if b"word/vbaProject.bin" in data or b"xl/vbaProject.bin" in data or b"ppt/vbaProject.bin" in data:
            flags.append("ooxml_vba")
            notes.append("В OOXML найден vbaProject.bin — макросы")
        if b"xl/macrosheets" in data or b"xl\\macrosheets" in data:
            if "office_xlm" not in flags:
                flags.append("office_xlm")
                notes.append("Excel 4.0 / XLM: xl/macrosheets")
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
            try:
                from reliquary.core.office_extract import (
                    detect_office_dde,
                    detect_office_external_data,
                    detect_office_remote_template,
                )

                if detect_office_remote_template(data):
                    flags.append("office_remote_template")
                    notes.append("OOXML: remote template / TargetMode=External http(s)")
                if detect_office_dde(data):
                    flags.append("office_dde")
                    notes.append("OOXML: Excel DDE / formula injection markers")
                if detect_office_external_data(data):
                    flags.append("office_external_data")
                    notes.append("OOXML: connections / externalLinks / WEBSERVICE|HYPERLINK")
            except (OSError, ValueError, TypeError, RuntimeError, ImportError):
                pass
        if b"EncryptionInfo" in data[:65536] or b"EncryptedPackage" in data[:65536]:
            flags.append("office_encrypted")
            notes.append("Зашифрованный Office (EncryptionInfo / EncryptedPackage)")

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

    if "ooxml_vba" in flags or "ole_macros_suspected" in flags:
        try:
            from reliquary.core.office_extract import detect_office_vba_live

            if detect_office_vba_live(data):
                flags.append("office_vba_live")
                notes.append(
                    "VBA: автозапуск или загрузка (AutoOpen / Shell / URLDownloadToFile)"
                )
        except (OSError, ValueError, TypeError, RuntimeError, ImportError):
            pass

    if ext in {".pdf", ".jpg", ".png", ".txt", ".docx"} and mime in {
        "application/x-msdownload",
        "application/x-executable",
        "application/vnd.microsoft.portable-executable",
    }:
        flags.append("mime_mismatch")
        notes.append(f"Расширение {ext}, но MIME похож на executable ({mime})")

    # Keep payload for nested email, HTML/SVG/MHT, Office OOXML, archives with nested mail, TNEF.
    if keep_bytes is None:
        need_keep = bool(
            {
                "nested_email",
                "html_attachment",
                "mht_attachment",
                "svg_attachment",
                "archive_nested_email",
                "tnef_attachment",
            }.intersection(flags)
            or ext in {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
            or ext in {".ics", ".ical"}
            or (mime or "").lower() == "text/calendar"
            or lower in {"winmail.dat", "win.dat"}
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
