"""Best-effort read-only .pst → temporary .eml expansion (optional pypff)."""

from __future__ import annotations

import tempfile
from pathlib import Path

# Outlook PST/OST magic (!BDN)
PST_MAGIC = b"!BDN"


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
        "Установите `pip install reliquary[pst]` (pypff) или libratom. "
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


def _extract_with_pypff(
    src: Path, dest: Path, *, limit: int, notes: list[str]
) -> list[str]:
    import pypff

    out: list[str] = []
    pst = pypff.file()
    pst.open(str(src))
    try:
        root = pst.get_root_folder()
        _walk_pypff_folder(root, dest, out, limit=limit)
    finally:
        try:
            pst.close()
        except Exception:  # noqa: BLE001
            pass
    notes.append(f"PST pypff: извлечено {len(out)} писем из «{src.name}»")
    return out


def _walk_pypff_folder(folder, dest: Path, out: list[str], *, limit: int) -> None:
    if len(out) >= limit:
        return
    try:
        n = folder.get_number_of_sub_messages()
    except Exception:  # noqa: BLE001
        n = 0
    for i in range(n):
        if len(out) >= limit:
            return
        try:
            msg = folder.get_sub_message(i)
        except Exception:  # noqa: BLE001
            continue
        raw = _pypff_message_to_eml(msg)
        if not raw:
            continue
        name = dest / f"{len(out):04d}.eml"
        name.write_bytes(raw)
        out.append(str(name))
    try:
        n_sub = folder.get_number_of_sub_folders()
    except Exception:  # noqa: BLE001
        n_sub = 0
    for i in range(n_sub):
        if len(out) >= limit:
            return
        try:
            sub = folder.get_sub_folder(i)
        except Exception:  # noqa: BLE001
            continue
        _walk_pypff_folder(sub, dest, out, limit=limit)


def _pypff_message_to_eml(msg) -> bytes:
    """Best-effort RFC822 bytes from a pypff message."""
    try:
        transport = msg.get_transport_headers()
        if transport:
            body = ""
            try:
                body = msg.get_plain_text_body() or ""
            except Exception:  # noqa: BLE001
                try:
                    body = msg.get_html_body() or ""
                except Exception:  # noqa: BLE001
                    body = ""
            if isinstance(body, bytes):
                body_b = body
            else:
                body_b = str(body).encode("utf-8", errors="replace")
            hdr = transport if isinstance(transport, str) else transport.decode("utf-8", "replace")
            if not hdr.endswith("\n"):
                hdr += "\n"
            return (hdr + "\n").encode("utf-8", errors="replace") + body_b
    except Exception:  # noqa: BLE001
        pass
    # Minimal synthetic eml
    subject = ""
    sender = ""
    try:
        subject = msg.get_subject() or ""
    except Exception:  # noqa: BLE001
        pass
    try:
        sender = msg.get_sender_name() or ""
    except Exception:  # noqa: BLE001
        pass
    body = ""
    try:
        body = msg.get_plain_text_body() or ""
    except Exception:  # noqa: BLE001
        pass
    if isinstance(body, bytes):
        body_s = body.decode("utf-8", errors="replace")
    else:
        body_s = str(body)
    return (
        f"From: {sender}\nSubject: {subject}\nMIME-Version: 1.0\n"
        f"Content-Type: text/plain; charset=utf-8\n\n{body_s}\n"
    ).encode("utf-8", errors="replace")


def _extract_with_libratom(
    src: Path, dest: Path, *, limit: int, notes: list[str]
) -> list[str]:
    from libratom.lib.pff import PffArchive

    out: list[str] = []
    with PffArchive(str(src)) as archive:
        for i, message in enumerate(archive.messages()):
            if i >= limit:
                break
            try:
                headers = getattr(message, "headers", None) or ""
                body = getattr(message, "plain_text_body", None) or getattr(
                    message, "html_body", None
                ) or ""
                if isinstance(body, bytes):
                    body_b = body
                else:
                    body_b = str(body).encode("utf-8", errors="replace")
                hdr = headers if isinstance(headers, str) else str(headers)
                if hdr and not hdr.endswith("\n"):
                    hdr += "\n"
                raw = (hdr + "\n").encode("utf-8", errors="replace") + body_b
            except Exception:  # noqa: BLE001
                continue
            name = dest / f"{len(out):04d}.eml"
            name.write_bytes(raw)
            out.append(str(name))
    notes.append(f"PST libratom: извлечено {len(out)} писем из «{src.name}»")
    return out
