"""Offline QR payload extraction from image bytes (best-effort)."""

from __future__ import annotations

import io


def decode_qr_payloads(data: bytes) -> tuple[list[str], list[str]]:
    """Return (decoded strings, soft-error notes). Never contacts network."""
    payloads: list[str] = []
    notes: list[str] = []
    tried = False

    # Pillow + pyzbar (common on analyst workstations if libzbar present)
    try:
        from PIL import Image  # type: ignore[import-untyped]
        from pyzbar.pyzbar import decode as zbar_decode  # type: ignore[import-untyped]

        tried = True
        img = Image.open(io.BytesIO(data))
        for obj in zbar_decode(img):
            try:
                text = obj.data.decode("utf-8", errors="replace").strip()
            except Exception as exc:  # noqa: BLE001
                notes.append(f"QR pyzbar decode: {exc}")
                continue
            if text:
                payloads.append(text)
    except ImportError:
        notes.append("QR: pyzbar/Pillow не установлены (опционально)")
    except Exception as exc:  # noqa: BLE001
        notes.append(f"QR pyzbar: {exc}")

    if payloads:
        return _dedup(payloads), notes

    # zxing-cpp wheels (optional)
    try:
        import zxingcpp  # type: ignore[import-untyped]
        from PIL import Image  # type: ignore[import-untyped]

        tried = True
        img = Image.open(io.BytesIO(data))
        results = zxingcpp.read_barcodes(img)
        for r in results:
            text = (getattr(r, "text", None) or "").strip()
            if text:
                payloads.append(text)
    except ImportError:
        if not tried:
            notes.append("QR: zxingcpp не установлен (опционально)")
    except Exception as exc:  # noqa: BLE001
        notes.append(f"QR zxing: {exc}")

    # Deduplicate soft notes (optional backends often both missing)
    uniq_notes: list[str] = []
    seen: set[str] = set()
    for n in notes:
        if n not in seen:
            seen.add(n)
            uniq_notes.append(n)
    # Don't spam "not installed" for every image in a batch — keep one short note
    if all("не установлен" in n for n in uniq_notes) and uniq_notes:
        uniq_notes = ["QR: опциональный декодер не установлен"]

    return _dedup(payloads), uniq_notes


def _dedup(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for it in items:
        key = it.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out
