"""Offline QR payload extraction from image bytes (best-effort)."""

from __future__ import annotations

import io
import re

_URL_IN_TEXT = re.compile(r"(?i)\b(?:https?|hxxps?)://[^\s<>\"']+")


def decode_qr_payloads(data: bytes) -> list[str]:
    """Return decoded QR strings. Tries optional backends; never contacts network."""
    payloads: list[str] = []

    # Pillow + pyzbar (common on analyst workstations if libzbar present)
    try:
        from PIL import Image  # type: ignore[import-untyped]
        from pyzbar.pyzbar import decode as zbar_decode  # type: ignore[import-untyped]

        img = Image.open(io.BytesIO(data))
        for obj in zbar_decode(img):
            try:
                text = obj.data.decode("utf-8", errors="replace").strip()
            except Exception:  # noqa: BLE001
                continue
            if text:
                payloads.append(text)
    except Exception:  # noqa: BLE001
        pass

    if payloads:
        return _dedup(payloads)

    # zxing-cpp wheels (optional)
    try:
        import zxingcpp  # type: ignore[import-untyped]
        from PIL import Image  # type: ignore[import-untyped]

        img = Image.open(io.BytesIO(data))
        results = zxingcpp.read_barcodes(img)
        for r in results:
            text = (getattr(r, "text", None) or str(r)).strip()
            if text:
                payloads.append(text)
    except Exception:  # noqa: BLE001
        pass

    return _dedup(payloads)


def _dedup(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def urls_from_payloads(payloads: list[str]) -> list[str]:
    urls: list[str] = []
    for p in payloads:
        urls.extend(_URL_IN_TEXT.findall(p))
        if p.startswith("http://") or p.startswith("https://"):
            urls.append(p)
    return _dedup(urls)
