"""Window geometry helpers (kept out of the CTk app module for unit tests)."""

from __future__ import annotations

import re
import sys

_DEFAULT_W = 1320
_DEFAULT_H = 820
_ABS_MIN_W = 640
_ABS_MIN_H = 480
_GEOM_SIZE = re.compile(r"^(?P<w>\d+)x(?P<h>\d+)$")
_GEOM_FULL = re.compile(r"^(?P<w>\d+)x(?P<h>\d+)(?P<x>[+-]\d+)(?P<y>[+-]\d+)$")


def parse_geometry(geom: str) -> tuple[int, int, int | None, int | None]:
    """Parse Tk `WxH` or `WxH±X±Y`. Invalid input → default size, no position."""
    raw = (geom or "").strip()
    full = _GEOM_FULL.match(raw)
    if full:
        return int(full["w"]), int(full["h"]), int(full["x"]), int(full["y"])
    size = _GEOM_SIZE.match(raw)
    if size:
        return int(size["w"]), int(size["h"]), None, None
    return _DEFAULT_W, _DEFAULT_H, None, None


def size_only_geometry(geom: str) -> str:
    """Keep ``WxH`` for prefs — position is recalculated on each launch."""
    w, h, _, _ = parse_geometry(geom)
    return f"{w}x{h}"


def titlebar_is_visible(
    x: int,
    y: int,
    *,
    virtual: tuple[int, int, int, int],
    min_w: int = 80,
    min_h: int = 16,
) -> bool:
    """True if enough of the title bar intersects the virtual desktop."""
    vx, vy, vw, vh = virtual
    tw, th = 160, 28
    ix0 = max(x, vx)
    iy0 = max(y, vy)
    ix1 = min(x + tw, vx + vw)
    iy1 = min(y + th, vy + vh)
    return (ix1 - ix0) >= min_w and (iy1 - iy0) >= min_h


def primary_work_area() -> tuple[int, int, int, int] | None:
    """Windows primary monitor work area (excludes taskbar): ``(x, y, w, h)``.

    Returns ``None`` on non-Windows or if the API call fails.
    """
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class RECT(ctypes.Structure):
            _fields_ = [
                ("left", wintypes.LONG),
                ("top", wintypes.LONG),
                ("right", wintypes.LONG),
                ("bottom", wintypes.LONG),
            ]

        rect = RECT()
        spi_getworkarea = 0x0030
        ok = ctypes.windll.user32.SystemParametersInfoW(
            spi_getworkarea, 0, ctypes.byref(rect), 0
        )
        if not ok:
            return None
        w = int(rect.right - rect.left)
        h = int(rect.bottom - rect.top)
        if w < 320 or h < 240:
            return None
        return int(rect.left), int(rect.top), w, h
    except Exception:  # noqa: BLE001
        return None


def _usable_area(
    screen: tuple[int, int],
    work_area: tuple[int, int, int, int] | None,
    *,
    margin: int,
) -> tuple[int, int, int, int]:
    """Return ``(x, y, w, h)`` for placing the window fully on-screen.

    Drops ``work_area`` when it disagrees with Tk screen metrics (DPI mismatch).
    """
    sw, sh = max(1, screen[0]), max(1, screen[1])
    if work_area is not None:
        ax, ay, aw, ah = work_area
        # Same coordinate space as Tk: work area should not exceed screen much
        if aw <= sw * 1.12 and ah <= sh * 1.12 and aw >= sw * 0.5 and ah >= sh * 0.5:
            # Intersect with primary screen origin box
            left = max(0, ax)
            top = max(0, ay)
            right = min(sw, ax + aw)
            bottom = min(sh, ay + ah)
            aw2 = right - left
            ah2 = bottom - top
            if aw2 >= 320 and ah2 >= 240:
                return left, top, aw2 - margin, ah2 - margin
    # Fallback: full screen minus margin (rough taskbar allowance on bottom)
    taskbar = max(margin, 40)
    return 0, 0, max(_ABS_MIN_W, sw - margin), max(_ABS_MIN_H, sh - taskbar)


def fit_window_geometry(
    geom: str,
    *,
    screen: tuple[int, int],
    virtual: tuple[int, int, int, int] | None = None,
    work_area: tuple[int, int, int, int] | None = None,
    min_size: tuple[int, int] = (920, 620),
    margin: int = 24,
    force_center: bool = False,
) -> str:
    """Return `WxH+X+Y` that fits entirely in the usable screen area.

    Size is clamped to the usable area (never larger). Preferred ``min_size`` is
    honored only when it still fits; otherwise the window shrinks so nothing is
    clipped. With ``force_center=True`` always recenters (startup UX).
    """
    sw, sh = (max(1, screen[0]), max(1, screen[1]))
    pref_w, pref_h = min_size
    w, h, x, y = parse_geometry(geom)

    ax, ay, usable_w, usable_h = _usable_area(screen, work_area, margin=margin)
    usable_w = max(_ABS_MIN_W, usable_w)
    usable_h = max(_ABS_MIN_H, usable_h)

    # Never exceed usable area — even if preferred min is larger
    target_min_w = min(pref_w, usable_w)
    target_min_h = min(pref_h, usable_h)
    w = min(max(w, target_min_w), usable_w)
    h = min(max(h, target_min_h), usable_h)

    vx, vy, vw, vh = virtual if virtual is not None else (0, 0, sw, sh)
    if vw <= 0 or vh <= 0:
        vx, vy, vw, vh = 0, 0, sw, sh

    need_center = (
        force_center
        or x is None
        or y is None
        or not titlebar_is_visible(x, y, virtual=(vx, vy, vw, vh))
    )
    if need_center:
        x = ax + max(0, (usable_w - w) // 2)
        y = ay + max(0, (usable_h - h) // 2)
        # Keep the whole window inside the usable (primary) rect
        x = max(ax, min(x, ax + usable_w - w))
        y = max(ay, min(y, ay + usable_h - h))
    return f"{w}x{h}+{x}+{y}"


def filter_treeview_style_map(mapped: list) -> list:
    """Drop Windows ``!disabled !selected`` maps that hide Treeview tag colors."""
    out: list = []
    for elm in mapped:
        if isinstance(elm, (list, tuple)) and len(elm) >= 2:
            if tuple(elm[:2]) == ("!disabled", "!selected"):
                continue
        out.append(elm)
    return out
