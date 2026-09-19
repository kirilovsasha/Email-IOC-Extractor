"""Window geometry helpers (kept out of the CTk app module for unit tests)."""

from __future__ import annotations

import re

_DEFAULT_W = 1320
_DEFAULT_H = 820
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


def fit_window_geometry(
    geom: str,
    *,
    screen: tuple[int, int],
    virtual: tuple[int, int, int, int] | None = None,
    min_size: tuple[int, int] = (920, 620),
    margin: int = 48,
) -> str:
    """Return `WxH+X+Y` that fits the screen.

    Missing or off-screen coordinates are centered on the primary screen so the
    window does not open half off a disconnected monitor.
    """
    sw, sh = (max(1, screen[0]), max(1, screen[1]))
    min_w, min_h = min_size
    w, h, x, y = parse_geometry(geom)
    max_w = max(min_w, sw - margin)
    max_h = max(min_h, sh - margin)
    w = max(min_w, min(w, max_w))
    h = max(min_h, min(h, max_h))

    vx, vy, vw, vh = virtual if virtual is not None else (0, 0, sw, sh)
    if vw <= 0 or vh <= 0:
        vx, vy, vw, vh = 0, 0, sw, sh

    if x is None or y is None or not titlebar_is_visible(x, y, virtual=(vx, vy, vw, vh)):
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
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
