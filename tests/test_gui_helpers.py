"""GUI helpers (windowing, theme) and MSG parse smoke."""

from __future__ import annotations

from pathlib import Path

from reliquary.core.models import IocType
from reliquary.core.pipeline import analyze_file
from reliquary.gui.theme import IOC_TYPE_COLORS
from reliquary.gui.windowing import (
    filter_treeview_style_map,
    fit_window_geometry,
    parse_geometry,
    titlebar_is_visible,
)

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_msg_sample_parses():
    path = SAMPLES / "msg_sample.msg"
    assert path.is_file()
    result = analyze_file(path)
    assert result.source_kind == "email"
    assert result.subject or result.raw_text_preview or result.errors == []


def test_window_geometry_centers_and_clamps():
    assert parse_geometry("1320x820") == (1320, 820, None, None)
    assert parse_geometry("1100x700+40+80") == (1100, 700, 40, 80)
    assert parse_geometry("1100x700-1920+10") == (1100, 700, -1920, 10)
    assert parse_geometry("nope")[0:2] == (1320, 820)

    centered = fit_window_geometry("1320x820", screen=(1920, 1080))
    assert centered == "1320x820+300+130"

    off = fit_window_geometry("1000x700+9000+9000", screen=(1920, 1080))
    assert off.startswith("1000x700+")
    assert titlebar_is_visible(300, 130, virtual=(0, 0, 1920, 1080))
    assert not titlebar_is_visible(9000, 9000, virtual=(0, 0, 1920, 1080))

    dual = fit_window_geometry(
        "1100x700+1920+80",
        screen=(1920, 1080),
        virtual=(0, 0, 3840, 1080),
    )
    assert dual == "1100x700+1920+80"

    mapped = [
        ("!disabled", "!selected", "SystemWindowText"),
        ("selected", "#fff"),
    ]
    assert filter_treeview_style_map(mapped) == [("selected", "#fff")]


def test_ioc_type_colors_are_distinct():
    for itype in IocType:
        assert itype.value in IOC_TYPE_COLORS
    colors = list(IOC_TYPE_COLORS.values())
    assert len(set(colors)) == len(colors)
