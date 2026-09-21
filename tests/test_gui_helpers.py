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
    # Fallback usable height = 1080 - 40 taskbar ≈; width 1920 - 24 margin
    w, h, x, y = parse_geometry(centered)
    assert w <= 1920 - 24
    assert h <= 1080 - 40
    assert x >= 0 and y >= 0
    assert x + w <= 1920
    assert y + h <= 1080

    # Saved offset is ignored when force_center=True
    forced = fit_window_geometry(
        "1100x700+40+80",
        screen=(1920, 1080),
        force_center=True,
    )
    fw, fh, fx, fy = parse_geometry(forced)
    assert (fw, fh) == (1100, 700)
    assert fx == (1920 - 24 - 1100) // 2
    assert fy == (1080 - 40 - 700) // 2

    # Work area (taskbar) — window must fit entirely inside
    work = fit_window_geometry(
        "1000x700",
        screen=(1920, 1080),
        work_area=(0, 0, 1920, 1040),
        force_center=True,
    )
    ww, wh, wx, wy = parse_geometry(work)
    assert ww <= 1920 - 24
    assert wh <= 1040 - 24
    assert wx + ww <= 1920
    assert wy + wh <= 1040

    # Small screen: shrink below preferred min so nothing is clipped
    small = fit_window_geometry(
        "1320x820",
        screen=(1280, 720),
        work_area=(0, 0, 1280, 680),
        force_center=True,
    )
    sw, sh, sx, sy = parse_geometry(small)
    assert sw <= 1280 - 24
    assert sh <= 680 - 24
    assert sx >= 0 and sy >= 0
    assert sx + sw <= 1280
    assert sy + sh <= 680

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

    from reliquary.gui.windowing import size_only_geometry

    assert size_only_geometry("1320x820+100+50") == "1320x820"

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


def test_appearance_remap_and_derived_sync():
    from reliquary.gui import theme

    theme.set_high_contrast(False)
    theme.apply_appearance("dark")
    assert theme.COLORS["bg"] == theme.COLORS_DARK["bg"]
    assert theme.VERDICT_COLORS["malicious"] == theme.COLORS["danger"]

    remap = theme.apply_appearance("light")
    assert theme.COLORS["bg"] == theme.COLORS_LIGHT["bg"]
    assert theme.COLORS_DARK["bg"].lower() in remap
    assert remap[theme.COLORS_DARK["bg"].lower()] == theme.COLORS_LIGHT["bg"]
    assert theme.BTN_PRIMARY["fg_color"] == theme.COLORS["accent"]
    assert theme.SEVERITY_COLORS["info"] == theme.COLORS["muted"]

    # Round-trip restores dark
    remap2 = theme.apply_appearance("dark")
    assert theme.COLORS_LIGHT["bg"].lower() in remap2
    assert theme.COLORS["bg"] == theme.COLORS_DARK["bg"]


def test_i18n_ru_only():
    from reliquary.gui import i18n

    assert i18n.t("tab_verdict") == "Вердикт"
    assert i18n.t("btn_copy_enc_note").startswith("Заметка")
    assert not hasattr(i18n, "set_ui_lang")


def test_export_choices_everyday_only():
    from reliquary.gui.export_actions import EXPORT_CHOICES, normalize_export_kind

    assert EXPORT_CHOICES == ("JSON", "CSV", "Batch CSV", "Тикет")
    assert normalize_export_kind("Batch CSV") == "batch_csv"
    assert normalize_export_kind("Тикет") == "handoff"
    for kind in ("ECS", "CEF", "STIX", "MISP", "OpenCTI", "Кампания"):
        assert kind not in EXPORT_CHOICES
