"""GUI / filter / tabs smoke without creating a Tk root window."""

from __future__ import annotations

from types import SimpleNamespace

from reliquary.core.filter_state import FilterState
from reliquary.core.models import (
    AnalysisResult,
    AttachmentInfo,
    FileTriageRow,
    Ioc,
    IocType,
    UrlRewriteResult,
    Verdict,
    VerdictLevel,
)
from reliquary.gui.i18n import _STRINGS, t
from reliquary.gui.tabs import desired_result_tabs
from reliquary.gui.windowing import (
    fit_window_geometry,
    parse_geometry,
    size_only_geometry,
)


def test_i18n_catalog_complete_and_format_safe() -> None:
    required = {
        "tab_verdict",
        "tab_ioc",
        "tab_att",
        "tab_url",
        "tab_batch",
        "tab_err",
        "btn_open",
        "btn_export",
        "btn_handoff",
        "status_ready",
        "status_analyzing",
        "about_title",
        "high_contrast",
        "verdict_prompt",
    }
    missing = required - set(_STRINGS)
    assert not missing, missing
    assert t("missing_key_xyz") == "missing_key_xyz"
    assert t("status_ready") == "Готово"
    # format kwargs must not crash on unused / missing placeholders
    assert isinstance(t("about_title", unused=1), str)


def test_filter_state_from_prefs_and_cli() -> None:
    prefs = {
        "hide_rewriter": False,
        "hide_allowlisted": False,
        "hide_private": False,
        "actionable_only": False,
        "cat_network": True,
        "cat_hashes": False,
        "cat_host": True,
        "cat_crypto": True,
        "full_ioc_types": False,
    }
    state = FilterState.from_prefs(prefs)
    selected = state.selected_types()
    assert selected is not None
    assert "url" in selected
    assert "md5" not in selected
    assert "registry" not in selected  # legacy host hidden
    assert state.serializable()["hide_rewriter"] is False

    args = SimpleNamespace(
        types="url,domain",
        full_ioc_types=False,
        hide_rewriter=True,
        hide_allowlisted=True,
        hide_private=True,
        actionable=True,
        search="evil",
    )
    cli = FilterState.from_cli_args(args)
    assert cli.types == {"url", "domain"}
    assert cli.search == "evil"
    focused = cli.with_focus(r"C:\inbox\mail.eml")
    assert focused.source_file == "C:/inbox/mail.eml"
    assert cli.with_focus("/var/mail/inbox/other.eml").source_file == "/var/mail/inbox/other.eml"

    full_args = SimpleNamespace(
        types=None,
        full_ioc_types=True,
        hide_rewriter=True,
        hide_allowlisted=True,
        hide_private=True,
        actionable=False,
        search="",
    )
    full = FilterState.from_cli_args(full_args)
    assert full.cat_crypto is True
    assert full.full_ioc_types is True


def test_desired_result_tabs_compact_and_full() -> None:
    assert desired_result_tabs(None)[0][0] == "mail"

    result = AnalysisResult(
        source_path="a.eml",
        source_kind="email",
        attachments=[
            AttachmentInfo(
                filename="a.zip",
                size=10,
                mime_guess="application/zip",
                md5="0" * 32,
                sha1="0" * 40,
                sha256="0" * 64,
                risk_flags=["zip"],
            )
        ],
        url_rewrites=[
            UrlRewriteResult(
                original="https://safe/x",
                unwrapped="https://evil",
                rewriter="microsoft_safelinks",
                changed=True,
            )
        ],
        iocs=[Ioc(value="https://evil", ioc_type=IocType.URL)],
        verdict=Verdict(
            level=VerdictLevel.SUSPICIOUS,
            score=40,
            summary="test",
            reasons=["x"],
        ),
        errors=["oops"],
        file_rows=[
            FileTriageRow(path="a.eml", kind="email", verdict_level="suspicious", verdict_score=40),
            FileTriageRow(path="b.eml", kind="email", verdict_level="suspicious", verdict_score=35),
        ],
    )
    tabs = desired_result_tabs(result, filtered_count=3, compact=False)
    keys = [k for k, _ in tabs]
    assert keys[0] == "mail"
    assert "att" in keys and "url" in keys and "ioc" in keys
    assert "batch" in keys and "err" in keys
    # Labels stay stable — no verdict level embedded
    assert all(" · " not in lab for _k, lab in tabs)
    assert tabs[0][1] == "Вердикт"

    compact = desired_result_tabs(result, filtered_count=1, compact=True)
    assert any(lab.startswith("Влож.") for _k, lab in compact)
    assert any(lab.startswith("!") or "Ошиб" in lab for _k, lab in compact)
    assert compact[0] == ("mail", "Вердикт")


def test_windowing_helpers_no_tk() -> None:
    fitted = fit_window_geometry(
        "900x600+10+10",
        screen=(1280, 800),
        work_area=(0, 0, 1280, 760),
        force_center=True,
    )
    w, h, x, y = parse_geometry(fitted)
    assert w <= 1280 and h <= 760
    assert x >= 0 and y >= 0
    assert size_only_geometry(fitted) == f"{w}x{h}"
