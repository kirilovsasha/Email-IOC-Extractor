"""Allowlist and IOC filter behaviour."""

from __future__ import annotations

from pathlib import Path

from reliquary.cli import main as cli_main
from reliquary.core.allowlist import (
    build_allowlist,
    parse_allowlist_lines,
    tag_allowlist,
)
from reliquary.core.filter_state import CATEGORY_TYPES, IOC_GROUPS, LEGACY_HOST_TYPES, FilterState
from reliquary.core.models import Ioc, IocType
from reliquary.gui.theme import IOC_GROUPS as THEME_GROUPS

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_ioc_groups_single_source():
    assert IOC_GROUPS == THEME_GROUPS
    assert "Хеши и CVE" in CATEGORY_TYPES
    assert "cve" in CATEGORY_TYPES["Хеши и CVE"]


def test_parse_allowlist_extra(tmp_path: Path):
    text = """
# comment
domain:noise.cdn.example
ip:9.9.9.9
*.corp.internal
8.8.8.8
"""
    domains, ips = parse_allowlist_lines(text)
    assert "noise.cdn.example" in domains
    assert "*.corp.internal" in domains
    assert "9.9.9.9" in ips
    assert "8.8.8.8" in ips

    path = tmp_path / "extra.txt"
    path.write_text("domain:unique-allow-test.example\n", encoding="utf-8")
    domains, ips = build_allowlist(extra_path=path)
    assert "unique-allow-test.example" in domains
    assert "microsoft.com" in domains

    iocs = [
        Ioc("https://unique-allow-test.example/x", IocType.URL),
        Ioc("evil.example.phishing", IocType.DOMAIN),
    ]
    tag_allowlist(iocs, domains, ips)
    assert "allowlisted" in iocs[0].tags
    assert "allowlisted" not in iocs[1].tags


def test_email_mode_hides_legacy_types() -> None:
    state = FilterState(full_ioc_types=False, cat_host=True, cat_crypto=True)
    types = state.selected_types()
    assert types is not None
    assert not (types & LEGACY_HOST_TYPES)
    assert "bitcoin" in types

    full = FilterState(full_ioc_types=True, cat_host=True, cat_crypto=True)
    assert full.selected_types() is None or LEGACY_HOST_TYPES <= (full.selected_types() or set())


def test_full_ioc_types_cli_style() -> None:
    class Args:
        hide_rewriter = True
        hide_allowlisted = True
        hide_private = True
        actionable = True
        search = ""
        types = None
        full_ioc_types = True

    state = FilterState.from_cli_args(Args())
    assert state.full_ioc_types
    assert state.cat_crypto
    assert state.selected_types() is None


def test_cli_defaults_match_gui_filters(tmp_path: Path):
    code = cli_main(
        [
            str(SAMPLES / "phishing_sample.eml"),
            "--quiet-verdict",
            "--handoff",
            str(tmp_path / "t.txt"),
            "--no-actionable",
            "--no-hide-rewriter",
            "--no-hide-allowlisted",
            "--no-hide-private",
        ]
    )
    assert code == 0
    assert (tmp_path / "t.txt").is_file()
    state = FilterState.from_prefs({})
    assert state.actionable_only is True
    assert state.hide_rewriter is True
