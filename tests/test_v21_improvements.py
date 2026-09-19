"""Tests for allowlist extras, handoff, batch export, MSG, verdict edges."""

from __future__ import annotations

import email
import email.policy
import json
from pathlib import Path

from reliquary.cli import main as cli_main
from reliquary.core.allowlist import (
    build_allowlist,
    parse_allowlist_lines,
    tag_allowlist,
)
from reliquary.core.exporters import export_batch_csv, export_report_json
from reliquary.core.filter_state import CATEGORY_TYPES, IOC_GROUPS, FilterState
from reliquary.core.handoff import render_handoff
from reliquary.core.header_analyzer import analyze_headers, build_mail_identity
from reliquary.core.models import Ioc, IocType
from reliquary.core.pipeline import analyze_file, merge_results
from reliquary.core.verdict import VerdictConfig, render_verdict
from reliquary.gui.export_actions import EXPORT_CHOICES, default_export_filename, run_export
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
    assert "microsoft.com" in domains  # built-in still present

    iocs = [
        Ioc("https://unique-allow-test.example/x", IocType.URL),
        Ioc("evil.example.phishing", IocType.DOMAIN),
    ]
    tag_allowlist(iocs, domains, ips)
    assert "allowlisted" in iocs[0].tags
    assert "allowlisted" not in iocs[1].tags


def test_handoff_and_batch_export(tmp_path: Path):
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    text = render_handoff(result)
    assert "Verdict:" in text
    assert "Message-ID:" in text or "File:" in text

    out = run_export("handoff", result, tmp_path / "h.txt", filtered_iocs=result.iocs)
    assert out.read_text(encoding="utf-8").startswith("===")

    a = analyze_file(SAMPLES / "phishing_sample.eml")
    b = analyze_file(SAMPLES / "phishing_sample.eml")
    merged = merge_results([a, b])
    csv_path = export_batch_csv(merged, tmp_path / "batch.csv", batch_results=[a, b])
    assert csv_path.read_text(encoding="utf-8-sig").count("\n") >= 3

    js = export_report_json(merged, tmp_path / "b.json", batch_results=[a, b])
    payload = json.loads(js.read_text(encoding="utf-8"))
    assert "batch" in payload
    assert len(payload["batch"]) == 2

    assert "Handoff" in EXPORT_CHOICES
    assert default_export_filename("Batch CSV").endswith(".csv")


def test_msg_sample_parses():
    path = SAMPLES / "msg_sample.msg"
    assert path.is_file()
    result = analyze_file(path)
    assert result.source_kind == "email"
    assert result.subject or result.raw_text_preview or result.errors == []


def test_header_spf_fail_and_verdict_urgency():
    raw = (
        b"From: ceo@evil.example\r\n"
        b"To: victim@corp.test\r\n"
        b"Subject: URGENT: verify your account immediately\r\n"
        b"Message-ID: <abc@evil.example>\r\n"
        b"Authentication-Results: mx; spf=fail smtp.mailfrom=evil.example;"
        b" dkim=fail; dmarc=fail\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Click https://185.199.108.153/login now\r\n"
    )
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    findings = analyze_headers(msg)
    assert any(f.severity.value in ("high", "critical", "medium") for f in findings)
    mid = build_mail_identity(msg)
    assert mid.spf == "fail"

    result = analyze_file(SAMPLES / "phishing_sample.eml")
    assert result.verdict is not None
    assert result.verdict.level.value in ("malicious", "suspicious", "unknown", "benign")
    cfg = VerdictConfig(threshold_malicious=1, weight_urgency=100)
    v = render_verdict(result, cfg)
    assert v.score >= 0


def test_cli_defaults_match_gui_filters(tmp_path: Path):
    """CLI without flags uses actionable/hide-* like GUI prefs."""
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


def test_window_geometry_centers_and_clamps():
    from reliquary.gui.windowing import (
        filter_treeview_style_map,
        fit_window_geometry,
        parse_geometry,
        titlebar_is_visible,
    )

    assert parse_geometry("1320x820") == (1320, 820, None, None)
    assert parse_geometry("1100x700+40+80") == (1100, 700, 40, 80)
    assert parse_geometry("1100x700-1920+10") == (1100, 700, -1920, 10)
    assert parse_geometry("nope")[0:2] == (1320, 820)

    centered = fit_window_geometry("1320x820", screen=(1920, 1080))
    assert centered == "1320x820+300+130"

    off = fit_window_geometry("1000x700+9000+9000", screen=(1920, 1080))
    assert off.startswith("1000x700+")
    assert titlebar_is_visible(
        300, 130, virtual=(0, 0, 1920, 1080)
    )
    assert not titlebar_is_visible(
        9000, 9000, virtual=(0, 0, 1920, 1080)
    )

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
    from reliquary.core.models import IocType
    from reliquary.gui.theme import IOC_TYPE_COLORS

    for itype in IocType:
        assert itype.value in IOC_TYPE_COLORS
    colors = list(IOC_TYPE_COLORS.values())
    assert len(set(colors)) == len(colors)
