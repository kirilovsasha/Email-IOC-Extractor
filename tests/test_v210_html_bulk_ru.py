"""v2.10: HTML/PDF вложения, RU-rewriters, mailing-list, калибровка, self-check."""

from __future__ import annotations

import json
from pathlib import Path

from reliquary.core.attachment_inspector import inspect_bytes
from reliquary.core.calibration import calibrate_inbox, segment_for
from reliquary.core.org_profile import resolve_default_profile_path
from reliquary.core.pipeline import analyze_file
from reliquary.core.self_check import build_self_check_lines
from reliquary.core.url_rewrite import unwrap_url
from reliquary.core.verdict import (
    VerdictConfig,
    probe_verdict_extra_warnings,
    validate_verdict_extra,
)

CORPUS = Path(__file__).resolve().parents[1] / "samples" / "corpus"


def test_html_attachment_smuggling_flags() -> None:
    raw = (
        b"<html><body><a href='https://evil.top/x'>microsoft.com</a>"
        b"<script>atob('QQ=='); new Blob([1]);</script></body></html>"
    )
    info = inspect_bytes("login.html", raw)
    assert "html_attachment" in info.risk_flags
    assert "html_smuggling" in info.risk_flags
    assert info.data is not None


def test_pdf_javascript_flags() -> None:
    raw = b"%PDF-1.4\n/OpenAction << /S /JavaScript /JS (app.alert(1)) >>\n/URI (http://x)\n"
    info = inspect_bytes("x.pdf", raw)
    assert "pdf_javascript" in info.risk_flags
    assert "pdf_uri_action" in info.risk_flags


def test_mailru_yandex_unwrap() -> None:
    r = unwrap_url("https://away.mail.ru/clck?url=https%3A%2F%2Fevil.top%2Fa")
    assert r.changed and r.rewriter == "mailru_away"
    assert r.unwrapped.startswith("https://evil.top")
    r2 = unwrap_url("https://clck.yandex.ru/redir?url=https%3A%2F%2Fevil.top%2Fb")
    assert r2.changed and r2.rewriter == "yandex_redir"


def test_mailing_list_mitigation() -> None:
    r = analyze_file(CORPUS / "benign_mailing_list.eml")
    assert r.verdict is not None
    assert r.verdict.level.value == "benign"
    assert r.mail_identity is not None
    assert r.mail_identity.list_unsubscribe
    reasons = " ".join(b.reason for b in r.verdict.breakdown if b.category == "mitigation")
    assert "Рассылка" in reasons or "List-Unsubscribe" in reasons


def test_html_attachment_corpus() -> None:
    r = analyze_file(CORPUS / "suspicious_html_attachment.eml")
    assert r.verdict is not None
    assert r.verdict.level.value in ("suspicious", "malicious")
    assert any("html_smuggling" in (a.risk_flags or []) for a in r.attachments)


def test_pdf_js_corpus() -> None:
    r = analyze_file(CORPUS / "suspicious_pdf_js.eml")
    assert r.verdict is not None
    assert r.verdict.level.value in ("suspicious", "malicious")
    assert any("pdf_javascript" in (a.risk_flags or []) for a in r.attachments)


def test_new_weights_in_config() -> None:
    cfg = VerdictConfig()
    assert cfg.weight_mailing_list < 0
    assert cfg.weight_html_smuggling > 0
    assert cfg.weight_pdf_javascript > 0


def test_self_check_lines() -> None:
    lines = build_self_check_lines()
    assert any("Версия" in x for x in lines)
    assert any("Сборка" in x for x in lines)
    assert any("Конфиги" in x for x in lines)


def test_probe_verdict_extra_warnings(tmp_path: Path) -> None:
    bad = tmp_path / "verdict_extra.json"
    bad.write_text(json.dumps({"threshold_malicious": 999, "nope": 1}), encoding="utf-8")
    warns = probe_verdict_extra_warnings(bad)
    assert warns
    assert validate_verdict_extra({"threshold_malicious": 50}) == []


def test_calibrate_inbox_empty(tmp_path: Path) -> None:
    report = calibrate_inbox(tmp_path)
    assert report.file_count == 0
    assert "Нет" in report.to_text()


def test_segment_bulk() -> None:
    r = analyze_file(CORPUS / "benign_mailing_list.eml")
    assert segment_for(r) == "bulk_mail"


def test_resolve_default_profile_path_none_or_path() -> None:
    # May be None in clean checkout — function must not raise
    path = resolve_default_profile_path()
    assert path is None or path.exists()
