"""Behavior fixes from the analyst improvement list. No new detection."""

from __future__ import annotations

import mailbox
from pathlib import Path

import pytest

from reliquary.core.analysis_options import AnalysisOptions
from reliquary.core.exporters import filter_iocs, source_file_matches
from reliquary.core.filter_state import FilterState
from reliquary.core.formats import (
    cleanup_ingest_dirs,
    expand_input_paths,
    ingest_problem_notes,
    take_ingest_notes,
)
from reliquary.core.handoff import render_default_handoff, render_handoff
from reliquary.core.labels import confidence_label_ru, parse_verdict_level, verdict_card_label
from reliquary.core.mbox_ingest import expand_mbox_to_emls
from reliquary.core.models import (
    AnalysisResult,
    AttachmentInfo,
    FileTriageRow,
    Ioc,
    IocType,
    Verdict,
    VerdictLevel,
)
from reliquary.core.pipeline import (
    _decode_data_image_qr,
    _dedup_iocs,
    apply_campaign_divergence,
    is_parser_failure,
    merge_results,
    parser_failures,
    rescore_with_options,
    source_too_large_message,
)
from reliquary.core.pst_ingest import _folder_label, _message_to_eml, compose_eml
from reliquary.core.self_check import startup_status_text
from reliquary.core.yara_scan import clear_rules_cache, compiled_rules, scan_result_attachments
from reliquary.gui.analysis_actions import (
    _source_meta_line,
    cancel_in_progress_status,
    cancelled_batch_status,
)
from reliquary.gui.tabs import desired_result_tabs


def _ioc(value: str, tags: list[str], rewritten: str | None = None, priority_tag: str | None = None) -> Ioc:
    use = list(tags)
    if priority_tag and priority_tag not in use:
        use.append(priority_tag)
    return Ioc(value=value, ioc_type=IocType.URL, tags=use, rewritten_from=rewritten)


def test_dedup_keeps_weaker_tags_and_unwrap_chain() -> None:
    strong = _ioc("https://evil.example/a", ["unwrapped"], "https://wrap.example/a")
    weak = _ioc("https://evil.example/a", ["from_body", "qr"], "https://other.example/a")
    merged = _dedup_iocs([weak, strong])
    assert len(merged) == 1
    tags = set(merged[0].tags)
    assert "unwrapped" in tags
    assert "from_body" in tags
    assert "qr" in tags
    assert "https://wrap.example/a" in (merged[0].rewritten_from or "")
    assert "https://other.example/a" in (merged[0].rewritten_from or "")


def test_findings_are_not_parser_failures() -> None:
    lines = [
        "QR data:image: https://evil.example",
        "OOXML: найден vbaProject.bin (макросы)",
        "OLE разбор ограничен (ImportError): olefile",
        "Batch: карточка почты от первого письма",
        "Кампании: 2 писем связаны",
        "Чтение файла: нет такого файла",
    ]
    assert parser_failures(lines) == ["Чтение файла: нет такого файла"]
    assert not is_parser_failure(lines[0])


def test_source_too_large_does_not_mention_a_setting() -> None:
    text = source_too_large_message(50 * 1024 * 1024)
    assert "40 МБ" in text
    assert "остановлен" in text
    assert "увелич" not in text
    assert "лимит" not in text.lower() or "настрой" not in text.lower()
    assert "настрой" not in text.lower()


def test_merge_does_not_replace_message_verdict() -> None:
    low = AnalysisResult(
        source_path="/mail/a.eml",
        source_kind="email",
        subject="one",
        verdict=Verdict(level=VerdictLevel.SUSPICIOUS, score=31, summary="s", reasons=["первая причина длиннее шестидесяти символов для строки пакета"]),
        iocs=[Ioc(value="https://a.example", ioc_type=IocType.URL, tags=["file:a.eml"])],
    )
    high = AnalysisResult(
        source_path="/mail/b.eml",
        source_kind="email",
        subject="two",
        verdict=Verdict(level=VerdictLevel.BENIGN, score=4, summary="b", reasons=["тихо"]),
        iocs=[Ioc(value="https://b.example", ioc_type=IocType.URL)],
    )
    merged = merge_results([low, high])
    assert merged.verdict is None
    assert low.verdict is not None and low.verdict.score == 31
    assert merged.file_rows[0].verdict_score == 31
    assert not any("карточка почты" in e or e.startswith("Кампании:") for e in merged.errors)
    tagged = [t for i in merged.iocs for t in i.tags if t.startswith("file:")]
    assert any(t == "file:/mail/a.eml" for t in tagged)


def test_campaign_rescore_uses_same_options(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def _fake(result, cfg, **kwargs):
        seen["brands"] = kwargs.get("brands_path")
        seen["org"] = kwargs.get("org_domains_path")
        seen["allow"] = kwargs.get("allowlist_domains")
        return result.verdict

    monkeypatch.setattr("reliquary.core.pipeline.render_verdict", _fake)
    monkeypatch.setattr(
        "reliquary.core.pipeline.load_verdict_config",
        lambda *_a, **_k: object(),
    )
    a = AnalysisResult(
        source_path="a.eml",
        source_kind="email",
        sender="one@alpha.example",
        subject="Same campaign subject XYZ",
        verdict=Verdict(level=VerdictLevel.SUSPICIOUS, score=40, summary="x", reasons=["r"]),
    )
    b = AnalysisResult(
        source_path="b.eml",
        source_kind="email",
        sender="two@beta.example",
        subject="Same campaign subject XYZ",
        verdict=Verdict(level=VerdictLevel.SUSPICIOUS, score=40, summary="x", reasons=["r"]),
    )
    # Force a shared key regardless of subject normalization.
    monkeypatch.setattr("reliquary.core.pipeline.campaign_key_for", lambda _r: "camp")
    monkeypatch.setattr(
        "reliquary.core.pipeline.campaign_divergence_keys",
        lambda _rows: {"camp"},
    )
    opts = AnalysisOptions(
        brands_path="brands.txt",
        org_domains_path="org.txt",
        allowlist_path="allow.txt",
        verdict_path="verdict.json",
    )
    monkeypatch.setattr(
        "reliquary.core.allowlist.build_allowlist",
        lambda **_k: ({"company.example"}, set()),
    )
    apply_campaign_divergence([a, b], options=opts)
    assert seen["brands"] == "brands.txt"
    assert seen["org"] == "org.txt"
    assert seen["allow"] == {"company.example"}


def test_path_filter_does_not_mix_same_basename() -> None:
    result = AnalysisResult(
        source_path="batch",
        source_kind="batch",
        iocs=[
            Ioc(value="1.2.3.4", ioc_type=IocType.IPV4, tags=["file:/one/invoice.eml"]),
            Ioc(value="5.6.7.8", ioc_type=IocType.IPV4, tags=["file:/two/invoice.eml"]),
        ],
    )
    state = FilterState(actionable_only=False, hide_private=False, hide_rewriter=False, hide_allowlisted=False)
    focused = state.with_focus(r"C:\two\invoice.eml".replace("C:", "/two") if False else "/two/invoice.eml")
    assert focused.source_file == "/two/invoice.eml"
    got = filter_iocs(result, **focused.kwargs())
    assert [i.value for i in got] == ["5.6.7.8"]
    assert source_file_matches("invoice.eml", "/two/invoice.eml")


def test_ioc_badge_is_shown_over_total() -> None:
    result = AnalysisResult(
        source_path="a.eml",
        source_kind="email",
        iocs=[
            Ioc(value="1.1.1.1", ioc_type=IocType.IPV4, tags=["private"]),
            Ioc(value="https://evil.example", ioc_type=IocType.URL),
        ],
        errors=["QR data:image: https://evil.example", "Чтение: обрыв"],
    )
    tabs = dict(desired_result_tabs(result, filtered_count=1))
    assert tabs["ioc"] == "IOC 1/2"
    assert tabs["err"] == "Ошибки 1"
    state = FilterState(hide_private=True, actionable_only=False, hide_rewriter=False, hide_allowlisted=False)
    summary = state.hidden_summary(result)
    assert "локальные IP 1" in summary


def test_handoff_actions_confidence_and_batch_tail() -> None:
    reasons = [f"причина {i}" for i in range(10)]
    rows = [
        FileTriageRow(path=f"/mail/{i}.eml", kind="email", verdict_level="suspicious", verdict_score=30, ioc_count=1, top_reason="длинная причина")
        for i in range(32)
    ]
    result = AnalysisResult(
        source_path="/mail/0.eml",
        source_kind="email",
        subject="тема",
        verdict=Verdict(
            level=VerdictLevel.MALICIOUS,
            score=70,
            summary="сводка",
            reasons=reasons,
            confidence="high",
        ),
        attachments=[
            AttachmentInfo(
                filename="a.exe",
                size=1,
                mime_guess="application/octet-stream",
                md5="0" * 32,
                sha1="0" * 40,
                sha256="0" * 64,
                risk_flags=["dangerous_extension"],
            )
        ],
        file_rows=rows,
    )
    text = render_default_handoff(result)
    assert "Вердикт:" in text
    assert "вредоносно" in text
    assert "уверенность высокая" in text
    assert "Действия:" in text
    assert "ещё 2" in text
    assert "показано 30 из 32" in text
    filled = render_handoff(result, template="A={actions}\nC={confidence}\n")
    assert "причина" in filled
    assert "высокая" in filled
    assert filled.strip() != "A=\nC="


def test_feedback_level_parser_rejects_typos() -> None:
    assert parse_verdict_level("benign") == VerdictLevel.BENIGN
    assert parse_verdict_level("безопасно") == VerdictLevel.BENIGN
    assert parse_verdict_level("bening") is None
    assert verdict_card_label(VerdictLevel.MALICIOUS) == "вредоносно"
    assert confidence_label_ru("low") == "низкая"


def test_rescore_retags_allowlist(tmp_path: Path) -> None:
    allow = tmp_path / "allow.txt"
    allow.write_text("evil.example\n", encoding="utf-8")
    result = AnalysisResult(
        source_path="clipboard",
        source_kind="email",
        subject="x",
        iocs=[Ioc(value="evil.example", ioc_type=IocType.DOMAIN, tags=["from_url"])],
        verdict=Verdict(level=VerdictLevel.SUSPICIOUS, score=40, summary="s", reasons=["r"]),
    )
    fresh = rescore_with_options(result, AnalysisOptions(allowlist_path=allow))
    assert any("allowlisted" in i.tags for i in fresh.iocs)


def test_qr_payload_is_a_note_not_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("reliquary.core.qr_scan.qr_decoder_available", lambda: True)
    monkeypatch.setattr(
        "reliquary.core.qr_scan.decode_qr_payloads",
        lambda _data: (["https://evil.example/qr"], []),
    )
    blob = "data:image/png;base64," + ("A" * 120)
    result = AnalysisResult(source_path="a.eml", source_kind="email")
    extra = _decode_data_image_qr(blob, result)
    assert "https://evil.example/qr" in extra
    assert not any(e.startswith("QR data:image:") for e in result.errors)
    assert any("QR:" in n for a in result.attachments for n in a.notes)


def test_qr_over_limit_note(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("reliquary.core.qr_scan.qr_decoder_available", lambda: True)
    monkeypatch.setattr(
        "reliquary.core.qr_scan.decode_qr_payloads",
        lambda _data: ([], ["QR pyzbar: boom"]),
    )
    chunk = "data:image/png;base64," + ("A" * 120)
    html = "\n".join(chunk for _ in range(6))
    result = AnalysisResult(source_path="a.eml", source_kind="email")
    _decode_data_image_qr(html, result)
    notes = [n for a in result.attachments for n in a.notes]
    assert any("просмотрено 4" in n for n in notes)
    assert any(e.startswith("QR: сбой декодера") for e in result.errors)
    assert sum(1 for e in result.errors if e.startswith("QR: сбой декодера")) == 1


def test_pst_keeps_html_and_names_full_folder() -> None:
    class _Msg:
        def get_transport_headers(self) -> str:
            return "From: a@b\nSubject: s\n"

        def get_plain_text_body(self) -> str:
            return "plain body"

        def get_html_body(self) -> str:
            return "<html><a href='http://evil.example/x'>x</a></html>"

        def get_number_of_attachments(self) -> int:
            return 9

        def get_attachment(self, index: int):
            return _Att(index)

    class _Att:
        def __init__(self, index: int) -> None:
            self.index = index

        def get_name(self) -> str:
            return f"f{self.index}.bin"

        def get_size(self) -> int:
            return 4

        def read_buffer(self, _n: int) -> bytes:
            return b"data"

    notes: list[str] = []
    raw = _message_to_eml(_Msg(), notes)
    assert b"text/plain" in raw
    assert b"text/html" in raw
    assert b"plain body" in raw
    assert b"evil.example" in raw
    assert any("вложений 9, сохранено 8" in n for n in notes)
    assert len(_folder_label(type("F", (), {"get_name": lambda self: "VeryLongFolderNameForInvoices"})())) > 24


def test_compose_eml_alternative() -> None:
    raw = compose_eml(
        "From: a@b\nSubject: s\n",
        b"",
        [],
        plain=b"plain",
        html_body=b"<b>html</b>",
    )
    assert b"text/plain" in raw
    assert b"text/html" in raw


def test_mbox_skip_note_and_temp_cleanup(tmp_path: Path) -> None:
    mbox_path = tmp_path / "box.mbox"
    mbox = mailbox.mbox(mbox_path)
    for i in range(3):
        mbox.add(f"From: a@b\nSubject: {i}\n\nbody {i}\n")
    mbox.close()
    notes: list[str] = []
    emls, _dest = expand_mbox_to_emls(mbox_path, limit=1, notes=notes)
    assert len(emls) == 1
    assert any("пропущено 2" in n for n in notes)
    assert any("пропущено" in n for n in ingest_problem_notes(notes))
    first_dir = Path(emls[0]).parent
    second = expand_input_paths([mbox_path], mbox_limit=1)
    second_dir = Path(second[0]).parent
    taken = take_ingest_notes()
    assert any("пропущено" in n for n in taken)
    cleanup_ingest_dirs()
    assert not first_dir.exists()
    assert not second_dir.exists()
    assert take_ingest_notes() == []


def test_yara_compiles_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rules = tmp_path / "r.yar"
    rules.write_text("rule demo { condition: true }\n", encoding="utf-8")
    calls = {"n": 0}

    class _Rules:
        def match(self, data: bytes, timeout: int = 5):
            return []

    def _compile(**_kwargs):
        calls["n"] += 1
        return _Rules()

    import sys
    import types

    mod = types.ModuleType("yara")
    mod.compile = _compile  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "yara", mod)
    clear_rules_cache()
    atts = [
        AttachmentInfo("a.bin", 1, "application/octet-stream", "", "", "", data=b"a"),
        AttachmentInfo("b.bin", 1, "application/octet-stream", "", "", "", data=b"b"),
    ]
    scan_result_attachments(atts, body=b"body", rules_path=rules)
    scan_result_attachments(atts, body=b"body", rules_path=rules)
    assert calls["n"] == 1
    compiled_rules(rules)
    assert calls["n"] == 1


def test_ui_helpers() -> None:
    subject = "Тема письма " + ("очень длинная " * 8)
    line = _source_meta_line("email", "long-file-name.eml", subject)
    assert "\n" in line
    assert " ".join(subject.split()) in line
    assert "…" not in line
    assert "дочитывается" in cancel_in_progress_status("invoice.eml")
    assert "не применён" in cancelled_batch_status()
    warning = "⚠ SHA256 НЕ СОВПАЛ: " + ("x" * 200)
    status = startup_status_text(["Версия 1", warning])
    assert warning in status
    assert len(status) > 180
