"""Second-pass behavior: score corpus, MIME, auth, allowlist, batch, YARA, export."""

from __future__ import annotations

import email
import email.policy
import json
from pathlib import Path

import pytest

from reliquary.core.allowlist import build_allowlist, domain_matches, tag_allowlist
from reliquary.core.analysis_options import AnalysisOptions
from reliquary.core.attachment_inspector import decode_payload_text, inspect_bytes
from reliquary.core.diff import find_batch_peer
from reliquary.core.exporters import (
    export_batch_csv,
    export_csv,
    export_ioc_summary,
    export_report_json,
)
from reliquary.core.header_analyzer import analyze_headers, build_mail_identity
from reliquary.core.models import (
    AnalysisResult,
    AttachmentInfo,
    FileTriageRow,
    Ioc,
    IocType,
    MailIdentity,
)
from reliquary.core.pipeline import (
    analyze_file,
    analyze_text,
    annotate_campaigns,
    is_parser_failure,
    park_nonfailure_lines,
    parser_failures,
    sort_batch_rows,
)
from reliquary.core.verdict import VerdictConfig
from reliquary.core.verdict_scoring import (
    _ics_contains_url,
    _score_mitigations,
    _text_for_score,
)
from reliquary.gui.analysis_actions import AnalysisActionsMixin, source_panel_text
from reliquary.gui.export_actions import run_export
from reliquary.gui.result_panels import ResultPanelsMixin, campaign_banner_text
from reliquary.gui.tabs import desired_result_tabs


def _eml(headers: dict[str, str], body: str) -> str:
    lines = [f"{key}: {value}" for key, value in headers.items()]
    lines.append("MIME-Version: 1.0")
    lines.append("Content-Type: text/plain; charset=utf-8")
    lines.append("")
    lines.append(body)
    return "\n".join(lines)


def _att(filename: str, flags: list[str], notes: list[str]) -> AttachmentInfo:
    return AttachmentInfo(
        filename=filename,
        size=4,
        mime_guess="application/octet-stream",
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
        risk_flags=flags,
        notes=notes,
    )


def test_score_uses_text_past_the_preview() -> None:
    pad = "a" * 4500
    body = f"{pad}\nсрочно переведите на счёт сегодня\n"
    raw = _eml(
        {
            "From": "cfo@evil.example",
            "To": "pay@corp.example",
            "Subject": "invoice",
            "Message-ID": "<tail@evil.example>",
        },
        body,
    )
    result = analyze_text(raw, label="tail-bec.eml")
    assert "срочно" not in result.raw_text_preview
    assert "срочно переведите" in result.score_text
    assert "bec_payment" in result.content_signals
    assert result.verdict is not None
    assert any("BEC" in (c.reason or "") for c in result.verdict.breakdown)
    assert "score_text" not in result.to_dict()
    panel = source_panel_text(result)
    assert f"Показаны первые {len(result.raw_text_preview)} символов" in panel


def test_calendar_url_past_preview_blocks_mitigation() -> None:
    pad = "x" * 4500
    url = "https://tail-cal.example/phish"
    body = f"{pad}\nBEGIN:VCALENDAR\nDESCRIPTION:{url}\nEND:VCALENDAR\n"
    raw = _eml(
        {
            "From": "calendar@contoso.com",
            "To": "user@company.example",
            "Subject": "Meeting: review",
            "Message-ID": "<tailcal@contoso.com>",
            "Authentication-Results": "mx.example; spf=pass; dkim=pass; dmarc=pass",
        },
        body,
    )
    result = analyze_text(raw, label="tail-cal.eml")
    assert url not in result.raw_text_preview
    assert url in _text_for_score(result)
    assert _ics_contains_url(result, _text_for_score(result))
    assert not _ics_contains_url(result, result.raw_text_preview)
    assert result.verdict is not None
    assert not any(
        "Календарное приглашение" in (c.reason or "") for c in result.verdict.breakdown
    )


def test_nameless_rfc822_calendar_and_attachment() -> None:
    nested = (
        "From: inner@evil.example\n"
        "To: user@company.example\n"
        "Subject: inside\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "See https://nested-rfc822.example/phish\n"
    )
    ics = (
        "BEGIN:VCALENDAR\n"
        "BEGIN:VEVENT\n"
        "SUMMARY:sync\n"
        "DESCRIPTION:https://nameless-cal.example/join\n"
        "END:VEVENT\n"
        "END:VCALENDAR\n"
    )
    raw = (
        "From: a@example.com\n"
        "To: user@company.example\n"
        "Subject: wrap\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=BOUND\n"
        "\n"
        "--BOUND\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "cover\n"
        "--BOUND\n"
        "Content-Type: message/rfc822\n"
        "\n"
        f"{nested}"
        "--BOUND\n"
        "Content-Type: text/calendar\n"
        "\n"
        f"{ics}"
        "--BOUND\n"
        "Content-Type: application/pdf\n"
        "Content-Disposition: attachment\n"
        "\n"
        "%PDF-1.1 nameless\n"
        "--BOUND--\n"
    )
    result = analyze_text(raw, label="nameless.eml")
    names = {a.filename for a in result.attachments}
    assert "nested.eml" in names
    assert "invite.ics" in names
    assert any(name.startswith("attachment.") for name in names)
    nested_att = next(a for a in result.attachments if a.filename == "nested.eml")
    ics_att = next(a for a in result.attachments if a.filename == "invite.ics")
    assert nested_att.data
    assert ics_att.data
    assert any("nested-rfc822.example" in i.value for i in result.iocs)
    assert b"nameless-cal.example" in (ics_att.data or b"")
    assert _ics_contains_url(result, result.score_text or "")


def test_named_ics_bytes_block_calendar_mitigation() -> None:
    ics = (
        "BEGIN:VCALENDAR\n"
        "BEGIN:VEVENT\n"
        "SUMMARY:sync\n"
        "ATTACH:https://ics-attach.example/a.exe\n"
        "END:VEVENT\n"
        "END:VCALENDAR\n"
    )
    raw = (
        "From: calendar@contoso.com\n"
        "To: user@company.example\n"
        "Subject: Meeting: review\n"
        "Message-ID: <ics@contoso.com>\n"
        "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=BOUND\n"
        "\n"
        "--BOUND\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "You are invited to Q3 planning tomorrow at 10:00.\n"
        "--BOUND\n"
        "Content-Type: application/octet-stream\n"
        "Content-Disposition: attachment; filename=\"meet.ics\"\n"
        "\n"
        f"{ics}"
        "--BOUND--\n"
    )
    result = analyze_text(raw, label="named-ics.eml")
    att = next(a for a in result.attachments if a.filename == "meet.ics")
    assert att.data and b"ATTACH:" in att.data
    assert result.verdict is not None
    assert not any(
        "Календарное приглашение" in (c.reason or "") for c in result.verdict.breakdown
    )
    kept = inspect_bytes("meet.ics", ics.encode("utf-8"))
    assert kept.data is not None


def test_cp1251_body_without_usable_charset(tmp_path: Path) -> None:
    phrase = "Срочно переведите на счёт"
    body = phrase.encode("cp1251")
    raw = (
        b"From: ceo@evil.example\r\n"
        b"To: pay@corp.example\r\n"
        b"Subject: pay\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
    ) + body
    path = tmp_path / "cp1251.eml"
    path.write_bytes(raw)
    result = analyze_file(path)
    assert phrase in (result.score_text or "")
    assert "bec_payment" in result.content_signals
    assert decode_payload_text("hello".encode("utf-8"), None) == "hello"
    assert decode_payload_text(body, "not-a-charset") == phrase


def test_later_auth_fail_is_not_hidden_by_pass() -> None:
    raw = (
        b"From: ceo@evil.example\r\n"
        b"To: pay@corp.example\r\n"
        b"Subject: hello\r\n"
        b"Message-ID: <auth@evil.example>\r\n"
        b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n"
        b"Authentication-Results: mx; dmarc=fail\r\n"
        b"Received-SPF: softfail identity=mailfrom; client-ip=203.0.113.5\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"ordinary note\r\n"
    )
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    mid = build_mail_identity(msg)
    assert mid.spf == "softfail"
    assert mid.dmarc == "fail"
    assert mid.dkim == "pass"
    findings = analyze_headers(msg)
    dmarc = next(h for h in findings if h.name == "DMARC result")
    spf = next(h for h in findings if h.name == "SPF result")
    assert dmarc.value == "fail"
    assert spf.value == "softfail"
    result = analyze_text(raw.decode("utf-8"), label="auth-later.eml")
    assert result.mail_identity is not None
    assert result.mail_identity.dmarc == "fail"
    assert result.mail_identity.spf == "softfail"
    assert result.verdict is not None
    reasons = [c.reason or "" for c in result.verdict.breakdown]
    assert not any("SPF+DKIM+DMARC pass" in r for r in reasons)
    assert not any("DMARC+DKIM pass" in r for r in reasons)


def test_received_spf_fail_without_authentication_results() -> None:
    raw = (
        b"From: ceo@evil.example\r\n"
        b"To: pay@corp.example\r\n"
        b"Subject: hello\r\n"
        b"Received-SPF: fail (domain does not designate)\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"ordinary note\r\n"
    )
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    assert build_mail_identity(msg).spf == "fail"
    findings = analyze_headers(msg)
    assert any(h.name == "SPF result" and h.value == "fail" for h in findings)


def test_user_cloud_buckets_are_not_suffix_allowlisted() -> None:
    domains, ips = build_allowlist()
    assert domain_matches("s3.amazonaws.com", domains)
    assert domain_matches("s3-eu-west-1.amazonaws.com", domains)
    assert domain_matches("fonts.googleapis.com", domains)
    assert domain_matches("ajax.googleapis.com", domains)
    assert domain_matches("login.microsoftonline.com", domains)
    blocked = [
        "bucket.s3.amazonaws.com",
        "bucket.s3-eu-west-1.amazonaws.com",
        "acct.blob.core.windows.net",
        "acct.file.core.windows.net",
        "storage.googleapis.com",
        "team.storage.googleapis.com",
        "user.githubusercontent.com",
        "acct.blob.core.azure.com",
    ]
    for host in blocked:
        assert not domain_matches(host, domains), host
    assert domain_matches("bucket.s3.amazonaws.com", {"bucket.s3.amazonaws.com"})
    assert domain_matches("bucket.s3.amazonaws.com", {"*.s3.amazonaws.com"})
    iocs = [
        Ioc("https://bucket.s3.amazonaws.com/a", IocType.URL),
        Ioc("fonts.googleapis.com", IocType.DOMAIN),
    ]
    tag_allowlist(iocs, domains, ips)
    assert "allowlisted" not in iocs[0].tags
    assert "allowlisted" in iocs[1].tags

    cfg = VerdictConfig()
    cloud = AnalysisResult(
        source_path="cloud.eml",
        source_kind="email",
        mail_identity=MailIdentity(
            from_header="User <user@bucket.s3.amazonaws.com>",
            spf="pass",
            dkim="pass",
            dmarc="pass",
        ),
    )
    _score, parts = _score_mitigations(cloud, cfg, allowlist_domains=domains)
    assert not any("bucket.s3.amazonaws.com" in (c.reason or "") for c in parts)
    cdn = AnalysisResult(
        source_path="cdn.eml",
        source_kind="email",
        mail_identity=MailIdentity(
            from_header="Fonts <bot@fonts.googleapis.com>",
            spf="pass",
            dkim="pass",
            dmarc="pass",
        ),
    )
    _score, parts = _score_mitigations(cdn, cfg, allowlist_domains=domains)
    assert any("fonts.googleapis.com" in (c.reason or "") for c in parts)


def test_batch_opens_top_score_and_peers_keep_paths() -> None:
    low = FileTriageRow(path="/mail/low.eml", kind="email", verdict_score=3)
    high = FileTriageRow(path="/mail/high.eml", kind="email", verdict_score=80)
    assert sort_batch_rows([low, high])[0].path == "/mail/high.eml"

    class _App:
        _batch_sort_col = "score"
        _batch_sort_reverse = True

    assert AnalysisActionsMixin._open_batch_path(_App(), [low, high]) == "/mail/high.eml"

    same = [
        FileTriageRow(path="/one/invoice.eml", kind="email", campaign_key="camp"),
        FileTriageRow(path="/two/invoice.eml", kind="email", campaign_key="camp"),
    ]
    annotate_campaigns(same)
    assert same[0].campaign_peers == ["/two/invoice.eml"]
    assert same[1].campaign_peers == ["/one/invoice.eml"]
    batch = [
        AnalysisResult(source_path="/one/invoice.eml", source_kind="email"),
        AnalysisResult(source_path="/two/invoice.eml", source_kind="email"),
    ]
    assert find_batch_peer(batch, filename="invoice.eml") is None
    assert find_batch_peer(batch, filename="/two/invoice.eml") is batch[1]
    shown = AnalysisResult(source_path="/one/invoice.eml", source_kind="email", file_rows=same)
    assert "2 писем" in campaign_banner_text(shown)


def test_batch_highlight_does_not_reopen() -> None:
    class _Tree:
        def __init__(self) -> None:
            self.selected = ""

        def selection_set(self, iid: str) -> None:
            self.selected = iid

        def focus(self, iid: str) -> None:
            return None

        def see(self, iid: str) -> None:
            return None

        def selection(self) -> tuple[str, ...]:
            return (self.selected,)

    class _App:
        def __init__(self) -> None:
            self.result = AnalysisResult(source_path="/mail/high.eml", source_kind="email")
            self._batch_row_map = {
                "low": FileTriageRow(path="/mail/low.eml", kind="email"),
                "high": FileTriageRow(path="/mail/high.eml", kind="email"),
            }
            self._batch_select_silent = False
            self.opened = ""

        def _present_batch_message(self, path: str, *, preload_text: bool = True) -> None:
            self.opened = path

    app = _App()
    tree = _Tree()
    ResultPanelsMixin._highlight_open_batch_row(app, tree)
    assert tree.selected == "high"
    assert app._batch_select_silent is False
    app._batch_select_silent = True
    ResultPanelsMixin._on_batch_tree_select(app, None)
    assert app.opened == ""


def test_yara_sees_html_before_drop_and_notes_unseen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[int] = []

    def _compiled(_path=None):
        return object(), []

    def _scan(data, compiled=None, **_kwargs):
        blob = bytes(data or b"")
        seen.append(len(blob))
        if b"YARAMARK" in blob:
            return ["OfficeHtmlRule"], []
        return [], []

    monkeypatch.setattr("reliquary.core.yara_scan.compiled_rules", _compiled)
    monkeypatch.setattr("reliquary.core.yara_scan.scan_bytes", _scan)
    payload = b"YARAMARK" + (b"A" * (2 * 1024 * 1024 + 64))
    raw = (
        "From: a@example.com\n"
        "To: b@example.com\n"
        "Subject: html\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=BOUND\n"
        "\n"
        "--BOUND\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "cover\n"
        "--BOUND\n"
        "Content-Type: text/html; charset=utf-8\n"
        "Content-Disposition: attachment; filename=\"page.html\"\n"
        "\n"
        f"{payload.decode('ascii')}\n"
        "--BOUND--\n"
    )
    result = analyze_text(
        raw,
        label="yara-html.eml",
        options=AnalysisOptions(enable_yara=True),
    )
    att = next(a for a in result.attachments if a.filename == "page.html")
    assert att.data is None
    assert "yara_match" in att.risk_flags
    assert any("YARA: OfficeHtmlRule" in n for n in att.notes)
    assert any(n > 2 * 1024 * 1024 for n in seen)
    assert "yara:OfficeHtmlRule" in result.content_signals

    monkeypatch.setattr("reliquary.core.attachment_inspector.MAX_KEEP_BYTES", 32)
    small = (
        "From: a@example.com\n"
        "To: b@example.com\n"
        "Subject: big\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=BOUND\n"
        "\n"
        "--BOUND\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "cover\n"
        "--BOUND\n"
        "Content-Type: text/html\n"
        "Content-Disposition: attachment; filename=\"huge.html\"\n"
        "\n"
        + ("B" * 80)
        + "\n--BOUND--\n"
    )
    missed = analyze_text(
        small,
        label="yara-miss.eml",
        options=AnalysisOptions(enable_yara=True),
    )
    huge = next(a for a in missed.attachments if a.filename == "huge.html")
    assert huge.data is None
    assert any("YARA не видела этот файл (huge.html)" in n for n in huge.notes)


def test_export_summary_and_csv_tail(tmp_path: Path) -> None:
    summary = export_ioc_summary(2, 9, "allowlist 7")
    assert summary == "доказательства 2/9 · скрыто: allowlist 7"
    assert export_ioc_summary(4, 4, "") == "доказательства 4/4"
    shown = [
        Ioc("https://evil.example/a", IocType.URL),
        Ioc("https://evil.example/b", IocType.URL),
    ]
    result = AnalysisResult(
        source_path="batch.eml",
        source_kind="email",
        iocs=shown,
        file_rows=[
            FileTriageRow(
                path="/mail/a.eml",
                kind="email",
                top_iocs=[f"url:http://x{i}.example" for i in range(10)],
                errors=[f"fail {i}" for i in range(7)],
            )
        ],
    )
    csv_path = run_export(
        "csv",
        result,
        tmp_path / "ioc.csv",
        ioc_summary=summary,
        filters_applied={"ioc_summary": summary},
    )
    text = csv_path.read_text(encoding="utf-8-sig")
    assert "ioc_summary" in text.splitlines()[0]
    assert summary in text
    assert text.count("https://evil.example/") == 2
    batch = export_batch_csv(result, tmp_path / "batch.csv")
    batch_text = batch.read_text(encoding="utf-8-sig")
    assert "ещё 2" in batch_text
    js = export_report_json(
        result,
        tmp_path / "out.json",
        filters_applied={"ioc_summary": summary},
    )
    payload = json.loads(js.read_text(encoding="utf-8"))
    assert payload["meta"]["filters_applied"]["ioc_summary"] == summary
    assert [i["value"] for i in payload["iocs"]] == [i.value for i in shown]
    direct = export_csv(result, tmp_path / "direct.csv", ioc_summary=summary)
    assert summary in direct.read_text(encoding="utf-8-sig")


def test_nonfailure_lines_leave_the_errors_tab() -> None:
    lines = [
        "TNEF: извлечено вложений: 2",
        "Текст обрезан до 2 000 000 символов для разбора",
        "⚠ secret.zip: архив защищён паролем — содержимое не извлечено",
        "MSG: transport-заголовки частично синтезированы",
        "Чтение файла: нет такого файла",
    ]
    assert parser_failures(lines) == ["Чтение файла: нет такого файла"]
    for line in lines[:4]:
        assert not is_parser_failure(line)
    result = AnalysisResult(
        source_path="notes.eml",
        source_kind="email",
        errors=list(lines),
        attachments=[
            _att(
                "winmail.dat",
                ["tnef_attachment"],
                ["TNEF: извлечено 2 вложений"],
            ),
            _att(
                "secret.zip",
                ["encrypted_archive"],
                ["⚠ ЗАЩИЩЁН ПАРОЛЕМ: зашифрованный ZIP"],
            ),
        ],
    )
    parked = desired_result_tabs(result)
    assert any(key == "err" and "1" in label for key, label in parked)
    park_nonfailure_lines(result)
    assert result.errors == ["Чтение файла: нет такого файла"]
    assert any("Текст обрезан" in n for n in result.status_notes)
    assert any("синтезированы" in n for n in result.status_notes)
    assert result.attachments[0].notes == ["TNEF: извлечено 2 вложений"]
    assert result.attachments[1].notes == ["⚠ ЗАЩИЩЁН ПАРОЛЕМ: зашифрованный ZIP"]
    panel = source_panel_text(
        AnalysisResult(
            source_path="clip.eml",
            source_kind="email",
            status_notes=["Текст обрезан до 2 000 000 символов для разбора"],
            raw_text_preview="x" * 4000,
            body_chars=2_000_000,
        )
    )
    assert "Текст обрезан до" in panel
    assert "Показаны первые 4000 символов" in panel
    quiet = AnalysisResult(
        source_path="quiet.eml",
        source_kind="email",
        errors=lines[:4],
    )
    assert all(key != "err" for key, _label in desired_result_tabs(quiet))
