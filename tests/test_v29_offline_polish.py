"""v2.9: benign markers, thread keys, nested depth, verdict_extra schema, RU export."""

from __future__ import annotations

import json
from pathlib import Path

from reliquary.core.models import MailIdentity
from reliquary.core.pipeline import analyze_file, campaign_key_for
from reliquary.core.prefs import _coerce_value
from reliquary.core.verdict import (
    VerdictConfig,
    validate_verdict_extra,
)
from reliquary.gui.export_actions import EXPORT_CHOICES, normalize_export_kind

CORPUS = Path(__file__).resolve().parents[1] / "samples" / "corpus"


def test_mail_identity_thread_root() -> None:
    mid = MailIdentity(
        message_id="<me@x>",
        in_reply_to="<irt@x>",
        references="<root@x> <irt@x>",
    )
    assert mid.thread_root_id() == "<root@x>"
    mid2 = MailIdentity(message_id="<me@x>", in_reply_to="<irt@x>")
    assert mid2.thread_root_id() == "<irt@x>"


def test_campaign_key_prefers_thread() -> None:
    r = analyze_file(CORPUS / "benign_thread_reply.eml")
    key = campaign_key_for(r)
    assert key.startswith("thread:")
    assert "thread_root@company.local" in key


def test_benign_auto_reply_mitigation() -> None:
    r = analyze_file(CORPUS / "benign_auto_reply.eml")
    assert r.verdict is not None
    assert r.verdict.level.value == "benign"
    assert r.mail_identity is not None
    assert "auto-replied" in (r.mail_identity.auto_submitted or "").lower()
    reasons = " ".join(b.reason for b in r.verdict.breakdown if b.category == "mitigation")
    assert "Автоответ" in reasons or "Out-of-Office" in reasons or "подпись" in reasons.lower()


def test_benign_thread_reply_mitigation() -> None:
    r = analyze_file(CORPUS / "benign_thread_reply.eml")
    assert r.verdict is not None
    assert r.verdict.level.value == "benign"
    reasons = " ".join(b.reason for b in r.verdict.breakdown if b.category == "mitigation")
    assert "треде" in reasons.lower() or "In-Reply-To" in reasons


def test_calendar_invite_mitigation() -> None:
    r = analyze_file(CORPUS / "benign_calendar_invite.eml")
    assert r.verdict is not None
    assert r.verdict.level.value == "benign"
    # Meeting subject / body should contribute calendar mitigation or stay low via auth
    assert r.verdict.score <= 9


def test_nested_mail_depth2() -> None:
    r = analyze_file(CORPUS / "suspicious_nested_depth2.eml")
    blob = (r.raw_text_preview or "") + " ".join(i.value for i in r.iocs)
    assert "evil.top" in blob or any("evil.top" in (i.value or "") for i in r.iocs)
    assert r.verdict is not None
    assert r.verdict.level.value in ("suspicious", "malicious", "unknown")


def test_validate_verdict_extra_schema() -> None:
    ok = validate_verdict_extra({"threshold_malicious": 55, "_comment": "x"})
    assert ok == []
    bad = validate_verdict_extra({"threshold_malicious": 999, "nope": 1})
    assert any("999" in w or "порог" in w for w in bad)
    assert any("неизвестный" in w for w in bad)


def test_benign_weights_in_config() -> None:
    cfg = VerdictConfig()
    assert cfg.weight_auto_reply < 0
    assert cfg.weight_calendar_invite < 0
    assert cfg.cap_mitigation >= 30


def test_export_ticket_ru() -> None:
    assert "Тикет" in EXPORT_CHOICES
    assert "Handoff" not in EXPORT_CHOICES
    assert normalize_export_kind("Тикет") == "handoff"
    assert normalize_export_kind("handoff") == "handoff"


def test_prefs_handoff_legacy_maps_to_ticket() -> None:
    assert _coerce_value("export_choice", "Handoff", "JSON") == "Тикет"


def test_schema_mail_identity_thread_fields() -> None:
    r = analyze_file(CORPUS / "benign_thread_reply.eml")
    payload = r.to_dict()
    mid = payload.get("mail_identity") or {}
    assert "in_reply_to" in mid
    assert "references" in mid
    assert "auto_submitted" in mid
    assert mid["in_reply_to"]


def test_example_verdict_extra_matches_schema() -> None:
    root = Path(__file__).resolve().parents[1]
    data = json.loads((root / "verdict_extra.example.json").read_text(encoding="utf-8"))
    assert validate_verdict_extra(data) == []
