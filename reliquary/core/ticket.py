"""Ticket / handoff text templates for SOC clipboard paste."""

from __future__ import annotations

import configparser
from pathlib import Path

from reliquary.core.defang import defang_value
from reliquary.core.models import AnalysisResult, Ioc
from reliquary.core.paths import config_path, ensure_user_lists

_BUILTIN: dict[str, dict[str, str]] = {
    "ru": {
        "title": "=== IOC Extractor — заметка triage ===",
        "source": "Источник",
        "kind": "Тип",
        "analyzed": "Разобрано",
        "app": "Приложение",
        "source_sha": "SHA256 источника",
        "verdict": "Вердикт",
        "summary": "Итог",
        "reasons": "Причины",
        "mail": "--- Письмо ---",
        "subject": "Тема",
        "from": "From",
        "reply_to": "Reply-To",
        "return_path": "Return-Path",
        "message_id": "Message-ID",
        "auth": "Auth",
        "date": "Дата",
        "urls": "--- Раскрытые URL ---",
        "none": "(нет)",
        "attachments": "--- Вложения ---",
        "iocs": "--- IOC (топ {max}) ---",
        "batch": "--- Пакет файлов ---",
        "end": "=== конец ===",
    },
    "en": {
        "title": "=== IOC Extractor — triage note ===",
        "source": "Source",
        "kind": "Kind",
        "analyzed": "Analyzed",
        "app": "App",
        "source_sha": "Source SHA256",
        "verdict": "Verdict",
        "summary": "Summary",
        "reasons": "Reasons",
        "mail": "--- Mail ---",
        "subject": "Subject",
        "from": "From",
        "reply_to": "Reply-To",
        "return_path": "Return-Path",
        "message_id": "Message-ID",
        "auth": "Auth",
        "date": "Date",
        "urls": "--- Unwrapped URLs ---",
        "none": "(none)",
        "attachments": "--- Attachments ---",
        "iocs": "--- IOC (top {max}) ---",
        "batch": "--- Batch files ---",
        "end": "=== end ===",
    },
}


def load_ticket_config() -> tuple[str, bool, int, dict[str, str]]:
    """Return (lang, defang_default, max_iocs, labels)."""
    ensure_user_lists()
    lang = "ru"
    do_defang = True
    max_iocs = 40
    path = config_path("ticket.ini")
    cp = configparser.ConfigParser()
    if path.is_file():
        try:
            cp.read(path, encoding="utf-8")
        except (OSError, configparser.Error):
            cp = configparser.ConfigParser()
    if cp.has_section("ticket"):
        lang = (cp.get("ticket", "lang", fallback=lang) or lang).strip().lower()
        if lang not in _BUILTIN:
            lang = "ru"
        do_defang = cp.getboolean("ticket", "defang", fallback=do_defang)
        try:
            max_iocs = max(5, min(200, cp.getint("ticket", "max_iocs", fallback=max_iocs)))
        except ValueError:
            pass
    labels = dict(_BUILTIN[lang])
    section = f"labels.{lang}"
    if cp.has_section(section):
        for key, val in cp.items(section):
            labels[key] = val
    return lang, do_defang, max_iocs, labels


def build_ticket_template(
    result: AnalysisResult,
    iocs: list[Ioc] | None = None,
    *,
    defang: bool | None = None,
    max_iocs: int | None = None,
    short: bool = False,
    lang: str | None = None,
) -> str:
    """Plain-text triage note suitable for ITSM / chat handoff."""
    cfg_lang, cfg_defang, cfg_max, labels = load_ticket_config()
    if lang in _BUILTIN:
        labels = dict(_BUILTIN[lang])
        # Merge optional file overrides for that language
        path = config_path("ticket.ini")
        if path.is_file():
            cp = configparser.ConfigParser()
            try:
                cp.read(path, encoding="utf-8")
                section = f"labels.{lang}"
                if cp.has_section(section):
                    for key, val in cp.items(section):
                        labels[key] = val
            except (OSError, configparser.Error):
                pass
    elif cfg_lang:
        pass  # labels already from config
    use_defang = cfg_defang if defang is None else defang
    use_max = cfg_max if max_iocs is None else max_iocs
    items = iocs if iocs is not None else result.iocs
    mid = result.mail_identity

    if short:
        return _short_ticket(result, items, defang=use_defang, labels=labels)

    L = labels
    lines: list[str] = [
        L["title"],
        f"{L['source']}: {result.source_path}",
        f"{L['kind']}: {result.source_kind}",
    ]
    if result.meta:
        lines.append(f"{L['analyzed']}: {result.meta.analyzed_at}")
        lines.append(f"{L['app']}: v{result.meta.app_version}")
        if result.meta.source_sha256:
            lines.append(f"{L['source_sha']}: {result.meta.source_sha256}")

    if result.verdict:
        lines.append(
            f"{L['verdict']}: {result.verdict.level.value.upper()} (score {result.verdict.score})"
        )
        lines.append(f"{L['summary']}: {result.verdict.summary}")
        if result.verdict.reasons:
            lines.append(f"{L['reasons']}:")
            for r in result.verdict.reasons[:8]:
                lines.append(f"  - {r}")

    lines.append("")
    lines.append(L["mail"])
    subject = (mid.subject if mid and mid.subject else result.subject) or "—"
    sender = (mid.from_header if mid and mid.from_header else result.sender) or "—"
    reply_to = (mid.reply_to if mid else "") or "—"
    lines.append(f"{L['subject']}: {subject}")
    lines.append(f"{L['from']}: {sender}")
    lines.append(f"{L['reply_to']}: {reply_to}")
    if mid:
        lines.append(f"{L['return_path']}: {mid.return_path or '—'}")
        lines.append(f"{L['message_id']}: {mid.message_id or '—'}")
        lines.append(
            f"{L['auth']}: SPF={mid.spf or '—'} DKIM={mid.dkim or '—'} DMARC={mid.dmarc or '—'}"
        )
        lines.append(f"{L['date']}: {mid.date or '—'}")

    lines.append("")
    lines.append(L["urls"])
    rewrites = [u for u in result.url_rewrites if u.changed]
    if not rewrites:
        lines.append(L["none"])
    else:
        for u in rewrites[:20]:
            val = defang_value(u.unwrapped) if use_defang else u.unwrapped
            lines.append(f"  {u.rewriter}: {val}")

    lines.append("")
    lines.append(L["attachments"])
    if not result.attachments:
        lines.append(L["none"])
    else:
        for a in result.attachments[:30]:
            flags = ",".join(a.risk_flags) if a.risk_flags else "-"
            lines.append(f"  {a.filename} | {a.size}B | sha256={a.sha256} | flags={flags}")
            if a.ole_streams:
                lines.append(f"    OLE streams: {', '.join(a.ole_streams[:8])}")

    lines.append("")
    lines.append(L["iocs"].replace("{max}", str(use_max)))
    if not items:
        lines.append(L["none"])
    else:
        for ioc in items[:use_max]:
            val = defang_value(ioc.value) if use_defang else ioc.value
            tags = ",".join(ioc.tags) if ioc.tags else ""
            suffix = f" [{tags}]" if tags else ""
            lines.append(f"  {ioc.ioc_type.value}|{val}{suffix}")

    if result.file_rows and len(result.file_rows) > 1:
        lines.append("")
        lines.append(L["batch"])
        for row in result.file_rows:
            name = Path(row.path).name
            v = row.verdict_level or "-"
            err = f" err={len(row.errors)}" if row.errors else ""
            lines.append(f"  {name} | {row.kind} | {v} | iocs={row.ioc_count}{err}")

    lines.append("")
    lines.append(L["end"])
    return "\n".join(lines)


def _short_ticket(
    result: AnalysisResult, items: list[Ioc], *, defang: bool, labels: dict[str, str]
) -> str:
    mid = result.mail_identity
    v = result.verdict
    subject = (mid.subject if mid and mid.subject else result.subject) or "—"
    sender = (mid.from_header if mid and mid.from_header else result.sender) or "—"
    mid_s = (mid.message_id if mid else "") or "—"
    verdict = f"{v.level.value.upper()} {v.score}" if v else "—"
    lines = [
        f"{labels['verdict']}: {verdict} | {Path(result.source_path).name}",
        f"{labels['from']}: {sender}",
        f"{labels['subject']}: {subject}",
        f"Msg-ID: {mid_s}",
    ]
    if mid:
        lines.append(
            f"{labels['auth']}: SPF={mid.spf or '—'} DKIM={mid.dkim or '—'} DMARC={mid.dmarc or '—'}"
        )
    unwrap = next((u.unwrapped for u in result.url_rewrites if u.changed), "")
    if unwrap:
        lines.append(f"URL: {defang_value(unwrap) if defang else unwrap}")
    if result.attachments:
        a = result.attachments[0]
        lines.append(f"Att: {a.filename} sha256={a.sha256[:16]}…")
    top = items[:5]
    if top:
        vals = [defang_value(ioc.value) if defang else ioc.value for ioc in top]
        lines.append("IOC: " + " | ".join(vals))
    return "\n".join(lines)


def build_message_id_block(result: AnalysisResult) -> str:
    """Message-ID (+ subject) for campaign correlation."""
    mid = result.mail_identity
    parts: list[str] = []
    if mid and mid.message_id:
        parts.append(mid.message_id)
    elif result.raw_headers.get("Message-ID"):
        parts.append(result.raw_headers["Message-ID"])
    if mid and mid.subject:
        parts.append(f"Subject: {mid.subject}")
    elif result.subject:
        parts.append(f"Subject: {result.subject}")
    if result.file_rows:
        for row in result.file_rows:
            if row.message_id:
                parts.append(row.message_id)
    seen: set[str] = set()
    out: list[str] = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return "\n".join(out)
