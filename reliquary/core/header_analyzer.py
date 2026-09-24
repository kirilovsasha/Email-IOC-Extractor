"""Email header authentication and spoofing analysis (offline)."""

from __future__ import annotations

import re
from email.message import Message
from email.utils import parseaddr

from reliquary.core.lookalike import check_display_name_spoof
from reliquary.core.models import HeaderFinding, MailIdentity, Severity

_KIT_MAILER_RE = re.compile(
    r"(?i)(phpmailer|swiftmailer|codeigniter|zend[_\s-]?mail|pear::mail|"
    r"javax\.mail|roundcube|wordpress|joomla|wp-mail|sendgrid|mailgun)"
)
_ORPHAN_REPLY_RE = re.compile(r"(?i)^(re|отв|ответ)\s*:")


def _addr_domain(addr: str) -> str:
    text = (addr or "").strip().lower()
    if "@" not in text:
        return ""
    return text.rsplit("@", 1)[-1].strip(">").strip()


def _same_domain(left: str, right: str) -> bool:
    if not left or not right:
        return False
    return left == right or left.endswith("." + right) or right.endswith("." + left)


def _get_all(msg: Message, name: str) -> list[str]:
    return [str(v) for v in msg.get_all(name, [])]


def analyze_headers(msg: Message) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []

    # Identity block — first: who/what this mail is
    subject = msg.get("Subject", "")
    date = msg.get("Date", "")
    mid = msg.get("Message-ID", "")
    to_hdr = msg.get("To", "")
    cc_hdr = msg.get("Cc", "")

    if subject:
        findings.append(HeaderFinding("Subject", subject, Severity.INFO, "Тема письма"))
    if date:
        findings.append(HeaderFinding("Date", date, Severity.INFO, "Дата отправки"))
    if mid:
        findings.append(HeaderFinding("Message-ID", mid, Severity.INFO, "Уникальный ID сообщения"))
    if to_hdr:
        findings.append(HeaderFinding("To", to_hdr, Severity.INFO, "Получатель"))
    if cc_hdr:
        findings.append(HeaderFinding("Cc", cc_hdr, Severity.INFO, "Копия"))

    from_hdr = msg.get("From", "")
    from_name, from_addr = parseaddr(from_hdr)
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    _, return_addr = parseaddr(return_path)
    sender = msg.get("Sender", "")

    findings.append(
        HeaderFinding("From", from_hdr or "(пусто)", Severity.INFO, "Адрес отправителя")
    )
    if return_path:
        findings.append(
            HeaderFinding("Return-Path", return_path, Severity.INFO, "Конверт отправителя (SMTP)")
        )
    if reply_to:
        findings.append(
            HeaderFinding("Reply-To", reply_to, Severity.INFO, "Адрес для ответа")
        )
        _, reply_addr = parseaddr(reply_to)
        from_dom = _addr_domain(from_addr)
        reply_dom = _addr_domain(reply_addr)
        if (
            from_addr
            and reply_addr
            and from_addr.lower() != reply_addr.lower()
            and not (from_dom and reply_dom and from_dom == reply_dom)
        ):
            findings.append(
                HeaderFinding(
                    "Reply-To mismatch",
                    f"{from_addr} ≠ {reply_addr}",
                    Severity.HIGH,
                    "Reply-To отличается от From — типичный признак фишинга",
                )
            )

    if return_addr and from_addr:
        from_dom = from_addr.split("@")[-1].lower()
        ret_dom = return_addr.split("@")[-1].lower()
        if from_dom and ret_dom and from_dom != ret_dom:
            findings.append(
                HeaderFinding(
                    "Return-Path mismatch",
                    f"{from_dom} ≠ {ret_dom}",
                    Severity.MEDIUM,
                    "Домен Return-Path не совпадает с From",
                )
            )

    # Reply-chain anomaly: In-Reply-To/References present but From domain
    # differs from Message-ID domain in the prior thread, or Re:/Отв: with
    # unrelated From (credential/BEC scored separately).
    in_reply = (msg.get("In-Reply-To") or "").strip()
    references = (msg.get("References") or "").strip()
    subject_raw = msg.get("Subject") or ""
    prior_blob = f"{in_reply} {references}".strip()
    if prior_blob and from_addr and "@" in from_addr:
        from_dom = from_addr.split("@")[-1].lower()
        prior_mids = re.findall(r"<[^>]+@([^>]+)>", prior_blob)
        prior_doms = {d.strip().lower() for d in prior_mids if d.strip()}
        re_subj = bool(re.match(r"(?i)^(re|fw|fwd|отв|пересл)\s*:", subject_raw.strip()))
        if prior_doms and from_dom and from_dom not in prior_doms and not any(
            from_dom.endswith("." + d) or d.endswith("." + from_dom) for d in prior_doms
        ):
            findings.append(
                HeaderFinding(
                    "Reply-chain anomaly",
                    f"From={from_dom} vs prior Msg-ID domain(s)={', '.join(sorted(prior_doms)[:3])}",
                    Severity.HIGH,
                    "Ответ в треде, но From-домен не совпадает с Message-ID в References/In-Reply-To",
                )
            )
        elif re_subj and in_reply and from_addr:
            # Re: subject + In-Reply-To but no usable prior domain — still note lightly
            pass
    elif _ORPHAN_REPLY_RE.match(subject_raw.strip()) and not in_reply and not references:
        findings.append(
            HeaderFinding(
                "Orphan reply",
                subject_raw.strip()[:120],
                Severity.HIGH,
                "Тема Re:/Отв: без In-Reply-To и References — возможный угон треда",
            )
        )

    if sender:
        findings.append(HeaderFinding("Sender", sender, Severity.INFO, "Заголовок Sender"))

    # Authentication-Results / ARC
    auth_results = _get_all(msg, "Authentication-Results")
    auth_blob = " | ".join(auth_results).lower()
    if auth_results:
        findings.append(
            HeaderFinding(
                "Authentication-Results",
                " | ".join(auth_results)[:500],
                Severity.INFO,
                "Результаты SPF/DKIM/DMARC от принимающего MTA",
            )
        )
        resolved_auth = resolve_auth_results(msg)
        for proto, label in (("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")):
            result = resolved_auth.get(proto, "")
            if not result:
                continue
            if result == "fail":
                findings.append(
                    HeaderFinding(
                        f"{label} result",
                        result,
                        Severity.CRITICAL if proto == "dmarc" else Severity.HIGH,
                        f"{label} fail — сильный сигнал подделки/несанкционированной отправки",
                    )
                )
            elif result == "softfail":
                findings.append(
                    HeaderFinding(
                        f"{label} result",
                        result,
                        Severity.MEDIUM,
                        f"{label} softfail — домен не подтверждён жёстко (часто фишинг)",
                    )
                )
            elif result in ("permerror", "temperror"):
                findings.append(
                    HeaderFinding(
                        f"{label} result",
                        result,
                        Severity.MEDIUM,
                        f"{label} ошибка проверки ({result})",
                    )
                )
            elif result == "pass":
                findings.append(
                    HeaderFinding(f"{label} result", result, Severity.INFO, f"{label} прошёл")
                )
            elif result == "none":
                findings.append(
                    HeaderFinding(
                        f"{label} result",
                        result,
                        Severity.LOW,
                        f"{label} отсутствует",
                    )
                )

        # Alignment: a d=/from mismatch in any Authentication-Results.
        mismatch = _dkim_alignment_mismatch(auth_results)
        if mismatch:
            d_dom, f_dom = mismatch
            findings.append(
                HeaderFinding(
                    "DKIM alignment",
                    f"d={d_dom} vs from={f_dom}",
                    Severity.HIGH,
                    "DKIM d= не совпадает с From — возможный spoof / forward",
                )
            )

        # ARC present when forwarded; absence with broken auth is noted lightly
        arc_results = _get_all(msg, "ARC-Authentication-Results")
        arc_seal = _get_all(msg, "ARC-Seal")
        arc_blob = " | ".join(arc_results).lower()
        if arc_results or arc_seal:
            arc_fail = bool(
                re.search(
                    r"(?:spf|dkim|dmarc)\s*=\s*fail|\bi\s*=\s*\d+[^\n;]*fail",
                    arc_blob,
                )
            )
            findings.append(
                HeaderFinding(
                    "ARC",
                    f"results={len(arc_results)} seal={len(arc_seal)}"
                    + (" fail" if arc_fail else ""),
                    Severity.HIGH if arc_fail else Severity.INFO,
                    (
                        "ARC-Authentication-Results: fail — цепочка ARC не подтверждает подлинность"
                        if arc_fail
                        else "Есть ARC — письмо могло быть переслано через доверенный посредник"
                    ),
                )
            )
            if arc_fail:
                findings.append(
                    HeaderFinding(
                        "ARC result",
                        "fail",
                        Severity.HIGH,
                        "ARC i=/auth fail — сигнал подделки при форварде/подмене",
                    )
                )
        elif re.search(r"spf\s*=\s*fail|dkim\s*=\s*fail|dmarc\s*=\s*fail", auth_blob):
            findings.append(
                HeaderFinding(
                    "ARC",
                    "(нет)",
                    Severity.LOW,
                    "Auth fail без ARC — нет цепочки доверия при форварде",
                )
            )
    else:
        findings.append(
            HeaderFinding(
                "Authentication-Results",
                "(отсутствует)",
                Severity.LOW,
                "Нет Authentication-Results — сложнее оценить подлинность",
            )
        )
        spf_only = resolve_auth_results(msg).get("spf", "")
        if spf_only == "fail":
            findings.append(
                HeaderFinding(
                    "SPF result",
                    spf_only,
                    Severity.HIGH,
                    "SPF fail — сильный сигнал подделки/несанкционированной отправки",
                )
            )
        elif spf_only == "softfail":
            findings.append(
                HeaderFinding(
                    "SPF result",
                    spf_only,
                    Severity.MEDIUM,
                    "SPF softfail — домен не подтверждён жёстко (часто фишинг)",
                )
            )

    # Sender ≠ From is common on lists (List-Id) and on DMARC-aligned mail.
    # Score only the unauthenticated external on-behalf case.
    if sender and from_addr:
        _, sender_addr = parseaddr(sender)
        sender_dom = _addr_domain(sender_addr)
        from_dom_sender = _addr_domain(from_addr)
        if sender_dom and from_dom_sender and not _same_domain(sender_dom, from_dom_sender):
            precedence = (msg.get("Precedence") or "").strip().lower()
            mailing = bool(msg.get("List-Id")) or precedence in {"bulk", "list", "junk"}
            dmarc_pass = resolve_auth_results(msg).get("dmarc") == "pass"
            if mailing or dmarc_pass:
                findings.append(
                    HeaderFinding(
                        "Sender mismatch",
                        f"{from_dom_sender} ≠ {sender_dom}",
                        Severity.INFO,
                        "Sender отличается от From, но есть DMARC pass или признаки рассылки",
                    )
                )
            else:
                findings.append(
                    HeaderFinding(
                        "Sender mismatch",
                        f"{from_dom_sender} ≠ {sender_dom}",
                        Severity.HIGH,
                        "Sender ≠ From без DMARC pass — типичный on-behalf BEC",
                    )
                )

    # Received chain — show first hop for mail path identity
    received = _get_all(msg, "Received")
    findings.append(
        HeaderFinding(
            "Received hops",
            str(len(received)),
            Severity.INFO,
            "Количество hops в цепочке Received",
        )
    )
    if received:
        findings.append(
            HeaderFinding(
                "Received (first)",
                received[0][:400],
                Severity.INFO,
                "Первый (ближайший к получателю) hop — откуда пришло письмо",
            )
        )
        if len(received) > 1:
            findings.append(
                HeaderFinding(
                    "Received (origin)",
                    received[-1][:400],
                    Severity.INFO,
                    "Последний hop в списке — обычно ближайший к отправителю",
                )
            )
    if len(received) == 0:
        findings.append(
            HeaderFinding(
                "Received",
                "(нет)",
                Severity.MEDIUM,
                "Нет заголовков Received — письмо могло быть сфабриковано",
            )
        )
    elif len(received) == 1:
        findings.append(
            HeaderFinding(
                "Received",
                "1 hop",
                Severity.MEDIUM,
                "Очень короткая цепочка доставки",
            )
        )

    # X-Mailer / User-Agent: script kit next to a brand display name
    x_mailer = msg.get("X-Mailer") or msg.get("User-Agent") or ""
    display_hits = check_display_name_spoof(from_hdr) if from_hdr else []
    if display_hits:
        findings.append(
            HeaderFinding(
                "Display-name spoof",
                f"name={from_name!r} addr={from_addr}",
                Severity.HIGH,
                display_hits[0].detail,
            )
        )
    if x_mailer:
        findings.append(
            HeaderFinding("X-Mailer/User-Agent", x_mailer, Severity.INFO, "Клиент отправки")
        )
        if _KIT_MAILER_RE.search(x_mailer) and display_hits:
            findings.append(
                HeaderFinding(
                    "Mailer brand mismatch",
                    x_mailer[:160],
                    Severity.HIGH,
                    "Скриптовый почтовый клиент при display-name известного бренда",
                )
            )
    if mid and from_addr and "@" in mid:
        mid_dom = mid.rsplit("@", 1)[-1].strip("> ").lower()
        from_dom = from_addr.split("@")[-1].lower()
        if mid_dom and from_dom and mid_dom != from_dom:
            findings.append(
                HeaderFinding(
                    "Message-ID domain",
                    f"{mid_dom} vs {from_dom}",
                    Severity.LOW,
                    "Домен Message-ID отличается от From (не всегда malicious)",
                )
            )
    resent = msg.get("Resent-From") or ""
    _, resent_addr = parseaddr(resent)
    resent_dom = _addr_domain(resent_addr)
    from_dom_hdr = _addr_domain(from_addr)
    if resent_dom and from_dom_hdr and not _same_domain(resent_dom, from_dom_hdr):
        findings.append(
            HeaderFinding(
                "Resent-From domain",
                f"{resent_dom} vs {from_dom_hdr}",
                Severity.MEDIUM,
                "Домен Resent-From отличается от From",
            )
        )

    # Urgent / social engineering subject cues are handled in verdict; keep X-Priority
    priority = msg.get("X-Priority") or msg.get("Importance") or ""
    if priority:
        findings.append(
            HeaderFinding("Priority", priority, Severity.INFO, "Приоритет письма")
        )

    return findings


_RAW_HEADER_KEYS = (
    "From",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-ID",
    "Return-Path",
    "Reply-To",
    "Sender",
    "Authentication-Results",
    "ARC-Authentication-Results",
    "ARC-Seal",
    "Received-SPF",
    "DKIM-Signature",
    "X-Mailer",
    "User-Agent",
    "X-Originating-IP",
    "X-Priority",
    "Importance",
)


def extract_raw_headers(msg: Message) -> dict[str, str]:
    """Key headers as plain strings for display / copy."""
    out: dict[str, str] = {}
    for key in _RAW_HEADER_KEYS:
        values = _get_all(msg, key)
        if values:
            out[key] = " | ".join(values) if key != "Received" else values[0]
    received = _get_all(msg, "Received")
    if received:
        out["Received-Count"] = str(len(received))
        out["Received-First"] = received[0]
        if len(received) > 1:
            out["Received-Origin"] = received[-1]
    return out


_AUTH_PROTOS = ("spf", "dkim", "dmarc")


# fail/softfail already beat pass. permerror/temperror must too.
_AUTH_PRIORITY = ("fail", "softfail", "permerror", "temperror")


def _domains_aligned(d_dom: str, f_dom: str) -> bool:
    return bool(d_dom and f_dom) and (d_dom == f_dom or f_dom.endswith("." + d_dom))


def _auth_identity_domain(token: str) -> str:
    """Domain of header.i (@evil.test or user@evil.test)."""
    raw = token.strip().strip("\"'").lower()
    if "@" in raw:
        raw = raw.rsplit("@", 1)[-1]
    return raw.strip(".")


def _dkim_alignment_mismatch(auth_results: list[str]) -> tuple[str, str] | None:
    """d= or header.i vs header.from when any Authentication-Results pair disagrees."""
    pairs: list[tuple[list[str], list[str]]] = []
    for header in auth_results:
        low = header.lower()
        ds = re.findall(r"header\.d\s*=\s*([a-z0-9.-]+)", low)
        for token in re.findall(r"header\.i\s*=\s*([^\s;]+)", low):
            ident = _auth_identity_domain(token)
            if ident and ident not in ds:
                ds.append(ident)
        fs = re.findall(r"header\.from\s*=\s*([a-z0-9.-]+)", low)
        pairs.append((ds, fs))
        if not ds or not fs:
            continue
        for d_dom in ds:
            if any(_domains_aligned(d_dom, f_dom) for f_dom in fs):
                continue
            return d_dom, fs[0]
    froms = list(dict.fromkeys(f_dom for _, fs in pairs for f_dom in fs))
    if len(froms) != 1:
        return None
    f_dom = froms[0]
    for ds, _fs in pairs:
        for d_dom in ds:
            if d_dom and not _domains_aligned(d_dom, f_dom):
                return d_dom, f_dom
    return None


def resolve_auth_results(msg: Message) -> dict[str, str]:
    """SPF/DKIM/DMARC for the card. Later fail/softfail/permerror/temperror beat pass."""
    found: dict[str, list[str]] = {proto: [] for proto in _AUTH_PROTOS}
    for header in _get_all(msg, "Authentication-Results"):
        low = header.lower()
        for proto in _AUTH_PROTOS:
            found[proto].extend(re.findall(rf"{proto}\s*=\s*([a-z]+)", low))
    for header in _get_all(msg, "Received-SPF"):
        match = re.match(r"\s*([a-z]+)", header.strip().lower())
        if match:
            found["spf"].append(match.group(1))
    chosen: dict[str, str] = {}
    for proto, values in found.items():
        if not values:
            continue
        for status in _AUTH_PRIORITY:
            if status in values:
                chosen[proto] = status
                break
        else:
            # No hard failure: a later pass beats an earlier neutral or bestguesspass.
            chosen[proto] = "pass" if "pass" in values else values[0]
    return chosen


def build_mail_identity(msg: Message) -> MailIdentity:
    resolved = resolve_auth_results(msg)

    def _auth(proto: str) -> str:
        return resolved.get(proto, "")

    received = _get_all(msg, "Received")
    return MailIdentity(
        from_header=msg.get("From", "") or "",
        return_path=msg.get("Return-Path", "") or "",
        reply_to=msg.get("Reply-To", "") or "",
        subject=msg.get("Subject", "") or "",
        message_id=msg.get("Message-ID", "") or "",
        date=msg.get("Date", "") or "",
        in_reply_to=msg.get("In-Reply-To", "") or "",
        references=msg.get("References", "") or "",
        auto_submitted=msg.get("Auto-Submitted", "") or "",
        list_id=msg.get("List-Id", "") or "",
        list_unsubscribe=msg.get("List-Unsubscribe", "") or "",
        precedence=msg.get("Precedence", "") or "",
        spf=_auth("spf"),
        dkim=_auth("dkim"),
        dmarc=_auth("dmarc"),
        received_hops=len(received),
        first_received=received[0][:300] if received else "",
    )
