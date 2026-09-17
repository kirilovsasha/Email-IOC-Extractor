"""Email header authentication and spoofing analysis (offline)."""

from __future__ import annotations

import re
from email.message import Message
from email.utils import parseaddr

from reliquary.core.models import HeaderFinding, Severity


def _get_all(msg: Message, name: str) -> list[str]:
    return [str(v) for v in msg.get_all(name, [])]


def analyze_headers(msg: Message) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []

    from_hdr = msg.get("From", "")
    from_name, from_addr = parseaddr(from_hdr)
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    _, return_addr = parseaddr(return_path)
    sender = msg.get("Sender", "")

    findings.append(
        HeaderFinding("From", from_hdr or "(пусто)", Severity.INFO, "Адрес отправителя")
    )
    if reply_to:
        findings.append(
            HeaderFinding("Reply-To", reply_to, Severity.INFO, "Адрес для ответа")
        )
        _, reply_addr = parseaddr(reply_to)
        if from_addr and reply_addr and from_addr.lower() != reply_addr.lower():
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
        for proto, label in (("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")):
            m = re.search(rf"{proto}\s*=\s*([a-z]+)", auth_blob)
            if not m:
                continue
            result = m.group(1)
            if result in ("fail", "permerror", "temperror", "softfail"):
                sev = Severity.HIGH if result == "fail" else Severity.MEDIUM
                findings.append(
                    HeaderFinding(
                        f"{label} result",
                        result,
                        sev,
                        f"{label} не прошёл проверку ({result})",
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
    else:
        findings.append(
            HeaderFinding(
                "Authentication-Results",
                "(отсутствует)",
                Severity.LOW,
                "Нет Authentication-Results — сложнее оценить подлинность",
            )
        )

    # Received chain
    received = _get_all(msg, "Received")
    findings.append(
        HeaderFinding(
            "Received hops",
            str(len(received)),
            Severity.INFO,
            "Количество hops в цепочке Received",
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
                Severity.LOW,
                "Очень короткая цепочка доставки",
            )
        )

    # X-Mailer / User-Agent anomalies
    x_mailer = msg.get("X-Mailer") or msg.get("User-Agent") or ""
    if x_mailer:
        findings.append(
            HeaderFinding("X-Mailer/User-Agent", x_mailer, Severity.INFO, "Клиент отправки")
        )

    # Display-name spoofing: brand in name, different domain
    if from_name and from_addr:
        brand_hints = (
            "microsoft",
            "google",
            "apple",
            "amazon",
            "paypal",
            "sber",
            "тинькофф",
            "tinkoff",
            "втб",
            "газпром",
            "support",
            "security",
            "admin",
            "noreply",
            "no-reply",
        )
        name_l = from_name.lower()
        dom = from_addr.split("@")[-1].lower()
        for brand in brand_hints:
            if brand in name_l and brand not in dom:
                findings.append(
                    HeaderFinding(
                        "Display-name spoof",
                        f"name={from_name!r} addr={from_addr}",
                        Severity.HIGH,
                        f"Имя содержит «{brand}», но домен другой — возможный spoofing",
                    )
                )
                break

    # Message-ID domain vs From domain
    mid = msg.get("Message-ID", "")
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

    # Urgent / social engineering subject cues are handled in verdict; keep X-Priority
    priority = msg.get("X-Priority") or msg.get("Importance") or ""
    if priority:
        findings.append(
            HeaderFinding("Priority", priority, Severity.INFO, "Приоритет письма")
        )

    return findings
