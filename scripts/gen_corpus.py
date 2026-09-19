"""Generate samples/corpus EMLs and print verdict scores (dev helper)."""

from __future__ import annotations

from pathlib import Path

from reliquary.core.pipeline import analyze_file

ROOT = Path(__file__).resolve().parents[1] / "samples" / "corpus"

_RECV = (
    "Received: from mail.internal.example (mail.internal.example [192.0.2.10]) "
    "by mx.company.local; Wed, 17 Sep 2025 10:00:00 +0000\n"
)


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    phishing = (ROOT.parent / "phishing_sample.eml").read_text(encoding="utf-8")

    files = {
        "benign_newsletter.eml": f"""\
{_RECV}From: newsletter@contoso.com
To: user@company.local
Subject: Weekly digest
Message-ID: <benign1@contoso.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

Hello, here is your weekly update from Contoso.
Visit https://www.contoso.com/docs for details.
""",
        "benign_hr_notice.eml": f"""\
{_RECV}From: hr@company.local
To: staff@company.local
Subject: Office closed Friday
Message-ID: <benign2@company.local>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

Reminder: the office is closed this Friday.
""",
        "benign_marketing_safelinks.eml": f"""\
{_RECV}From: marketing@contoso.com
To: user@company.local
Subject: Contoso product updates this month
Message-ID: <benign3@contoso.com>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

<html><body>
<p>Thanks for subscribing to the Contoso newsletter.</p>
<p>Read more:
<a href="https://nam.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.contoso.com%2Fblog%2Fupdates&amp;data=01">Contoso blog</a>
</p>
</body></html>
""",
        "fp_hr_pdf_mention.eml": f"""\
{_RECV}From: hr@company.local
To: staff@company.local
Subject: Benefits enrollment reminder
Message-ID: <benign4@company.local>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

Please review the benefits guide on the intranet.
If you previously received an invoice PDF attachment from Payroll, ignore it -
this notice has no attachment. Reply to hr@company.local with questions.
""",
        "unknown_weak_signals.eml": """\
From: friend@example.com
To: you@company.local
Subject: photos from trip
Message-ID: <unk1@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=none; dkim=none; dmarc=none

See https://share-photos.xyz/album/trip2025
""",
        "unknown_spf_none.eml": """\
From: notes@partner.example
To: you@company.local
Subject: quick link
Message-ID: <unk2@partner.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=none; dkim=pass; dmarc=pass

FYI: https://notes.partner.example/read?id=42
Also mirrored at https://cdn-mirror.top/doc/42
""",
        "suspicious_invoice_tld.eml": """\
From: billing@partner-site.club
To: finance@company.local
Subject: Invoice attached - please review
Message-ID: <sus1@partner-site.club>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=neutral; dmarc=pass

Please review the invoice: https://partner-site.club/pay/123
""",
        "suspicious_password_safelinks.eml": """\
From: it-support@vendor.example
To: user@company.local
Subject: Password will expire soon
Message-ID: <sus2@vendor.example>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Authentication-Results: mx.company.local; spf=softfail; dkim=pass; dmarc=pass

<html><body><p>Please verify your account:
<a href="https://nam.safelinks.protection.outlook.com/?url=https%3A%2F%2Fvendor.example%2Freset&amp;data=01">reset</a>
</p></body></html>
""",
        "suspicious_brand_spoof.eml": """\
From: "Microsoft Support" <help@random-vendor.biz>
Reply-To: support@totally-other.net
To: user@company.local
Subject: Your Microsoft account needs attention
Message-ID: <sus3@random-vendor.biz>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

Please contact support regarding your subscription.
Visit https://random-vendor.biz/help for details.
""",
        "suspicious_href_mismatch.eml": """\
From: notices@partner.example
To: user@company.local
Subject: Security notice
Message-ID: <sus4@partner.example>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

<html><body>
<p>Please open the portal:</p>
<p><a href="https://evil.top/login">https://www.microsoft.com/security</a></p>
</body></html>
""",
        "suspicious_credential_owa.eml": """\
From: helpdesk@corp-mail.example
To: user@company.local
Subject: OWA password reset required
Message-ID: <sus5@corp-mail.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

Your Outlook Web Access (OWA) password will expire.
Sign in to webmail and update your password immediately:
https://owa-login.corp-mail.example/owa
""",
        "suspicious_dmarc_fail.eml": """\
From: sender@partner.example
To: user@company.local
Subject: Monthly status
Message-ID: <sus6@partner.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=softfail; dkim=fail; dmarc=fail

Routine status update. No action required.
https://partner.example/status/sep
""",
        "malicious_lookalike.eml": """\
From: "Account Security" <secure@micros0ft.com>
To: user@company.local
Subject: URGENT: verify your account immediately
Message-ID: <mal3@micros0ft.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=fail; dkim=none; dmarc=fail

Your account will be suspended. Confirm your identity now:
https://micros0ft.com/login/verify
""",
        "malicious_phishing_sample.eml": phishing,
        "malicious_exe_ip_url.eml": """\
Return-Path: <bounce@bad.gq>
Received: from mail.bad.gq (unknown [203.0.113.99]) by mx.company.local; Wed, 17 Sep 2025 10:00:00 +0000
Authentication-Results: mx.company.local; spf=fail; dkim=fail; dmarc=fail
From: "IT Helpdesk" <help@bad.gq>
Reply-To: attacker@evil.top
To: victim@company.local
Subject: URGENT: Confirm your identity immediately
Message-ID: <mal2@bad.gq>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="B"

--B
Content-Type: text/plain; charset=utf-8

Confirm your identity immediately: http://198.51.100.20/login
--B
Content-Type: application/octet-stream; name="update.doc.exe"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="update.doc.exe"

TVqQAAMAAAAEAAAA
--B--
""",
    }

    for name, body in files.items():
        path = ROOT / name
        path.write_text(body, encoding="utf-8")
        result = analyze_file(path)
        v = result.verdict
        level = v.level.value if v else None
        score = v.score if v else None
        print(f"{name}: {level} score={score}")
        if v:
            for r in v.reasons[:8]:
                safe = r.encode("ascii", "replace").decode("ascii")
                print(f"  - {safe}")


if __name__ == "__main__":
    main()
