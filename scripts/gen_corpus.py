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
        # --- expanded corpus (v2.4) ---
        "benign_internal_relay.eml": f"""\
{_RECV}From: ops@company.local
To: staff@company.local
Subject: Weekly ops digest
Message-ID: <benign5@company.local>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

Internal status update. No action required.
""",
        "benign_arc_forward.eml": f"""\
Received: from outlook.office365.com (outlook.office365.com [40.92.0.1]) by mx.company.local; Wed, 17 Sep 2025 10:00:00 +0000
From: colleague@partner.example
To: you@company.local
Subject: Fwd: project notes
Message-ID: <benign6@partner.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass
ARC-Authentication-Results: i=1; mx.company.local; spf=pass; dkim=pass; dmarc=pass
ARC-Seal: i=1; a=rsa-sha256; s=arcselector; d=company.local; b=abc

Forwarded notes from the partner thread.
https://www.contoso.com/docs/notes
""",
        "benign_calendar_invite.eml": f"""\
{_RECV}From: calendar@contoso.com
To: user@company.local
Subject: Meeting: Q3 planning
Message-ID: <benign7@contoso.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

You are invited to Q3 planning tomorrow at 10:00.
Join: https://teams.microsoft.com/l/meetup-join/example
""",
        "fp_softfail_legit_brand.eml": f"""\
{_RECV}From: noreply@microsoft.com
To: user@company.local
Subject: Your Microsoft 365 subscription
Message-ID: <fp2@microsoft.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=softfail; dkim=pass; dmarc=pass

Your Microsoft 365 subscription renews soon.
Manage at https://account.microsoft.com/services
""",
        "unknown_bec_wire.eml": """\
From: "CFO Office" <cfo.office@partner-finance.biz>
To: ap@company.local
Subject: Urgent wire transfer approval
Message-ID: <unk3@partner-finance.biz>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

Please process the wire transfer today. Reply with confirmation.
No attachment. Call me only on my mobile.
""",
        "unknown_short_received.eml": """\
Received: from unknown (unknown [203.0.113.50]) by mx.company.local; Wed, 17 Sep 2025 10:00:00 +0000
From: tip@random.example
To: you@company.local
Subject: FYI
Message-ID: <unk4@random.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=none; dkim=none; dmarc=none

See https://notes.example/read/1
""",
        "suspicious_bec_ceo.eml": """\
From: "CEO" <ceo@company-mail.biz>
Reply-To: personal@totally-other.net
To: finance@company.local
Subject: URGENT: process payment immediately
Message-ID: <sus7@company-mail.biz>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

I need you to process this payment immediately. Do not discuss with anyone.
Confirm your identity on the call later.
""",
        "suspicious_hidden_html.eml": """\
From: notices@partner.example
To: user@company.local
Subject: Account notice
Message-ID: <sus8@partner.example>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

<html><body>
<p style="font-size:0;color:#fff;display:none">verify your account password expire unlock</p>
<p>Please review your account settings.</p>
<p><a href="https://portal.partner.example/settings">Open settings</a></p>
</body></html>
""",
        "suspicious_html_form.eml": """\
From: security@vendor.example
To: user@company.local
Subject: Confirm your mailbox
Message-ID: <sus9@vendor.example>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Authentication-Results: mx.company.local; spf=softfail; dkim=pass; dmarc=pass

<html><body>
<p>Confirm your identity:</p>
<form action="https://evil.top/harvest" method="post">
<input name="password" type="password"/>
<button type="submit">Sign in</button>
</form>
</body></html>
""",
        "suspicious_arc_auth_fail.eml": """\
Received: from mail.protection.outlook.com by mx.company.local; Wed, 17 Sep 2025 10:00:00 +0000
From: sender@partner.example
To: user@company.local
Subject: Status with ARC
Message-ID: <sus10@partner.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=fail; dkim=fail; dmarc=fail
ARC-Authentication-Results: i=1; mx.company.local; spf=fail; dkim=fail; dmarc=fail
ARC-Seal: i=1; a=rsa-sha256; s=arc; d=company.local; b=xyz

Routine note with broken auth but ARC present.
https://partner.example/status
""",
        "suspicious_qr_mention.eml": """\
From: facilities@vendor.example
To: user@company.local
Subject: Scan QR to unlock door
Message-ID: <sus11@vendor.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

Scan the QR code image in the next message to verify your account immediately.
Do not share the code. Visit https://door-access.club/unlock
""",
        "suspicious_nested_eml.eml": """\
From: relay@odd.example
To: user@company.local
Subject: FW: invoice
Message-ID: <sus12@odd.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="N"

--N
Content-Type: text/plain; charset=utf-8

Forwarded message attached.
--N
Content-Type: message/rfc822; name="inner.eml"
Content-Disposition: attachment; filename="inner.eml"
Content-Transfer-Encoding: 7bit

From: inner@evil.top
To: victim@company.local
Subject: pay now
Message-ID: <inner@evil.top>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Pay https://evil.top/pay immediately
--N--
""",
        "suspicious_dkim_misalign.eml": """\
From: notices@brand.example
To: user@company.local
Subject: Security alert
Message-ID: <sus13@brand.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass header.d=other-mailer.net header.from=brand.example; dmarc=pass

Please verify your account: https://brand.example/secure
""",
        "malicious_encrypted_zip.eml": """\
Return-Path: <bounce@bad.gq>
Received: from mail.bad.gq (unknown [203.0.113.88]) by mx.company.local; Wed, 17 Sep 2025 10:00:00 +0000
Authentication-Results: mx.company.local; spf=fail; dkim=fail; dmarc=fail
From: "IT" <help@bad.gq>
To: victim@company.local
Subject: URGENT: password protected archive
Message-ID: <mal4@bad.gq>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="Z"

--Z
Content-Type: text/plain; charset=utf-8

Open the attached archive. Password is 1234. Confirm your identity immediately.
--Z
Content-Type: application/zip; name="invoice.zip"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice.zip"

UEsDBBQACQAIAAAAIQAAAAAAAAAAAAAAAAAJAAAAaW52b2ljZS50eHRTW4O/nJcAUesL
--Z--
""",
        "malicious_idn_homoglyph.eml": """\
From: "Apple Support" <secure@xn--pple-43d.com>
To: user@company.local
Subject: URGENT: verify your Apple ID immediately
Message-ID: <mal5@xn--pple-43d.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=fail; dkim=none; dmarc=fail

Your Apple ID will be locked. Confirm your identity:
https://xn--pple-43d.com/login
""",
        "malicious_macro_docm.eml": """\
Return-Path: <x@evil.top>
Received: from evil.top by mx.company.local; Wed, 17 Sep 2025 10:00:00 +0000
Authentication-Results: mx.company.local; spf=fail; dkim=fail; dmarc=fail
From: billing@evil.top
To: finance@company.local
Subject: Invoice - open urgently
Message-ID: <mal6@evil.top>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="M"

--M
Content-Type: text/plain; charset=utf-8

Open the attached macro-enabled document immediately.
--M
Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="invoice.docm"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice.docm"

UEsDBBQABgAIAAAAIQAAAAAAAAAAAAAAAAAAAAAAAA==
--M--
""",
        "campaign_a1.eml": """\
From: blast@campaign.example
To: a@company.local
Subject: Campaign wave A
Message-ID: <same-campaign-id@campaign.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=none; dkim=none; dmarc=none

Wave A copy 1: https://share-photos.xyz/a1
""",
        "campaign_a2.eml": """\
From: blast@campaign.example
To: b@company.local
Subject: Campaign wave A
Message-ID: <same-campaign-id@campaign.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=none; dkim=none; dmarc=none

Wave A copy 2: https://share-photos.xyz/a2
""",
        "benign_google_workspace.eml": f"""\
Received: from mail.google.com (mail.google.com [142.250.0.1]) by mx.company.local; Wed, 17 Sep 2025 10:00:00 +0000
From: alerts@google.com
To: user@company.local
Subject: Device activity notice
Message-ID: <benign8@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

A new device was used with your Google Account on Windows.
If this was you, no action is needed.
https://myaccount.google.com/notifications
""",
        "unknown_empty_body.eml": """\
From: blank@example.com
To: you@company.local
Subject: (no subject)
Message-ID: <unk5@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=none; dkim=none; dmarc=none

""",
        "suspicious_return_path_mismatch.eml": """\
Return-Path: <bounce@totally-other.net>
From: support@vendor.example
To: user@company.local
Subject: Password will expire soon
Message-ID: <sus14@vendor.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=softfail; dkim=pass; dmarc=pass

Please verify your account immediately:
https://vendor.example/reset
""",
        "malicious_ip_url_urgency.eml": """\
From: help@bad.gq
To: victim@company.local
Subject: URGENT: confirm your identity immediately
Message-ID: <mal7@bad.gq>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=fail; dkim=fail; dmarc=fail

Your account is locked. Confirm your identity:
http://203.0.113.77/login
""",
        "suspicious_messenger_lure.eml": """\
From: hr@partner.example
To: user@company.local
Subject: Salary question - write in Telegram
Message-ID: <sus15@partner.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

Please contact me urgently in Telegram @payroll_help_desk about your salary.
Also see https://partner-site.club/pay
""",
        "benign_dmarc_pass_only.eml": f"""\
{_RECV}From: news@contoso.com
To: user@company.local
Subject: Product changelog
Message-ID: <benign9@contoso.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Authentication-Results: mx.company.local; spf=pass; dkim=pass; dmarc=pass

Changelog for September is available on the docs site.
https://www.contoso.com/changelog
""",
        "unknown_proofpoint_url.eml": """\
From: news@vendor.example
To: user@company.local
Subject: Link wrapped
Message-ID: <unk6@vendor.example>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Authentication-Results: mx.company.local; spf=none; dkim=none; dmarc=none

<html><body>
<a href="https://urldefense.proofpoint.com/v2/url?u=https-3A__notes.partner.example_read&amp;d=DwMFaQ">notes</a>
</body></html>
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
