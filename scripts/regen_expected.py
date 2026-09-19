"""Regenerate samples/corpus/expected.json from current analyzer output."""

from __future__ import annotations

import json
from pathlib import Path

from reliquary.core.pipeline import analyze_file

CORPUS = Path(__file__).resolve().parents[1] / "samples" / "corpus"
BANDS = {
    "benign": (0, 9),
    "unknown": (10, 29),
    "suspicious": (30, 59),
    "malicious": (60, 100),
}
NEEDLES = {
    "benign_marketing_safelinks.eml": ["rewrite", "SafeLinks", "URL"],
    "unknown_weak_signals.eml": [".xyz", "SPF", "none"],
    "unknown_spf_none.eml": ["SPF", ".top", "none"],
    "suspicious_invoice_tld.eml": [".club"],
    "suspicious_password_safelinks.eml": [
        "softfail",
        "password",
        "rewrite",
        "SafeLinks",
        "verify",
        "urgent",
    ],
    "suspicious_brand_spoof.eml": ["Reply-To", "spoof", "Display", "Microsoft"],
    "suspicious_href_mismatch.eml": ["evil.top", "href", "mismatch", ".top", "microsoft"],
    "suspicious_credential_owa.eml": ["OWA", "password", "webmail", "login", "credential"],
    "suspicious_dmarc_fail.eml": ["DMARC", "softfail", "fail"],
    "malicious_lookalike.eml": ["lookalike", "micros0ft", "microsoft"],
    "malicious_phishing_sample.eml": [
        "double_extension",
        "dangerous_extension",
        "SPF",
        "fail",
    ],
    "malicious_exe_ip_url.eml": ["double_extension", "IP"],
    "suspicious_nested_eml.eml": ["nested", "evil.top"],
    "malicious_encrypted_zip.eml": ["encrypted", "archive", "fail"],
    "campaign_a1.eml": [".xyz"],
    "campaign_a2.eml": [".xyz"],
}


def main() -> None:
    out: dict = {}
    for path in sorted(CORPUS.glob("*.eml")):
        result = analyze_file(path)
        verdict = result.verdict
        assert verdict is not None, path.name
        level = verdict.level.value
        smin, smax = BANDS[level]
        entry: dict = {"level": level, "score_min": smin, "score_max": smax}
        if path.name in NEEDLES:
            entry["reason_substrings"] = NEEDLES[path.name]
        out[path.name] = entry
        print(f"{path.name}: {level} {verdict.score}")
    (CORPUS / "expected.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(out)} entries")


if __name__ == "__main__":
    main()
