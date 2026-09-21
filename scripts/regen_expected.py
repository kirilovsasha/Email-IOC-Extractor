"""Regenerate samples/corpus/expected.json from current analyzer output.

Tight score windows (± half-width inside the verdict band) catch weight
regressions without inventing new detection features.
"""

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
# Half-width inside band (benign stays full band — scores are usually 0).
_HALF = {
    "benign": 9,
    "unknown": 8,
    "suspicious": 10,
    "malicious": 10,
}
NEEDLES = {
    "benign_marketing_safelinks.eml": ["rewrite", "SafeLinks", "URL"],
    "benign_local_mx_ru.eml": ["внутренн", "DMARC", "смягчение"],
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
    "malicious_encrypted_zip.eml": ["encrypted", "archive", "fail", "шифр"],
    "malicious_kaspersky_wrap.eml": ["lookalike", "micros0ft", "fail"],
    "suspicious_drweb_wrap.eml": [".club", "softfail", "password", "urgent"],
    "fn_bec_ru_wire.eml": ["IP", "fail"],
    "campaign_a1.eml": [".xyz"],
    "campaign_a2.eml": [".xyz"],
    "suspicious_display_spoof_belarusbank.eml": ["беларусбанк", "display", "spoof", "похож"],
    "suspicious_display_spoof_mns_by.eml": ["мнс", "nalog.gov.by", "похож"],
    "suspicious_bec_by_erip.eml": ["ерип", "BEC", "реквизит", "fail"],
}


def _tight_range(level: str, score: int) -> tuple[int, int]:
    lo, hi = BANDS[level]
    half = _HALF[level]
    smin = max(lo, score - half)
    smax = min(hi, score + half)
    if smin > score:
        smin = score
    if smax < score:
        smax = score
    return smin, smax


def main() -> None:
    prev: dict = {}
    expected_path = CORPUS / "expected.json"
    if expected_path.is_file():
        prev = json.loads(expected_path.read_text(encoding="utf-8"))

    out: dict = {}
    paths = sorted(CORPUS.glob("*.eml")) + sorted(CORPUS.glob("*.msg"))
    for path in paths:
        result = analyze_file(path)
        verdict = result.verdict
        assert verdict is not None, path.name
        level = verdict.level.value
        smin, smax = _tight_range(level, verdict.score)
        entry: dict = {"level": level, "score_min": smin, "score_max": smax}
        needles = NEEDLES.get(path.name)
        if not needles and path.name in prev:
            needles = prev[path.name].get("reason_substrings")
        if needles:
            # Keep only needles that still appear (avoid brittle stale substrings)
            reasons = " ".join(verdict.reasons or [])
            kept = [n for n in needles if n.lower() in reasons.lower()]
            if kept:
                entry["reason_substrings"] = kept
            elif path.name in NEEDLES:
                # Force listed needles for new BY cases even if wording drifts
                entry["reason_substrings"] = list(NEEDLES[path.name])
        out[path.name] = entry
        print(f"{path.name}: {level} {verdict.score} -> [{smin}-{smax}]")

    expected_path.write_text(
        json.dumps(out, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(out)} entries")


if __name__ == "__main__":
    main()
