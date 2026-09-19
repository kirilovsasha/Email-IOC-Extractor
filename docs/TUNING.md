# Tuning guide — `verdict_extra.json`

Copy `verdict_extra.example.json` to `verdict_extra.json` next to the exe, or put it in an org profile. Only listed keys override built-ins.

## When to change what

| Symptom | Touch |
|---------|--------|
| Too many **benign → suspicious** (FP) | Raise `threshold_suspicious` (e.g. 35), add allowlist, raise `weight_dmarc_pass_aligned` magnitude (more negative), or raise `cap_mitigation` |
| Missed phishing (**FN**, stays unknown) | Lower `threshold_suspicious` / `threshold_malicious`, raise `weight_href_mismatch`, `weight_lookalike`, `weight_credential_harvest` |
| SafeLinks noise inflates score | Lower `weight_url_rewrite` (M365 preset uses 3) |
| Brand spoof under-scored | Raise `weight_lookalike` / `weight_idn`; extend `brands.txt` |
| Auth fails dominate everything | Caps: `cap_headers` (default 45) — already limits stacking |
| Mitigations hide real attacks | Mitigations auto-skip on HIGH headers / dangerous attachments / bad content signals; lower `cap_mitigation` if needed |

## Score bands (defaults)

| Level | Score |
|-------|-------|
| benign | 0–9 |
| unknown | 10–29 |
| suspicious | 30–59 |
| malicious | ≥ 60 |

## Mitigations (negative weights)

| Key | Default | Meaning |
|-----|---------|---------|
| `weight_dmarc_pass_aligned` | −12 | DMARC+DKIM pass, no misalignment |
| `weight_auth_full_pass` | −6 | SPF+DKIM+DMARC (fallback) |
| `weight_internal_relay` | −8 | Received hop looks like internal/trusted MX |
| `cap_mitigation` | 25 | Max absolute reduction |

## Calibration loop

1. Keep golden corpus green: `pytest tests/test_corpus_verdicts.py` + `python scripts/corpus_metrics.py`
2. On a **local anonymized inbox sample** (offline copy of `.eml`):

   ```bash
   python scripts/corpus_metrics.py --inbox path/to/eml_folder
   ```

3. Adjust one knob at a time; re-run metrics; commit `verdict_extra.json` / org profile with the change reason in handoff notes.

## Schema

JSON reports include top-level `schema_version` (currently `1`). Bump only on breaking shape changes — see `reliquary.core.models.SCHEMA_VERSION`.
