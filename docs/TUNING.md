# Tuning guide — `verdict_extra.json`

Copy `verdict_extra.example.json` to `verdict_extra.json` next to the exe, or put it in an org profile. Only listed keys override built-ins.

## When to change what

| Symptom | Touch |
|---------|--------|
| Too many **benign → suspicious** (FP) | Raise `threshold_suspicious` (e.g. 35), add allowlist, raise `weight_dmarc_pass_aligned` magnitude (more negative), or raise `cap_mitigation` |
| Missed phishing (**FN**, stays unknown) | Lower `threshold_suspicious` / `threshold_malicious`, raise `weight_href_mismatch`, `weight_lookalike`, `weight_credential_harvest` |
| SafeLinks noise inflates score | Lower `weight_url_rewrite` (M365 preset uses 3) |
| Brand spoof under-scored | Raise `weight_display_spoof` (display-name) / `weight_lookalike` / `weight_idn`; extend `brands.txt` |
| Auth fails dominate everything | Caps: `cap_headers` (default 45) — already limits stacking |
| Mitigations hide real attacks | Mitigations auto-skip on HIGH headers / dangerous attachments / bad content signals; lower `cap_mitigation` if needed |
| RAR without UnRAR under-scored | Ship `UnRAR.exe` beside Full EXE; raise `weight_unrar_missing` |
| CAB / LNK / PDF URI soft | Raise `weight_cab_archive`, `weight_lnk_dangerous`, `weight_pdf_uri_action` |

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
| `weight_auto_reply` | −10 | Auto-Submitted / OOO subject |
| `weight_calendar_invite` | −8 | ICS / meeting / приглашение |
| `weight_corp_signature` | −5 | Корп. подпись / disclaimer |
| `weight_thread_reply` | −4 | Re:/Отв: + In-Reply-To / References |
| `weight_mailing_list` | −8 | List-Unsubscribe / List-Id / Precedence:bulk |
| `cap_mitigation` | 30 | Max absolute reduction |

HTML/PDF вложения: `weight_html_smuggling`, `weight_pdf_javascript`, `weight_html_attachment`, `weight_pdf_uri_action`.
LNK/CAB/RAR: `weight_attachment_lnk`, `weight_lnk_dangerous`, `weight_cab_archive`, `weight_unrar_missing`, `weight_archive_nested_email`, `weight_zip_bomb`.
Display-spoof: `weight_display_spoof` (отдельно от `weight_lookalike`).

Сегменты калибровки (2.14+): `display_spoof`, `office_link`, `script_att`, `cloud_lure`,
`tnef`, `iso`, `archive_password`, `oob_delivery`, `nested_mail`, `ru_rewrite`, …

Новые веса: `weight_office_hyperlink`, `weight_script_attachment`, `weight_cloud_lure`,
`weight_disk_image`, `weight_nested_archive`, `weight_archive_double_extension`.

## Calibration loop

1. Keep golden corpus green: `pytest tests/test_corpus_verdicts.py` + `python scripts/corpus_metrics.py`
2. On a **local anonymized inbox sample** (offline copy of `.eml`):

   ```bash
   python scripts/corpus_metrics.py --inbox path/to/eml_folder
   ```

   Вывод даёт распределение по **сегментам** (bec / safelinks / calendar / …) и подсказки FP/FN — без базы данных.

3. Adjust one knob at a time; re-run metrics; commit `verdict_extra.json` / org profile.
   Schema: [`docs/verdict_extra.schema.json`](verdict_extra.schema.json). Configs live **next to the EXE only**.

## Schema

JSON reports include top-level `schema_version` (currently `2`). Bump only on breaking shape changes — see `reliquary.core.models.SCHEMA_VERSION` and `docs/schema_report_v2.json`.
`mail_identity` additive fields in 2.9: `in_reply_to`, `references`, `auto_submitted`.