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
LNK/CAB/архивы: `weight_attachment_lnk`, `weight_lnk_dangerous`, `weight_cab_archive`, `weight_archive_nested_email`, `weight_zip_bomb`.
RAR: только флаг `rar_archive` / `archive_unlisted` (без inventory членов).
Display-spoof: `weight_display_spoof` (отдельно от `weight_lookalike`).

Сегменты калибровки (2.14+): `display_spoof`, `office_link`, `script_att`, `cloud_lure`,
`tnef`, `iso`, `archive_password`, `oob_delivery`, `nested_mail`, `ru_rewrite`, …

BY (Беларусь): встроенные бренды `belarusbank.by` / `nalog.gov.by` / `erip.by` / …;
пресет [`org_profile.example/by_gov/`](../org_profile.example/by_gov/);
BEC-маркеры ЕРИП/УНП/р/с; display-spoof «Беларусбанк» / «МНС РБ».

Новые веса: `weight_office_hyperlink`, `weight_script_attachment`, `weight_cloud_lure`,
`weight_disk_image`, `weight_nested_archive`, `weight_archive_double_extension`,
`weight_yara_match` (2.15, optional YARA).

2.16: `weight_messenger_lure`, `weight_qr_lure`, `weight_qr_credential`, `weight_iso_exe`,
`weight_office_remote_template`, `weight_html_polyglot`, `weight_rar_archive`,
`weight_spf_lookalike`, `weight_reply_to_spoof`. Сегменты калибровки: `messenger_lure` /
`qr_lure` / `iso_exe` / `remote_template` / `html_polyglot` / `rar`.
KZ/UA пресеты: [`kz_gov/`](../org_profile.example/kz_gov/), [`ua_gov/`](../org_profile.example/ua_gov/).
Feedback → `python scripts/feedback_weights.py` или `--feedback-weights OUT.json`.

2.17: `weight_wrap_lure` (12), `weight_return_path_mismatch` (10), `weight_arc_fail` (12),
`weight_reply_chain_anomaly` (14), `weight_campaign_divergence` (10),
`weight_office_dde` (18), `weight_ole_package` (16), `weight_pdf_openaction_uri` (14),
`weight_cid_phishing` (12), `weight_form_action_suspicious` (14), `cap_display_spoof` (28).
Сегменты: `wrap_lure` / `arc_fail` / `reply_chain` / `return_path` / `campaign` /
`office_dde` / `ole_package` / `pdf_openaction` / `cid_phishing` / `form_action`.
Feedback также пишет threshold/cap suggestions (`suggest_threshold_overrides`,
`--feedback-tune`). PST: optional `pip install .[pst]` (libratom; pypff тоже подходит).

Вердикт JSON (2.15+): поля `confidence` (`high`|`medium`|`low`) и `confidence_note`.

## Calibration loop

1. Keep golden corpus green: `pytest tests/test_corpus_verdicts.py` + `python scripts/corpus_metrics.py`
   Score windows в `expected.json` узкие (±8 unknown / ±10 suspicious·malicious) —
   обновлять через `python scripts/regen_expected.py` только при намеренном сдвиге весов.
2. On a **local anonymized inbox sample** (offline copy of `.eml`):

   ```bash
   python scripts/corpus_metrics.py --inbox path/to/eml_folder
   ```

   Вывод даёт распределение по **сегментам** (bec / safelinks / calendar / display_spoof / …)
   и подсказки FP/FN — без базы данных. Для РБ смотрите сегмент `display_spoof` и BEC.

3. Adjust one knob at a time; re-run metrics; commit `verdict_extra.json` / org profile.
   Schema: [`docs/verdict_extra.schema.json`](verdict_extra.schema.json). Configs live **next to the EXE only**.
4. Analyst FP/FN → `analyst_feedback.ndjson` → `--feedback-summary` → 1–2 кейса в corpus.

## Schema

JSON reports include top-level `schema_version` (currently `2`). Bump only on breaking shape changes — see `reliquary.core.models.SCHEMA_VERSION` and `docs/schema_report_v2.json`.
`mail_identity` additive fields in 2.9: `in_reply_to`, `references`, `auto_submitted`.