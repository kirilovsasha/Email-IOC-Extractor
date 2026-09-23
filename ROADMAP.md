"""Roadmap — Email IOC Extractor (Reliquary)

Offline SOC triage. No telemetry, no DB. Ship as one EXE + configs beside it.

## Done in 2.19

- Live VBA (autostart / download) separate from bare `vbaProject.bin`
- Composites: image-only×link, macro/XLM×password, HTML attachment×suspicious form action
- Calendar and thread mitigations skipped when Reply-To or thread domain is foreign
- `org_domains.txt`: organisation domains as protected lookalike / display-spoof brands

## Done in 2.18

- ClickFix, image-only HTML, fake auth in body, Excel 4.0/XLM
- Message-ID domain surfaced in the LOW header line; Resent-From mismatch
- Calendar mitigation skipped on ICS URL or ATTACH; password + encrypted Office
- PST folder prefix + attachment bytes when the library exposes them
- GUI: campaign banner, risky batch step, feedback +N
- Archives are signals only: no unpack of ZIP/7z/RAR members (sandbox)

## Done in 2.17.1

- IOC precision: Message-ID / In-Reply-To / References not treated as email/domain IOC
- Username-like labels (`ivan.petrov`) and auth attrs (`header.from`, `smtp.mailfrom`) rejected as domains
- Domain truncation after digit labels fixed (`mx1.mail…`); local-part not duplicated as domain

## Done in 2.17

- Wrap×lure composite; Return-Path mismatch + weak auth; SPF softfail FP control
- ARC fail + reply-chain anomaly scoring
- Campaign divergence as verdict signal (batch)
- Feedback → threshold/cap suggestions beyond ±2 weights (`--feedback-tune`)
- Attachment depth: Excel DDE, OLE Package, OneNote file-data, PDF OpenAction+/URI
- HTML depth: CID phishing, form action IP/TLD, deeper hidden styles
- Homoglyph expand; YARA pack v2; PST MVP (optional `.[pst]` / libratom·pypff / clear skip)
- `cap_display_spoof` to reduce spoof score pinning

## Done in 2.16

- Messenger/QR lure + QR+credential composite; RU BEC markers expansion
- RAR scrape / ISO·disk exe / HTML polyglot / Office remote template
- Compound SPF+lookalike and Reply-To spoof weights; 1-hop Received → MEDIUM
- Bundled offline YARA pack (`yara_rules/default.yar`) + auto-enable when importable
- Feedback → suggested weight overrides (`--feedback-weights`)
- KZ/UA brands + org presets; calibration segments for new channels

## Done in 2.15

- Verdict confidence (`high`/`medium`/`low`) + «Почему» note
- Module split: `verdict_config` / `verdict_scoring` / `verdict_confidence`
- Encrypted archive session password + re-extract (`--archive-password`, GUI)
- Analyst FP/FN feedback → `analyst_feedback.ndjson`
- `.mbox` ingest
- Org profile import wizard (Settings)
- Optional YARA (`pip install .[yara]`)
- BY brands / display-spoof / ЕРИП BEC + `by_gov` preset; coverage gate 75%

## Near-term

- [x] Raise core coverage gate toward 75%
- [x] Property-based unwrap fuzz expansion (SafeLinks / RU hosts)
- [x] GUI smoke tests without full Tk display
- [x] Narrow remaining broad `except Exception` in prefs/pipeline
- [x] Tighten golden corpus score windows + BY brands/spoof/BEC
- [x] Detection quality 2.16 (lures / polyglot / remote template / YARA pack)
- [x] Detection next 2.17 (wrap-lure / ARC / campaign / DDE / PST MVP / caps)
- [x] IOC precision 2.17.1 (Message-ID / usernames / auth headers / truncation)
- [ ] Deeper PST support (full folder tree / attachments) if fleet demands pypff builds

## Later

- [ ] Raise coverage gate toward 80% (attachment_inspector / calibration)
- [ ] Optional offline rule packs beyond YARA (Sigma-lite for mail?)
- [ ] Campaign graph view in GUI
- [ ] Authenticode-by-default release lane
- [ ] Inbox-driven weight pack from analyst_feedback.ndjson aggregates

## Non-goals

- Network lookups / sandbox detonation
- Cloud sync of prefs or feedback
- Replacing mail gateways
