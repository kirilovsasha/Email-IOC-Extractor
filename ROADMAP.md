"""Roadmap — Email IOC Extractor (Reliquary)

Offline SOC triage. No telemetry, no DB. Ship as one EXE + configs beside it.

## Done in 2.15

- Verdict confidence (`high`/`medium`/`low`) + «Почему» note
- Module split: `verdict_config` / `verdict_scoring` / `verdict_confidence`
- Encrypted archive session password + re-extract (`--archive-password`, GUI)
- Analyst FP/FN feedback → `analyst_feedback.ndjson`
- `.mbox` ingest
- Org profile import wizard (Settings)
- Optional YARA (`pip install .[yara]`)

## Near-term

- [x] Raise core coverage gate toward 75%
- [x] Property-based unwrap fuzz expansion (SafeLinks / RU hosts)
- [x] GUI smoke tests without full Tk display
- [x] Narrow remaining broad `except Exception` in prefs/pipeline
- [x] Tighten golden corpus score windows + BY brands/spoof/BEC
- [ ] Deeper PST support (read-only extract → eml) if fleet demands

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
