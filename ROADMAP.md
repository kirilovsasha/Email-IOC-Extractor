"""Roadmap — Email IOC Extractor (Reliquary)

Offline SOC triage. No telemetry, no DB. Ship as one EXE + configs beside it.

## Done in 2.15

- Verdict confidence (`high`/`medium`/`low`) + «Почему» note
- Module split: `verdict_config` / `verdict_scoring` / `verdict_confidence`
- Encrypted archive session password + re-extract (`--archive-password`, GUI)
- Analyst FP/FN feedback → `analyst_feedback.ndjson`
- Watch-inbox folder poller
- Weight A/B compare (`--compare-weights`, GUI «A/B»)
- `.mbox` ingest
- Org profile import wizard (Settings)
- Optional YARA (`pip install .[yara]`)

## Near-term

- [ ] Deeper PST support (read-only extract → eml) if fleet demands
- [ ] Raise core coverage gate toward 75–80%
- [ ] Property-based unwrap fuzz expansion (SafeLinks / RU hosts)
- [ ] GUI smoke tests without full Tk display
- [ ] Narrow remaining broad `except Exception` in prefs/pipeline

## Later

- [ ] Optional offline rule packs beyond YARA (Sigma-lite for mail?)
- [ ] Campaign graph view in GUI
- [ ] Authenticode-by-default release lane

## Non-goals

- Network lookups / sandbox detonation
- Cloud sync of prefs or feedback
- Replacing mail gateways
