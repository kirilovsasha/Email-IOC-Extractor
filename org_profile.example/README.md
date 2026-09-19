# Org profile pack

Drop this folder next to the Reliquary exe as `org_profile/`, or point prefs `profile_dir` / CLI at a folder or `.zip`. Files are optional local overrides — no rebuild required.

## Files

| File | Purpose |
|------|---------|
| `allowlist_extra.txt` | Extra allowlisted hosts/domains (one per line). Merged with built-in allowlist. |
| `verdict_extra.json` | Override `VerdictConfig` thresholds, weights, and per-category caps. See [`docs/TUNING.md`](../docs/TUNING.md). |
| `handoff_extra.txt` | Default ITSM handoff template. |
| `handoff_{level}.txt` | Level-specific handoff (`malicious` / `suspicious` / `unknown` / `benign`). |
| `brands.txt` | Brand / lookalike watchlist. |

## Ready-made presets

| Preset | Path | Focus |
|--------|------|--------|
| Microsoft 365 | [`m365/`](m365/) | SafeLinks / Outlook / Graph / CDN allowlist + brands |
| Google Workspace | [`google/`](google/) | Google mail / Drive / CDN allowlist + brands |
| Banking / finance | [`banking/`](banking/) | Stricter thresholds, bank brand watchlist |

Copy a preset to `org_profile/` next to the exe, or: `reliquary mail.eml --profile org_profile.example/m365`

## Resolution order for handoff templates

1. Explicit `handoff_template_path` (CLI / prefs) if set.
2. Matching entry from an in-memory `handoff_by_level` map (profile pack).
3. `handoff_{level}.txt` next to the app or inside the profile folder.
4. `handoff_extra.txt`.
5. Built-in compact default block.

Repo-root examples: `allowlist_extra.example.txt`, `verdict_extra.example.json`, `handoff_extra.example.txt`, `handoff_malicious.example.txt`.

## Zip packs

A `.zip` may contain the files at the archive root or inside a single top-level folder.
