# Org profile pack

Drop this folder next to the Reliquary exe as `org_profile/`, or point prefs `profile_dir` / CLI at a folder or `.zip`. Files are optional local overrides — no rebuild required.

## Files

| File | Purpose |
|------|---------|
| `allowlist_extra.txt` | Extra allowlisted hosts/domains (one per line). Merged with built-in allowlist. |
| `verdict_extra.json` | Override `VerdictConfig` thresholds, weights, and per-category caps. See `verdict_extra.example.json` at repo root. |
| `handoff_extra.txt` | Default ITSM handoff template (used when no level-specific file matches). Placeholders: `{product}` `{version}` `{verdict}` `{score}` `{summary}` `{reasons}` `{breakdown}` `{file}` `{from}` `{subject}` `{msg_id}` `{auth}` `{iocs}` `{batch}`. |
| `handoff_malicious.txt` | Handoff template when verdict is **malicious**. |
| `handoff_suspicious.txt` | Handoff template when verdict is **suspicious**. |
| `handoff_unknown.txt` | Handoff template when verdict is **unknown**. |
| `handoff_benign.txt` | Handoff template when verdict is **benign**. |
| `brands.txt` | Brand / lookalike watchlist (one brand domain or name per line). |

## Resolution order for handoff templates

1. Explicit `handoff_template_path` (CLI / prefs) if set.
2. Matching entry from an in-memory `handoff_by_level` map (profile pack).
3. `handoff_{level}.txt` next to the app or inside the profile folder.
4. `handoff_extra.txt`.
5. Built-in compact default block.

Repo-root examples: `allowlist_extra.example.txt`, `verdict_extra.example.json`, `handoff_extra.example.txt`, `handoff_malicious.example.txt`.

## Zip packs

A `.zip` may contain the files at the archive root or inside a single top-level folder. Reliquary extracts to a temp dir and picks the same filenames.
