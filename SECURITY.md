# Security policy

## Product posture

Email IOC Extractor is designed to run **offline**. The Python process patches
`socket` / DNS helpers via `reliquary.core.offline.enforce_offline`. That guarantee
is **process-local**:

- Subprocesses (including `post_export_hook`) are outside the monkeypatch.
- Native DLLs can still open sockets without going through Python's `socket` module.

## Reporting

Report suspected vulnerabilities to your internal SOC / product owners. Do not file
public issues with exploit details for unpatched local RCE / path-traversal bugs.

## Hardening notes (operators)

| Surface | Guidance |
|---------|----------|
| Org profile `.zip` | Only load packs from trusted SOC admins. Zip members are validated against path traversal. |
| `ui_prefs.json` | Treat as admin-controlled next to the EXE. `post_export_hook` is restricted: blocked downloader/shell tokens (curl, powershell, bash, node, …) and shell metacharacters; scripts should live under the app directory unless `post_export_hook_allow_external` is set. |
| Disable hooks | Set prefs `disable_post_export_hook: true` or env `RELIQUARY_DISABLE_EXPORT_HOOK=1`. |
| Releases | Verify `EmailIOCExtractor.exe.sha256` / Full SHA256 before deploy. Prefer Authenticode when available (`docs/SIGNING.md`). |

## Known intentional capabilities

- Local file read of `.eml` / `.msg` and nested archives for triage.
- Optional local post-export hook (`shell=False`, timeout, argv only).
