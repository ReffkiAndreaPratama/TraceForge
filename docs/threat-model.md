# Threat model

TraceForge is designed for local, offline analysis.  This document lists the
threats considered and the mitigations implemented.

## Assets

- Workspace SQLite databases and exported reports
- Imported files (binaries, HAR captures)
- Analyst annotations
- Findings and evidence graph

## Trust boundaries

1. **Untrusted input**: any file imported by the user is treated as hostile.
2. **Local machine**: the workspace root and temp files are trusted only as far
   as the OS permissions allow.
3. **Bridge boundary**: the browser/front-end talks to a loopback HTTP bridge.
4. **Process boundary**: TraceForge runs as the user; no privilege escalation.

## Threats and mitigations

| Threat | Impact | Mitigation | Status |
| --- | --- | --- | --- |
| Execution of imported binary | Critical | Parse-only adapters; no `subprocess`/`os.system` on imports; tests and code review guard. | Implemented |
| Path traversal / symlink escape | High | `validate_input_file` blocks symlinks, normalises paths, enforces workspace constraints; bridge accepts uploads only. | Implemented |
| Secret leakage in storage/export | High | `Redactor` applied in HAR adapter and before persistence; fake secrets in fixtures; tests cover redaction. | Implemented |
| ZIP/slip or archive abuse | High | No archive extraction implemented in MVP; if added must re-validate entries. | N/A (not implemented) |
| Excessive memory/CPU (DoS) | High | `Limits`: max file/HAR entries/JSON depth/keys/strings/scan bytes/findings/relationships; truncation notes. | Implemented |
| SQL injection | High | SQLAlchemy ORM + parameterised queries; repository uses bound parameters. | Implemented |
| Unsafe deserialisation | High | No `pickle`, no `yaml.load` (use `yaml.safe_load`), no `eval`/`exec` on untrusted data. | Implemented |
| Cross-site request to localhost | Medium | Bridge binds `127.0.0.1`, requires `X-TraceForge-Token` for `/api` (except health/session), CORS restricted to configured origins; preflight blocks simple cross-site writes without token. | Implemented |
| Other local user reading token | Low | Token file written to `~/.traceforge/` with best-effort `0600`; same-user local processes already have file access. Documented. | Accepted/Documented |
| Logging secrets | High | Avoid logging raw headers/bodies; error messages are generic or redacted. | Implemented |
| False certainty (hypothesis presented as fact) | High | Confidence model + `verified` flag; binary→endpoint always hypothesis/unverified; UI labels state hypotheses explicitly; docs warn against over-interpretation. | Implemented |
| Supply chain | Medium | Minimal dependencies; pinned where sensitive (`pefile`), extras for optional features; no auto-update. | Implemented |

## Out of scope

- Running malware in sandboxes/emulators
- Network interception/proxying
- Cloud synchronisation
- Automatic exploitation or payload generation

## Operational guidance

- Keep workspace directories on a local filesystem you control.
- Only run `traceforge ui` on trusted machines.
- Review redaction patterns if you import custom traffic types.
- Exported reports may still contain hostnames/paths from captures — treat them
  as sensitive.
- If a Rust/C toolchain becomes available, a native build is possible, but it
  is **not verified** by this repository's test suite or CI.
