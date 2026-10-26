# Changelog

All notable changes to TraceForge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of TraceForge, a local-first reverse engineering workbench.
- Python core with CLI (`traceforge`) covering workspace lifecycle, binary fingerprinting (PE/ELF/Mach-O), HAR import, endpoint inventory, schema inference, API diff, evidence graph, and exports.
- Provenance model with confidence (`observed`/`inferred`/`hypothesis`), evidence references, method, tool version and limitations.
- Binary→endpoint relationships are always `candidate_endpoint_reference`, hypotheses and unverified.
- Redaction of common secrets (headers, cookies, auth parameters and bodies) before persistence.
- Bounded parsing (file sizes, HAR entries, JSON depth/keys, string scan limits).
- SQLite storage with Alembic migrations, content-addressed IDs, parameterised queries.
- Local HTTP bridge (`traceforge ui`, `traceforge-bridge`) for the desktop UI: loopback-only, per-run token, CORS-restricted, uploads only (no arbitrary paths).
- React + TypeScript + Vite desktop UI (served by the bridge). A native Tauri release is not produced in this repository because a Rust/C toolchain is not available; this is documented honestly.
- Pytest suite (unit/integration/security/regression) with synthetic fixtures.
- Documentation (`README`, `CONTRIBUTING`, `SECURITY`, `CODE_OF_CONDUCT`, `docs/architecture.md`, `docs/threat-model.md`, `docs/formats.md`).
- CI workflows for tests/lint/type-check and a release build.
- `traceforge doctor` and `--json` output on supported commands.

### Security
- Parse-only analysis: imported binaries are never executed.
- Path validation blocks symlinks and traversal attempts.
- Loopback-only network policy; no telemetry, no outbound calls, no cloud uploads.
- Secrets redacted before persistence and export.

## [0.1.0] - 2026-10-24

- First alpha release.
