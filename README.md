# TraceForge

TraceForge is an open-source, local-first reverse engineering workbench that
correlates API traffic (HAR), binary metadata, extracted strings and static
analysis findings into a searchable evidence graph with provenance.

- **Local-first**: no outbound network calls, no telemetry, no cloud uploads.
- **Parse-only**: imported binaries are never executed.
- **Provenance**: every finding records source, method, tool version, evidence
  references, confidence (`observed` / `inferred` / `hypothesis`) and
  limitations.
- **Evidence discipline**: candidate links (e.g. binary→endpoint) are always
  hypotheses, unverified and explicitly limited.
- **Safety by default**: secrets are redacted before persistence, parsing is
  bounded and all database access is parameterised.

## Features (MVP)

| Area | Capabilities |
| --- | --- |
| Workspace | `traceforge workspace init/list/info/delete` with per-workspace SQLite DB. |
| Binary analysis | PE/ELF/Mach-O fingerprinting (via `pefile`/`pyelftools`/`lief` when available), string extraction (ASCII/UTF-16LE/BE) with bounds. |
| HAR import | Ingest HAR, redact secrets, build endpoint inventory with path normalisation and schema inference. |
| Correlation | Evidence graph linking artifacts/findings/observations/endpoints/hosts with a versioned relationship vocabulary. |
| Diff | Compare two API snapshots and emit a structured diff. |
| Export | Findings, endpoint inventory and OpenAPI 3.1 (best-effort) exports as JSON/YAML. |
| CLI | `--json` mode, documented exit codes, `traceforge doctor`, `traceforge ui`. |
| Desktop UI | Local React+TypeScript app served by the loopback-only bridge (`traceforge ui`). |

## Quick start

```bash
# Install in development
pip install -e ".[dev,desktop]"

# Create a workspace
traceforge workspace init demo

# Analyze a binary
traceforge analyze binary ./sample.exe --workspace demo

# Import HTTP traffic
traceforge import har ./capture.har --workspace demo

# Inspect findings
traceforge show findings --workspace demo --json

# Explore the graph
traceforge graph show --workspace demo

# Export OpenAPI
traceforge export openapi --workspace demo -o openapi.yaml

# Run the local desktop UI (loopback only)
traceforge ui
```

`$env:TRACEFORGE_WORKSPACE_ROOT` can be used to override the workspace root.

## Safety notes

- The bridge binds to `127.0.0.1` only, requires a per-run token for `/api`
  (except `/health` and `/session`) and restricts CORS.
- Only file *uploads* are accepted by the bridge; arbitrary filesystem paths
  are never read from the client.
- A native Tauri desktop build is **not verified** in this environment (no
  Rust/C toolchain). The web UI served by the local bridge is the supported
  desktop path.
- Timestamps in exports are omitted by default for deterministic output;
  use the documented flags if you need generated timestamps.

## Testing

```bash
pytest -q
```

Tests use synthetic fixtures only; no real binaries, HARs or credentials are
committed.

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [File formats and schemas](docs/formats.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

## License

[Apache-2.0](LICENSE).
