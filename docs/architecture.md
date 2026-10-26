# Architecture

TraceForge follows a strict layering so that every action is auditable and the
evidence graph is the source of truth.

## Layers

```text
CLI (Typer/Rich)        Desktop UI (React+TS) -> Bridge (FastAPI, loopback only)
        \                        /
         v                      v
                Services (workspace, analysis)
                          |
                    Adapters (binary, http/har)
                          |
                      Analysis (schema, diff, paths)
                          |
                        Graph (builder, queries)
                          |
                    Storage (SQLAlchemy + SQLite + Alembic)
                          |
                        Domain models / IDs
```

## Core principles

- **Local-first**: all data lives under the workspace directory. No outbound
  network calls, no telemetry.
- **Parse-only**: adapters never execute imported artifacts.
- **Provenance-first**: `Finding` carries `method`, `tool_name`,
  `tool_version`, `evidence`, `confidence`, `limitations` and a stable ID.
- **Evidence discipline**: relationships store their `kind`, confidence,
  `verified` flag, summary, evidence and limitations. Uncertain correlations
  are marked `hypothesis` and unverified.
- **Deterministic IDs**: content-addressed prefixed IDs (`ws_`, `art_`, `fnd_`,
  `obs_`, `rel_`, `ep_`, `run_`, `exp_`, `ann_`) are derived from SHA-256.
- **Transactional persistence**: each import/analyze runs in a transaction
  with a recorded `AnalysisRun`.
- **Redaction**: sensitive values are stripped before persistence.

## Data model

Key tables (see `src/traceforge/storage/models.py`):
- `workspaces` - metadata and schema version
- `artifacts` - imported binaries/HARs with hashes and limits
- `analysis_runs` - provenance of each operation
- `findings` - typed findings with confidence and evidence
- `observations` - normalized observations (strings, hosts, headers, etc.)
- `endpoints` - inferred API endpoint inventory
- `relationships` - typed edges in the evidence graph
- `annotations` - analyst notes

## Relationship vocabulary (schema v1)

| Relation | Meaning | Typical confidence |
| --- | --- | --- |
| `contains_string` | Artifact contains an extracted string. | observed |
| `contains_domain` | Artifact references a domain/host. | observed |
| `observed_endpoint` | Endpoint was observed in captured traffic. | observed |
| `targets_host` | Endpoint targets a host. | observed |
| `co_located_in_workspace` | Entities share a workspace. | observed |
| `derived_from` | A finding/observation was derived from an artifact/run. | observed/inferred |
| `differs_from` | An endpoint/findingset differs between two snapshots. | inferred |
| `candidate_endpoint_reference` | String/domain in a binary may reference an endpoint. | **hypothesis (unverified)** |

Binary→endpoint links are *always* `candidate_endpoint_reference`, confidence
`hypothesis` and `verified=False`, with explicit limitations.

## Processing flow

### HAR import
1. `validate_input_file` checks size and blocks symlinks.
2. `parse_har` redacts secrets before building the capture model.
3. `import_har` creates the artifact, run, endpoints, findings and relationships.
4. Schema inference runs with depth/key limits and truncation notes.

### Binary analysis
1. Validate and fingerprint (`pefile`/`pyelftools`/`lief` when available).
2. Extract strings (own extractor, ASCII + UTF-16LE/BE) with hard caps.
3. Emit fingerprint/strings/domain findings with evidence refs.
4. Optionally create *hypothesis* candidate links to known endpoints.

## Security boundaries

- **Input validation**: `traceforge.security.paths` and `validators`.
- **Redaction**: `traceforge.security.redaction.Redactor`.
- **Limits**: `traceforge.config.Limits` enforced throughout.
- **Bridge**: loopback only, token auth, CORS allowlist, upload-only.
- **SQL**: SQLAlchemy parameterised statements; no dynamic SQL.

## Extensibility

- Add new adapters under `src/traceforge/adapters/`.
- Add finding types in `domain/enums.py` and handle in exporters/graph.
- New relationship kinds require updating the vocabulary and docs.

## Build notes

- Python `>=3.11`. No Cargo/Rust toolchain is required to run the core or
  the bridge.
- The native Tauri app is **not built or verified** here; the local web UI is
  the supported path.
- Migrations: `alembic revision --autogenerate` is available in development.
