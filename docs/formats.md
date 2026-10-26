# File formats and schemas

## IDs

All entities use content-addressed, prefixed IDs (SHA-256 hex, truncated):

| Prefix | Entity |
| --- | --- |
| `ws_` | Workspace |
| `art_` | Artifact |
| `run_` | Analysis run |
| `fnd_` | Finding |
| `obs_` | Observation |
| `ep_` | Endpoint |
| `rel_` | Relationship |
| `exp_` | Export/run artifact |
| `ann_` | Annotation |

IDs are deterministic for identical inputs where feasible (re-import uses
artifact hashes).

## Confidence

| Value | Meaning |
| --- | --- |
| `observed` | Directly read from the input (no inference). |
| `inferred` | Derived by a documented rule/heuristic. |
| `hypothesis` | Candidate link not verified; must carry limitations. |

## Evidence reference

```json
{
  "kind": "har_entry",
  "ref": "art_xxx:entry:123",
  "locator": "request.url",
  "description": "..."
}
```

## Finding export (`kind: findings`)

Schema version `1`. Deterministic by default (no `generated_at`, sorted).
```json
{
  "schema_version": 1,
  "kind": "findings",
  "tool": {"name": "traceforge", "version": "x.y.z"},
  "workspace": {"id": "ws_...", "name": "..."},
  "filters": {"artifact_id": null, "finding_type": null},
  "count": 10,
  "findings": [
    {
      "id": "fnd_...",
      "type": "binary.fingerprint",
      "summary": "...",
      "confidence": "observed",
      "method": "pefile.signature",
      "tool": {"name": "pefile", "version": "2024.8.26"},
      "artifact": {"id": "art_...", "display_name": "...", "sha256": "..."},
      "run_id": "run_...",
      "key": "...",
      "data": {},
      "evidence": [],
      "limitations": [],
      "annotation": null,
      "created_at": "..."
    }
  ],
  "notes": []
}
```

## Endpoint export (`kind: endpoints`)

Schema version `1`. Path parameters are the result of heuristics (`{param}`)
and must be treated as inferred in context.

## Graph export (`kind: graph`)

Schema version from `traceforge.version.GRAPH_SCHEMA_VERSION`. Nodes and edges
are sorted in deterministic mode. Edges carry `confidence`, `verified`,
`evidence`, `limitations`.

### Relationship kinds

| Kind | Description |
| --- * see list above, add to table if needed * |
| `contains_string` | Artifact contains extracted string |
| `contains_domain` | Artifact contains domain/host |
| `observed_endpoint` | Endpoint observed in traffic |
| `targets_host` | Endpoint targets host
| `co_located_in_workspace` | Co-located entities
| `derived_from` | Derived from artifact/run
| `differs_from` | Comparison edge
| `candidate_endpoint_reference` | **Hypothesis** candidate link between artifact/string and endpoint; always unverified with limitations

## OpenAPI export

TraceForge exports OpenAPI 3.1 in best-effort form based on observed traffic.
Paths use the inferred `path_key`. Missing request/response schemas are noted.
This is not a spec generated from source code — it is derived from captured
traffic only.

## Limits (defaults)

See `traceforge.config.Limits`. All limits are configurable via `Settings` and
enforced at the parser/ingestion/service level. Violations raise
`TraceForgeError` with exit code 4 (`REJECTED`).
