"""JSON exports.

Every export document carries a ``schema_version`` so that consumers can
detect format changes.  Exports are deterministic by default: collections are
sorted and volatile timestamps are only included when explicitly requested.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from traceforge.version import GRAPH_SCHEMA_VERSION, __version__

#: Version of the findings export document format.
FINDINGS_SCHEMA_VERSION = 1
#: Version of the endpoint inventory export document format.
ENDPOINTS_SCHEMA_VERSION = 1


def _timestamp(deterministic: bool) -> str | None:
    if deterministic:
        return None
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def export_findings_document(
    repo,
    *,
    workspace_name: str,
    artifact_id: str | None = None,
    finding_type: str | None = None,
    deterministic: bool = True,
) -> dict[str, Any]:
    """Build the findings export document."""
    findings = repo.list_findings(artifact_id=artifact_id, finding_type=finding_type)  # type: ignore[arg-type]
    artifacts = {row.id: row for row in repo.list_artifacts()}

    items: list[dict[str, Any]] = []
    for row in findings:
        artifact = artifacts.get(row.artifact_id or "")
        items.append(
            {
                "id": row.id,
                "type": row.type,
                "summary": row.summary,
                "confidence": row.confidence,
                "method": row.method,
                "tool": {"name": row.tool_name, "version": row.tool_version},
                "artifact": {
                    "id": row.artifact_id,
                    "display_name": artifact.display_name if artifact else None,
                    "sha256": artifact.sha256 if artifact else None,
                },
                "run_id": row.run_id,
                "key": row.key,
                "data": row.data_json or {},
                "evidence": row.evidence_json or [],
                "limitations": row.limitations_json or [],
                "annotation": row.annotation,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
        )

    document: dict[str, Any] = {
        "schema_version": FINDINGS_SCHEMA_VERSION,
        "kind": "findings",
        "tool": {"name": "traceforge", "version": __version__},
        "workspace": {"id": repo.workspace_id, "name": workspace_name},
        "filters": {
            "artifact_id": artifact_id,
            "finding_type": finding_type,
        },
        "count": len(items),
        "findings": sorted(items, key=lambda item: (item["type"], item["id"])),
        "notes": [
            "Every finding records the method and tool version that produced it.",
            "Confidence values: observed = directly read, inferred = derived by a "
            "documented rule, hypothesis = an unverified candidate link.",
        ],
    }
    generated = _timestamp(deterministic)
    if generated is not None:
        document["generated_at"] = generated
    return document


def export_endpoints_document(
    repo, *, workspace_name: str, deterministic: bool = True
) -> dict[str, Any]:
    """Build the API endpoint inventory export document."""
    endpoints = repo.list_endpoints()
    items: list[dict[str, Any]] = []
    for row in endpoints:
        items.append(
            {
                "id": row.id,
                "method": row.method,
                "origin": row.origin,
                "path": row.path,
                "path_key": row.path_key,
                "host": row.host,
                "scheme": row.scheme,
                "query_params": row.query_params_json or [],
                "status_codes": row.status_codes_json or [],
                "content_types": row.content_types_json or [],
                "request_schema": row.request_schema_json,
                "response_schema": row.response_schema_json,
                "timings": row.timings_json,
                "count": row.count,
                "confidence": row.confidence,
                "limitations": row.limitations_json or [],
                "artifact_ids": row.artifact_ids_json or [],
            }
        )

    document: dict[str, Any] = {
        "schema_version": ENDPOINTS_SCHEMA_VERSION,
        "kind": "endpoints",
        "tool": {"name": "traceforge", "version": __version__},
        "workspace": {"id": repo.workspace_id, "name": workspace_name},
        "count": len(items),
        "endpoints": sorted(items, key=lambda item: (item["method"], item["origin"], item["path_key"])),
        "notes": [
            "Endpoints are derived only from observed traffic.",
            "Path parameters are the result of a documented heuristic; see docs/formats.md.",
        ],
    }
    generated = _timestamp(deterministic)
    if generated is not None:
        document["generated_at"] = generated
    return document


def export_graph_document(
    document, *, deterministic: bool = True
) -> dict[str, Any]:
    """Serialise a graph document."""
    payload = document.as_dict(deterministic=deterministic)
    payload.setdefault("kind", "graph")
    payload["schema_version"] = payload.get("schema_version", GRAPH_SCHEMA_VERSION)
    payload["tool"] = {"name": "traceforge", "version": __version__}
    return payload
