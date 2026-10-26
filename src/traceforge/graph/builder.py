"""Construction of the evidence graph.

The graph is rebuilt from the repository after every analysis run, so that it
always reflects what is actually stored.  Edge creation follows strict rules:

* Provenance edges (``derived_from``) are always created for a finding and the
  artefact that produced it.
* Containment edges describe literal containment ("this binary contains this
  string").
* A binary is **never** linked to an endpoint merely because it contains a URL
  string.  Such a link is emitted only as an explicitly unverified
  ``candidate_endpoint_reference`` hypothesis, and its limitations state that a
  string match is not a behavioural observation.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

from traceforge.domain.enums import Confidence, FindingType, RelationKind
from traceforge.domain.models import EvidenceRef, Relationship
from traceforge.graph.model import (
    NODE_ARTIFACT,
    NODE_ENDPOINT,
    NODE_FINDING,
    NODE_HOST,
    NODE_OBSERVATION,
    GraphDocument,
    GraphEdge,
    GraphNode,
)
from traceforge.ids import relationship_id
from traceforge.storage.models import (
    ApiEndpointRow,
    ArtifactRow,
    FindingRow,
    ObservationRow,
)
from traceforge.storage.repository import WorkspaceRepository
from traceforge.version import GRAPH_SCHEMA_VERSION, RELATIONSHIP_SCHEMA_VERSION

#: Maximum number of pairwise co-location edges created for one workspace.
MAX_COLOCATION_EDGES = 2000

#: Finding types that are represented by a dedicated containment edge.
_SPECIFIC_EDGE: dict[str, RelationKind] = {
    FindingType.BINARY_STRING.value: RelationKind.CONTAINS_STRING,
    FindingType.BINARY_DOMAIN.value: RelationKind.CONTAINS_DOMAIN,
}


def host_node_id(host: str) -> str:
    """Deterministic identifier for a host node."""
    digest = hashlib.sha256(host.lower().encode("utf-8")).hexdigest()[:16]
    return f"host_{digest}"


def _relation_kind_value(raw: object) -> str:
    """Return the relation kind as a plain string.

    Rows read back from the database carry the kind as text, while freshly
    built :class:`Relationship` objects carry the enum member.
    """
    if isinstance(raw, RelationKind):
        return raw.value
    return str(raw)


def path_key_matches(path_key: str, path: str) -> bool:
    """Return ``True`` when ``path`` matches the normalised ``path_key``.

    ``{placeholder}`` segments in the key match any single path segment.
    """
    pattern = re.escape(path_key)
    pattern = re.sub(r"\\\{[a-zA-Z0-9_]+\\\}", r"[^/]+", pattern)
    try:
        return re.fullmatch(pattern, path) is not None
    except re.error:  # pragma: no cover - defensive
        return False


def build_relationships(repo: WorkspaceRepository) -> list[Relationship]:
    """Build the full set of relationships for a workspace."""
    relationships: list[Relationship] = []
    artifacts = repo.list_artifacts()
    findings = repo.list_findings()
    observations = repo.list_observations()
    endpoints = repo.list_endpoints()

    artifact_by_id = {row.id: row for row in artifacts}

    def _add(
        from_type: str,
        from_id: str,
        to_type: str,
        to_id: str,
        kind: RelationKind,
        summary: str,
        *,
        confidence: Confidence = Confidence.OBSERVED,
        evidence: tuple[EvidenceRef, ...] = (),
        limitations: tuple[str, ...] = (),
        verified: bool = False,
    ) -> None:
        relationships.append(
            Relationship(
                id=relationship_id(repo.workspace_id, from_id, kind.value, to_id),
                workspace_id=repo.workspace_id,
                from_type=from_type,
                from_id=from_id,
                to_type=to_type,
                to_id=to_id,
                kind=kind,
                summary=summary,
                confidence=confidence,
                evidence=evidence,
                limitations=limitations,
                verified=verified,
                schema_version=RELATIONSHIP_SCHEMA_VERSION,
            )
        )

    # --- provenance: finding -> artefact ------------------------------
    for finding in findings:
        if finding.artifact_id is None:
            continue
        artifact = artifact_by_id.get(finding.artifact_id)
        if artifact is None:
            continue
        specific = _SPECIFIC_EDGE.get(finding.type)
        if specific is not None:
            _add(
                NODE_ARTIFACT,
                artifact.id,
                NODE_FINDING,
                finding.id,
                specific,
                f"{artifact.display_name} contains {finding.summary}",
                evidence=(
                    EvidenceRef(
                        kind="finding",
                        ref=f"finding:{finding.id}",
                        detail=finding.method,
                    ),
                ),
            )
        else:
            _add(
                NODE_ARTIFACT,
                artifact.id,
                NODE_FINDING,
                finding.id,
                RelationKind.DERIVED_FROM,
                f"{artifact.display_name} produced {finding.summary}",
                evidence=(EvidenceRef(kind="finding", ref=f"finding:{finding.id}"),),
            )

    # --- provenance: observation -> artefact --------------------------
    for observation in observations:
        _add(
            NODE_ARTIFACT,
            observation.artifact_id,
            NODE_OBSERVATION,
            observation.id,
            RelationKind.DERIVED_FROM,
            f"Observation '{observation.key}' was extracted from the source artefact",
        )

    # --- observed endpoints -------------------------------------------
    for endpoint in endpoints:
        for artifact_id in endpoint.artifact_ids_json or []:
            artifact = artifact_by_id.get(artifact_id)
            if artifact is None:
                continue
            _add(
                NODE_ARTIFACT,
                artifact.id,
                NODE_ENDPOINT,
                endpoint.id,
                RelationKind.OBSERVED_ENDPOINT,
                f"{artifact.display_name} observed {endpoint.method} {endpoint.origin}{endpoint.path_key}",
                evidence=(
                    EvidenceRef(
                        kind="observation",
                        ref=f"endpoint_observation:{endpoint.id}:{artifact_id}",
                        detail="Grouped from observed traffic",
                    ),
                ),
            )
        _add(
            NODE_ENDPOINT,
            endpoint.id,
            NODE_HOST,
            host_node_id(endpoint.host),
            RelationKind.TARGETS_HOST,
            f"{endpoint.method} {endpoint.path_key} targets host {endpoint.host}",
            confidence=Confidence.OBSERVED,
        )

    # --- co-location ---------------------------------------------------
    artifact_ids = [row.id for row in artifacts]
    pair_count = 0
    for index, left_id in enumerate(artifact_ids):
        for right_id in artifact_ids[index + 1 :]:
            if pair_count >= MAX_COLOCATION_EDGES:
                break
            pair_count += 1
            left = artifact_by_id[left_id]
            right = artifact_by_id[right_id]
            _add(
                NODE_ARTIFACT,
                left.id,
                NODE_ARTIFACT,
                right.id,
                RelationKind.CO_LOCATED_IN_WORKSPACE,
                f"{left.display_name} and {right.display_name} were imported into the same workspace",
                confidence=Confidence.OBSERVED,
                limitations=(
                    "Sharing a workspace does not imply that these artefacts are related.",
                ),
            )

    # --- candidate endpoint references (hypotheses) --------------------
    string_findings = [
        f
        for f in findings
        if f.type == FindingType.BINARY_STRING.value and f.artifact_id is not None
    ]
    for endpoint in endpoints:
        for finding in string_findings:
            artifact = artifact_by_id.get(finding.artifact_id or "")
            if artifact is None or artifact.kind != "binary":
                continue
            value = (finding.data_json or {}).get("value")
            if not isinstance(value, str) or not value.startswith(("http://", "https://")):
                continue
            url_path = urlsplit(value).path or "/"
            if not path_key_matches(endpoint.path_key, url_path):
                continue
            _add(
                NODE_ARTIFACT,
                artifact.id,
                NODE_ENDPOINT,
                endpoint.id,
                RelationKind.CANDIDATE_ENDPOINT_REFERENCE,
                (
                    f"{artifact.display_name} contains a URL string that textually matches "
                    f"{endpoint.method} {endpoint.origin}{endpoint.path_key}"
                ),
                confidence=Confidence.HYPOTHESIS,
                evidence=(
                    EvidenceRef(
                        kind="finding",
                        ref=f"finding:{finding.id}",
                        detail="Literal string occurrence",
                        excerpt=value[:200],
                    ),
                ),
                limitations=(
                    "A URL string inside a binary is not evidence that the binary performs "
                    "this request; it may be dead code, a default value or unrelated text.",
                    "This edge is an unverified hypothesis and must be confirmed manually.",
                ),
                verified=False,
            )

    # De-duplicate: identical (source, kind, target) triples collapse.
    unique: dict[str, Relationship] = {}
    for relationship in relationships:
        unique.setdefault(relationship.id, relationship)
    return list(unique.values())


def build_graph_document(
    repo: WorkspaceRepository,
    *,
    workspace_name: str,
    generated_at: datetime | None = None,
) -> GraphDocument:
    """Build a serialisable graph document from the repository contents."""
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    for artifact in repo.list_artifacts():
        nodes.append(
            GraphNode(
                id=artifact.id,
                type=NODE_ARTIFACT,
                label=artifact.display_name,
                confidence=Confidence.OBSERVED,
                attributes={
                    "kind": artifact.kind,
                    "sha256": artifact.sha256,
                    "size_bytes": artifact.size_bytes,
                    "detected_type": artifact.detected_type,
                    "import_time": artifact.import_time.isoformat()
                    if artifact.import_time
                    else None,
                    "tool_version": artifact.tool_version,
                    "metadata": artifact.metadata_json or {},
                },
                artifact_id=artifact.id,
            )
        )

    for finding in repo.list_findings():
        nodes.append(
            GraphNode(
                id=finding.id,
                type=NODE_FINDING,
                label=finding.summary,
                confidence=Confidence(finding.confidence),
                attributes={
                    "type": finding.type,
                    "method": finding.method,
                    "tool_name": finding.tool_name,
                    "tool_version": finding.tool_version,
                    "data": finding.data_json or {},
                    "limitations": finding.limitations_json or [],
                    "annotation": finding.annotation,
                    "created_at": finding.created_at.isoformat() if finding.created_at else None,
                },
                artifact_id=finding.artifact_id,
                finding_type=finding.type,
            )
        )

    for observation in repo.list_observations():
        nodes.append(
            GraphNode(
                id=observation.id,
                type=NODE_OBSERVATION,
                label=observation.key,
                confidence=Confidence.OBSERVED,
                attributes={
                    "kind": observation.kind,
                    "value": observation.value_json or {},
                    "count": observation.count,
                    "source_ref": observation.source_ref,
                },
                artifact_id=observation.artifact_id,
            )
        )

    for endpoint in repo.list_endpoints():
        nodes.append(
            GraphNode(
                id=endpoint.id,
                type=NODE_ENDPOINT,
                label=f"{endpoint.method} {endpoint.origin}{endpoint.path_key}",
                confidence=Confidence(endpoint.confidence),
                attributes={
                    "method": endpoint.method,
                    "origin": endpoint.origin,
                    "path": endpoint.path,
                    "path_key": endpoint.path_key,
                    "host": endpoint.host,
                    "scheme": endpoint.scheme,
                    "query_params": endpoint.query_params_json or [],
                    "status_codes": endpoint.status_codes_json or [],
                    "content_types": endpoint.content_types_json or [],
                    "request_schema": endpoint.request_schema_json,
                    "response_schema": endpoint.response_schema_json,
                    "count": endpoint.count,
                    "limitations": endpoint.limitations_json or [],
                    "artifact_ids": endpoint.artifact_ids_json or [],
                },
                artifact_id=None,
            )
        )
        nodes.append(
            GraphNode(
                id=host_node_id(endpoint.host),
                type=NODE_HOST,
                label=endpoint.host,
                confidence=Confidence.OBSERVED,
                attributes={"host": endpoint.host, "scheme": endpoint.scheme},
            )
        )

    for relationship in repo.list_relationships():
        edges.append(
            GraphEdge(
                id=relationship.id,
                source=relationship.from_id,
                target=relationship.to_id,
                kind=_relation_kind_value(relationship.kind),
                summary=relationship.summary,
                confidence=Confidence(relationship.confidence),
                verified=relationship.verified,
                evidence=list(relationship.evidence_json or []),
                limitations=list(relationship.limitations_json or []),
                schema_version=relationship.schema_version,
            )
        )

    document = GraphDocument(
        workspace_id=repo.workspace_id,
        workspace_name=workspace_name,
        schema_version=GRAPH_SCHEMA_VERSION,
        generated_at=generated_at or datetime.now(UTC),
        nodes=nodes,
        edges=edges,
    )
    document.statistics = {
        "nodes": len(nodes),
        "edges": len(edges),
        "node_types": {
            node_type: sum(1 for node in nodes if node.type == node_type)
            for node_type in sorted({node.type for node in nodes})
        },
        "edge_kinds": {
            kind: sum(1 for edge in edges if edge.kind == kind)
            for kind in sorted({edge.kind for edge in edges})
        },
        "hypotheses": sum(1 for edge in edges if edge.confidence == Confidence.HYPOTHESIS),
    }
    document.notes = [
        "Edges describe relationships between observations, not proven behaviour.",
        "Edges with confidence 'hypothesis' are unverified candidate links.",
    ]
    return document


def endpoint_rows_to_nodes(rows: list[ApiEndpointRow]) -> list[GraphNode]:
    """Helper used by tests: convert endpoint rows to graph nodes."""
    return [
        GraphNode(
            id=row.id,
            type=NODE_ENDPOINT,
            label=f"{row.method} {row.origin}{row.path_key}",
            attributes={"path_key": row.path_key},
        )
        for row in rows
    ]


def finding_rows_to_nodes(rows: list[FindingRow]) -> list[GraphNode]:
    """Helper used by tests: convert finding rows to graph nodes."""
    return [
        GraphNode(
            id=row.id,
            type=NODE_FINDING,
            label=row.summary,
            finding_type=row.type,
            artifact_id=row.artifact_id,
        )
        for row in rows
    ]


def observation_rows_to_nodes(rows: list[ObservationRow]) -> list[GraphNode]:
    """Helper used by tests: convert observation rows to graph nodes."""
    return [
        GraphNode(
            id=row.id,
            type=NODE_OBSERVATION,
            label=row.key,
            attributes={"kind": row.kind},
            artifact_id=row.artifact_id,
        )
        for row in rows
    ]


def artifact_rows_to_nodes(rows: list[ArtifactRow]) -> list[GraphNode]:
    """Helper used by tests: convert artifact rows to graph nodes."""
    return [
        GraphNode(
            id=row.id,
            type=NODE_ARTIFACT,
            label=row.display_name,
            attributes={"kind": row.kind, "sha256": row.sha256},
            artifact_id=row.id,
        )
        for row in rows
    ]
