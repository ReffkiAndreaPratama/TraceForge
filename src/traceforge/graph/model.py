"""Evidence graph document model.

The graph is a directed, typed graph.  Nodes are artefacts and the things
derived from them; edges carry the *reason* a connection exists.

The relationship vocabulary is versioned.  See ``docs/formats.md`` for the
normative description.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from traceforge.domain.enums import Confidence
from traceforge.version import GRAPH_SCHEMA_VERSION

#: Node type vocabulary.
NODE_ARTIFACT = "artifact"
NODE_FINDING = "finding"
NODE_ENDPOINT = "endpoint"
NODE_OBSERVATION = "observation"
NODE_HOST = "host"

#: The set of node types this version emits.
NODE_TYPES: tuple[str, ...] = (
    NODE_ARTIFACT,
    NODE_FINDING,
    NODE_ENDPOINT,
    NODE_OBSERVATION,
    NODE_HOST,
)


@dataclass(slots=True)
class GraphNode:
    """A node in the evidence graph."""

    id: str
    type: str
    label: str
    confidence: Confidence = Confidence.OBSERVED
    attributes: dict[str, Any] = field(default_factory=dict)
    artifact_id: str | None = None
    finding_type: str | None = None


@dataclass(slots=True)
class GraphEdge:
    """A directed, evidence-backed edge."""

    id: str
    source: str
    target: str
    kind: str
    summary: str
    confidence: Confidence = Confidence.OBSERVED
    verified: bool = False
    evidence: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    schema_version: int = 1


@dataclass(slots=True)
class GraphDocument:
    """A serialisable view of a workspace's evidence graph."""

    workspace_id: str
    workspace_name: str
    schema_version: int = GRAPH_SCHEMA_VERSION
    generated_at: datetime | None = None
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def as_dict(self, *, deterministic: bool = False) -> dict[str, Any]:
        """Return the JSON-serialisable form of the document.

        With ``deterministic=True`` volatile fields (timestamps) are omitted
        and every collection is sorted, so two runs over identical inputs
        produce byte-identical output.
        """
        document: dict[str, Any] = {
            "schema_version": self.schema_version,
            "workspace": {"id": self.workspace_id, "name": self.workspace_name},
            "nodes": [
                {
                    "id": node.id,
                    "type": node.type,
                    "label": node.label,
                    "confidence": node.confidence.value,
                    "artifact_id": node.artifact_id,
                    "finding_type": node.finding_type,
                    "attributes": node.attributes,
                }
                for node in sorted(self.nodes, key=lambda n: (n.type, n.id))
            ],
            "edges": [
                {
                    "id": edge.id,
                    "source": edge.source,
                    "target": edge.target,
                    "kind": edge.kind,
                    "summary": edge.summary,
                    "confidence": edge.confidence.value,
                    "verified": edge.verified,
                    "evidence": edge.evidence,
                    "limitations": edge.limitations,
                    "schema_version": edge.schema_version,
                }
                for edge in sorted(self.edges, key=lambda e: (e.kind, e.id))
            ],
            "statistics": self.statistics,
            "notes": sorted(self.notes),
        }
        if not deterministic:
            document["generated_at"] = (
                self.generated_at.isoformat().replace("+00:00", "Z")
                if self.generated_at
                else None
            )
        return document
