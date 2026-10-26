"""Graph queries.

These operate on a :class:`~traceforge.graph.model.GraphDocument`, so they can
be used both by the CLI and by the desktop bridge without touching the
database.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from traceforge.domain.enums import Confidence
from traceforge.graph.model import GraphDocument, GraphEdge, GraphNode


@dataclass(slots=True)
class Neighbour:
    """A node reachable from another node, with the connecting edges."""

    node: GraphNode
    edges: tuple[GraphEdge, ...]
    direction: str  # "out" or "in"


def index_nodes(document: GraphDocument) -> dict[str, GraphNode]:
    return {node.id: node for node in document.nodes}


def index_edges(document: GraphDocument) -> list[GraphEdge]:
    return list(document.edges)


def search_nodes(
    document: GraphDocument,
    query: str,
    *,
    node_types: tuple[str, ...] | None = None,
    limit: int = 100,
) -> list[GraphNode]:
    """Case-insensitive substring search over node labels and attributes."""
    if not query:
        return []
    needle = query.lower()
    results: list[GraphNode] = []
    for node in document.nodes:
        if node_types and node.type not in node_types:
            continue
        haystack = node.label.lower()
        if needle in haystack:
            results.append(node)
            continue
        for value in node.attributes.values():
            if isinstance(value, str) and needle in value.lower():
                results.append(node)
                break
            if isinstance(value, (list, dict)) and needle in str(value).lower():
                results.append(node)
                break
        if len(results) >= limit:
            break
    return results[:limit]


def neighbours(document: GraphDocument, node_id: str) -> list[Neighbour]:
    """Return the nodes directly connected to ``node_id``."""
    nodes = index_nodes(document)
    grouped: dict[str, list[GraphEdge]] = {}
    direction: dict[str, str] = {}

    for edge in document.edges:
        if edge.source == node_id:
            grouped.setdefault(edge.target, []).append(edge)
            direction.setdefault(edge.target, "out")
        if edge.target == node_id:
            grouped.setdefault(edge.source, []).append(edge)
            direction.setdefault(edge.source, "in")

    result: list[Neighbour] = []
    for other_id, edges in grouped.items():
        node = nodes.get(other_id)
        if node is None:
            continue
        result.append(
            Neighbour(node=node, edges=tuple(edges), direction=direction.get(other_id, "out"))
        )
    result.sort(key=lambda n: (n.direction, n.node.type, n.node.id))
    return result


def find_path(
    document: GraphDocument, source_id: str, target_id: str, *, max_depth: int = 6
) -> list[GraphEdge] | None:
    """Return the shortest edge path between two nodes, if one exists."""
    if source_id == target_id:
        return []
    nodes = index_nodes(document)
    if source_id not in nodes or target_id not in nodes:
        return None

    adjacency: dict[str, list[tuple[str, GraphEdge]]] = {}
    for edge in document.edges:
        adjacency.setdefault(edge.source, []).append((edge.target, edge))
        adjacency.setdefault(edge.target, []).append((edge.source, edge))

    queue: deque[tuple[str, list[GraphEdge]]] = deque([(source_id, [])])
    visited = {source_id}

    while queue:
        current, path = queue.popleft()
        if len(path) >= max_depth:
            continue
        for neighbour, edge in adjacency.get(current, []):
            if neighbour in visited:
                continue
            new_path = [*path, edge]
            if neighbour == target_id:
                return new_path
            visited.add(neighbour)
            queue.append((neighbour, new_path))
    return None


def filter_edges(
    document: GraphDocument,
    *,
    confidence: Confidence | None = None,
    kinds: tuple[str, ...] | None = None,
) -> list[GraphEdge]:
    """Return the edges matching the given filters."""
    result = []
    for edge in document.edges:
        if confidence is not None and edge.confidence != confidence:
            continue
        if kinds is not None and edge.kind not in kinds:
            continue
        result.append(edge)
    return result
