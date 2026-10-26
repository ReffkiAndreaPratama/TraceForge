"""Evidence graph commands."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.table import Table

from traceforge.cli.common import (
    JSON_MODE,
    WORKSPACE_ROOT,
    console,
    emit_json,
    resolve_workspace,
)
from traceforge.errors import TraceForgeError
from traceforge.exporters.json_export import export_graph_document
from traceforge.graph.builder import build_graph_document
from traceforge.graph.queries import find_path, neighbours, search_nodes

app = typer.Typer(
    help="Query and export the evidence graph.",
    invoke_without_command=True,
)


@app.callback(invoke_without_command=True)
def graph_callback(
    ctx: typer.Context,
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    output_format: str = typer.Option("json", "--format", "-f", help="json or table."),
    output: Path = typer.Option(None, "--output", "-o", help="Write to a file instead of stdout."),
    json_output: bool = JSON_MODE,
) -> None:
    """Show the evidence graph (default when no sub-command is given)."""
    if ctx.invoked_subcommand is not None:
        return
    if not workspace:
        typer.echo("Error: --workspace is required", err=True)
        raise typer.Exit(2)
    show(workspace=workspace, root=root, output_format=output_format, output=output, json_output=json_output)


@app.command("show")
def show(
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    output_format: str = typer.Option("json", "--format", "-f", help="json or table."),
    output: Path = typer.Option(None, "--output", "-o", help="Write to a file instead of stdout."),
    json_output: bool = JSON_MODE,
) -> None:
    """Show the evidence graph of a workspace."""
    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    with ws.session_scope() as session:
        repo = ws.repository(session)
        document = build_graph_document(repo, workspace_name=ws.name)
        payload = export_graph_document(document)

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        console().print(f"[green]Wrote[/green] {output}")
        return

    if output_format.lower() == "table" and not json_output:
        table = Table(title=f"Evidence graph - {ws.name}")
        table.add_column("Type")
        table.add_column("Label")
        table.add_column("Confidence")
        for node in sorted(document.nodes, key=lambda n: (n.type, n.id))[:200]:
            table.add_row(node.type, node.label[:70], node.confidence.value)
        console().print(table)
        console().print(
            f"{len(document.nodes)} nodes, {len(document.edges)} edges, "
            f"{document.statistics.get('hypotheses', 0)} unverified hypothesis link(s)."
        )
        return

    emit_json(payload)


@app.command("neighbors")
def neighbors(
    node_id: str = typer.Argument(..., help="Identifier of the node to inspect."),
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    json_output: bool = JSON_MODE,
) -> None:
    """Show the nodes directly connected to a node."""
    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    with ws.session_scope() as session:
        repo = ws.repository(session)
        document = build_graph_document(repo, workspace_name=ws.name)
        found = neighbours(document, node_id)

    if json_output:
        emit_json(
            {
                "node": node_id,
                "neighbours": [
                    {
                        "id": n.node.id,
                        "type": n.node.type,
                        "label": n.node.label,
                        "direction": n.direction,
                        "edges": [
                            {
                                "kind": e.kind,
                                "confidence": e.confidence.value,
                                "summary": e.summary,
                                "verified": e.verified,
                                "limitations": e.limitations,
                            }
                            for e in n.edges
                        ],
                    }
                    for n in found
                ],
            }
        )
        return

    if not found:
        console().print("No neighbours found.")
        return

    table = Table(title=f"Neighbours of {node_id}")
    table.add_column("Direction")
    table.add_column("Type")
    table.add_column("Label")
    table.add_column("Relation")
    table.add_column("Confidence")
    for neighbour in found:
        for edge in neighbour.edges:
            table.add_row(
                neighbour.direction,
                neighbour.node.type,
                neighbour.node.label[:50],
                edge.kind,
                edge.confidence.value,
            )
    console().print(table)


@app.command("path")
def path(
    source: str = typer.Argument(..., help="Identifier of the source node."),
    target: str = typer.Argument(..., help="Identifier of the target node."),
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    json_output: bool = JSON_MODE,
) -> None:
    """Find the shortest path between two nodes."""
    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    with ws.session_scope() as session:
        repo = ws.repository(session)
        document = build_graph_document(repo, workspace_name=ws.name)
        edges = find_path(document, source, target)

    if edges is None:
        payload = {"source": source, "target": target, "path": None}
        if json_output:
            emit_json(payload)
        else:
            console().print("No path found.")
        raise typer.Exit(0)

    if json_output:
        emit_json(
            {
                "source": source,
                "target": target,
                "path": [
                    {
                        "kind": edge.kind,
                        "source": edge.source,
                        "target": edge.target,
                        "confidence": edge.confidence.value,
                        "summary": edge.summary,
                    }
                    for edge in edges
                ],
            }
        )
        return

    for index, edge in enumerate(edges, start=1):
        console().print(
            f"{index}. {edge.source} --[{edge.kind}]--> {edge.target}  ({edge.confidence.value})"
        )


@app.command("search")
def search(
    query: str = typer.Argument(..., help="Text to search for."),
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    json_output: bool = JSON_MODE,
) -> None:
    """Search the graph for nodes matching a string."""
    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    with ws.session_scope() as session:
        repo = ws.repository(session)
        document = build_graph_document(repo, workspace_name=ws.name)
        found = search_nodes(document, query)

    if json_output:
        emit_json(
            {
                "query": query,
                "count": len(found),
                "nodes": [
                    {
                        "id": n.id,
                        "type": n.type,
                        "label": n.label,
                        "confidence": n.confidence.value,
                    }
                    for n in found
                ],
            }
        )
        return

    if not found:
        console().print("No matches.")
        return

    table = Table(title=f"Search results for '{query}'")
    table.add_column("Type")
    table.add_column("Id")
    table.add_column("Label")
    for node in found:
        table.add_row(node.type, node.id, node.label[:70])
    console().print(table)
