"""Workspace management commands."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.table import Table

from traceforge.cli.common import (
    JSON_MODE,
    WORKSPACE_ROOT,
    console,
    emit_json,
    load_settings,
    resolve_workspace,
)
from traceforge.errors import TraceForgeError
from traceforge.services.workspace import (
    create_workspace,
    delete_workspace,
    list_workspaces,
    workspace_stats,
)

app = typer.Typer(help="Create, inspect and delete workspaces.", no_args_is_help=True)


@app.command("init")
def init_workspace(
    name: str = typer.Argument(..., help="Name of the workspace to create."),
    root: Path = WORKSPACE_ROOT,
    description: str = typer.Option(None, "--description", help="Optional description."),
    json_output: bool = JSON_MODE,
) -> None:
    """Create a new workspace."""
    try:
        workspace = create_workspace(name, root=root, description=description)
    except FileExistsError as exc:
        typer.echo(f"Error: a workspace already exists at {exc}", err=True)
        raise typer.Exit(4) from exc
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    if json_output:
        emit_json(
            {
                "workspace": {
                    "id": workspace.id,
                    "name": workspace.name,
                    "root": str(workspace.root),
                    "database": str(workspace.db_path),
                }
            }
        )
        return

    console().print(f"[green]Created workspace[/green] '{workspace.name}'")
    console().print(f"  id:   {workspace.id}")
    console().print(f"  path: {workspace.root}")


@app.command("list")
def list_all(
    root: Path = WORKSPACE_ROOT,
    json_output: bool = JSON_MODE,
) -> None:
    """List every workspace that can be found."""
    workspaces = list_workspaces(root)
    if json_output:
        emit_json(
            {
                "workspaces": [
                    {
                        "id": w.id,
                        "name": w.name,
                        "root": str(w.root),
                        "counts": workspace_stats(w),
                    }
                    for w in workspaces
                ]
            }
        )
        _close_all(workspaces)
        return

    if not workspaces:
        console().print("No workspaces found.")
        return

    table = Table(title="Workspaces")
    table.add_column("Name")
    table.add_column("Artifacts", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Endpoints", justify="right")
    table.add_column("Path")
    for workspace in workspaces:
        counts = workspace_stats(workspace)
        table.add_row(
            workspace.name,
            str(counts.get("artifacts", 0)),
            str(counts.get("findings", 0)),
            str(counts.get("endpoints", 0)),
            str(workspace.root),
        )
    console().print(table)
    _close_all(workspaces)


def _close_all(workspaces: list) -> None:
    """Release the database handles of workspaces that were only inspected."""
    for workspace in workspaces:
        workspace.close()


@app.command("info")
def info(
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    json_output: bool = JSON_MODE,
) -> None:
    """Show details about a workspace."""
    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    counts = workspace_stats(ws)
    if json_output:
        emit_json(
            {
                "workspace": {
                    "id": ws.id,
                    "name": ws.name,
                    "root": str(ws.root),
                    "database": str(ws.db_path),
                    "counts": counts,
                }
            }
        )
        return

    console().print(f"[bold]{ws.name}[/bold] ({ws.id})")
    console().print(f"  path: {ws.root}")
    for key in sorted(counts):
        console().print(f"  {key}: {counts[key]}")


@app.command("delete")
def delete(
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    yes: bool = typer.Option(False, "--yes", help="Do not ask for confirmation."),
    json_output: bool = JSON_MODE,
) -> None:
    """Delete a workspace and everything in it."""
    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    if not yes:
        confirmed = typer.confirm(f"Delete workspace '{ws.name}' at {ws.root}?")
        if not confirmed:
            raise typer.Exit(0)

    delete_workspace(ws)
    if json_output:
        emit_json({"deleted": ws.id, "path": str(ws.root)})
    else:
        console().print(f"[green]Deleted workspace[/green] {ws.name}")
