"""Analysis and import commands."""

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
from traceforge.services.analysis_service import analyze_binary, import_har

analyze_app = typer.Typer(help="Analyse binaries.", no_args_is_help=True)
import_app = typer.Typer(help="Import traffic captures.", no_args_is_help=True)


@analyze_app.command("binary")
def analyze_binary_command(
    file: Path = typer.Argument(..., help="Path to the binary to fingerprint."),
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    json_output: bool = JSON_MODE,
) -> None:
    """Fingerprint a binary without executing it."""
    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    try:
        outcome = analyze_binary(ws, file, settings=load_settings())
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc
    except OSError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc

    if json_output:
        emit_json(outcome.as_dict())
        return

    console().print(f"[green]Analysed[/green] {file.name}")
    detail = outcome.detail
    console().print(f"  format:       {detail.get('format')}")
    console().print(f"  architecture: {detail.get('architecture')}")
    console().print(f"  sha256:       {detail.get('sha256')}")
    console().print(f"  size:         {detail.get('size_bytes')} bytes")
    console().print(f"  sections:     {detail.get('sections')}")
    console().print(f"  imports:      {detail.get('imports')}")
    console().print(f"  strings:      {detail.get('strings')}")
    console().print(f"  domains:      {detail.get('domains')}")
    console().print(f"  urls:         {detail.get('urls')}")
    console().print(
        f"  findings:     {outcome.findings} (observations: {outcome.observations}, "
        f"relationships: {outcome.relationships})"
    )
    for diagnostic in outcome.diagnostics:
        console().print(f"  [yellow]{diagnostic.level.value}[/yellow] {diagnostic.message}")


@import_app.command("har")
def import_har_command(
    file: Path = typer.Argument(..., help="Path to the HAR file to import."),
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    json_output: bool = JSON_MODE,
) -> None:
    """Import a HAR capture and build the endpoint inventory."""
    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    try:
        outcome = import_har(ws, file, settings=load_settings())
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc
    except OSError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc

    if json_output:
        emit_json(outcome.as_dict())
        return

    console().print(f"[green]Imported[/green] {file.name}")
    detail = outcome.detail
    console().print(f"  entries:      {detail.get('entries')}")
    console().print(f"  endpoints:    {detail.get('endpoints')}")
    hosts = detail.get("hosts") or []
    if hosts:
        console().print(f"  hosts:        {', '.join(hosts)}")
    console().print(
        f"  findings:     {outcome.findings} (observations: {outcome.observations}, "
        f"relationships: {outcome.relationships})"
    )
    for diagnostic in outcome.diagnostics:
        console().print(f"  [yellow]{diagnostic.level.value}[/yellow] {diagnostic.message}")


@import_app.command("endpoints")
def list_endpoints(
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    json_output: bool = JSON_MODE,
) -> None:
    """Show the observed endpoint inventory."""
    from traceforge.exporters.json_export import export_endpoints_document

    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    with ws.session_scope() as session:
        repo = ws.repository(session)
        document = export_endpoints_document(repo, workspace_name=ws.name)
        rows = repo.list_endpoints()

    if json_output:
        emit_json(document)
        return

    if not rows:
        console().print("No endpoints observed yet.")
        return

    table = Table(title="Observed endpoints")
    table.add_column("Method")
    table.add_column("Path")
    table.add_column("Status")
    table.add_column("Seen", justify="right")
    for row in rows:
        table.add_row(
            row.method,
            row.path_key,
            ", ".join(str(code) for code in (row.status_codes_json or [])) or "-",
            str(row.count),
        )
    console().print(table)
