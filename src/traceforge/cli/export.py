"""Export commands."""

from __future__ import annotations

import json
from pathlib import Path

import typer
import yaml

from traceforge.cli.common import (
    JSON_MODE,
    WORKSPACE_ROOT,
    console,
    emit_json,
    resolve_workspace,
)
from traceforge.errors import TraceForgeError
from traceforge.exporters.json_export import (
    export_endpoints_document,
    export_findings_document,
    export_graph_document,
)
from traceforge.exporters.markdown import render_report
from traceforge.exporters.openapi import build_openapi
from traceforge.graph.builder import build_graph_document
from traceforge.services.analysis_service import export_openapi_document
from traceforge.storage.repository import row_to_export_record

app = typer.Typer(help="Export workspace data.", no_args_is_help=True)

FINDINGS_FORMAT = typer.Option("json", "--format", "-f", help="Output format: json or markdown.")


def _record_export(ws, kind: str, fmt: str, path: str | None, checksum: str | None, params: dict) -> None:
    from traceforge.ids import export_id as make_export_id
    from traceforge.domain.models import ExportRecord

    with ws.session_scope() as session:
        repo = ws.repository(session)
        repo.create_export_record(
            export_id=make_export_id(ws.id, kind, fmt, str(len(repo.list_export_records()))),
            kind=kind,
            fmt=fmt,
            path=path,
            checksum=checksum,
            parameters=params,
        )
        del ExportRecord


@app.command("findings")
def export_findings(
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    output_format: str = FINDINGS_FORMAT,
    artifact: str = typer.Option(None, "--artifact", "-a", help="Only export one artefact's findings."),
    finding_type: str = typer.Option(None, "--type", "-t", help="Only export one finding type."),
    output: Path = typer.Option(None, "--output", "-o", help="Write to a file instead of stdout."),
    json_output: bool = JSON_MODE,
) -> None:
    """Export the findings of a workspace."""
    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    fmt = output_format.lower()
    if fmt not in {"json", "markdown", "md"}:
        typer.echo("Error: --format must be 'json' or 'markdown'", err=True)
        raise typer.Exit(2)

    with ws.session_scope() as session:
        repo = ws.repository(session)
        document = export_findings_document(
            repo,
            workspace_name=ws.name,
            artifact_id=artifact,
            finding_type=finding_type,
        )
        if fmt in {"markdown", "md"}:
            text = render_report(
                workspace_name=ws.name,
                counts=repo.counts(),
                artifacts=repo.list_artifacts(),
                findings=repo.list_findings(),
                endpoints=repo.list_endpoints(),
                relationships=repo.list_relationships(),
            )
        else:
            text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)

    _write(text, output, json_output, fmt)
    _record_export(ws, "findings", fmt, str(output) if output else None, None, {"artifact": artifact})


@app.command("openapi")
def export_openapi(
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    output: Path = typer.Option(
        Path("openapi.yaml"), "--output", "-o", help="Where to write the OpenAPI document."
    ),
    json_output: bool = JSON_MODE,
) -> None:
    """Export an OpenAPI 3.1 document for the observed endpoints."""
    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    document = export_openapi_document(ws)
    text = yaml.safe_dump(document, sort_keys=True, allow_unicode=True, default_flow_style=False)
    _write(text, output, json_output, "yaml")
    _record_export(ws, "openapi", "yaml", str(output), None, {})


@app.command("endpoints")
def export_endpoints(
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    output: Path = typer.Option(None, "--output", "-o", help="Write to a file instead of stdout."),
    json_output: bool = JSON_MODE,
) -> None:
    """Export the endpoint inventory as JSON."""
    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    with ws.session_scope() as session:
        repo = ws.repository(session)
        document = export_endpoints_document(repo, workspace_name=ws.name)

    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)
    _write(text, output, json_output, "json")
    _record_export(ws, "endpoints", "json", str(output) if output else None, None, {})


@app.command("report")
def export_report(
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    output: Path = typer.Option(None, "--output", "-o", help="Write to a file instead of stdout."),
    json_output: bool = JSON_MODE,
) -> None:
    """Export a human readable Markdown report."""
    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    with ws.session_scope() as session:
        repo = ws.repository(session)
        text = render_report(
            workspace_name=ws.name,
            counts=repo.counts(),
            artifacts=repo.list_artifacts(),
            findings=repo.list_findings(),
            endpoints=repo.list_endpoints(),
            relationships=repo.list_relationships(),
        )

    _write(text, output, json_output, "markdown")
    _record_export(ws, "report", "markdown", str(output) if output else None, None, {})


def _write(text: str, output: Path | None, json_output: bool, fmt: str) -> None:
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        if json_output:
            emit_json({"written": str(output), "bytes": len(text.encode("utf-8"))})
        else:
            console().print(f"[green]Wrote[/green] {output} ({len(text.encode('utf-8'))} bytes)")
        return

    if fmt == "json":
        typer.echo(text)
    else:
        typer.echo(text)


__all__ = ["app", "build_openapi", "row_to_export_record"]
