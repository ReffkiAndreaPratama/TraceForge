"""TraceForge command line interface.

The CLI is the automation surface of the project: every operation that the
desktop UI can perform is also available here with a stable exit code and an
optional JSON output mode.

Exit codes
----------

=====  ==========================================================
Code   Meaning
=====  ==========================================================
0      Success
1      Unexpected internal error
2      Usage or validation error
3      The requested workspace, artefact or finding was not found
4      The input was rejected by a safety policy
5      The analysis could not produce a usable result
=====  ==========================================================
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import typer

from traceforge.cli import analysis, api, doctor, export, graph, ui, workspaces
from traceforge.cli.common import JSON_MODE, WORKSPACE_ROOT
from traceforge.errors import ExitCode, TraceForgeError
from traceforge.version import __version__

app = typer.Typer(
    name="traceforge",
    help=(
        "TraceForge - a local-first reverse engineering workbench. Correlates API "
        "traffic, binary metadata and static analysis findings into an evidence graph."
    ),
    no_args_is_help=True,
    add_completion=True,
    invoke_without_command=True,
)

app.add_typer(workspaces.app, name="workspace", help="Manage workspaces.")
app.add_typer(analysis.analyze_app, name="analyze", help="Analyse binaries.")
app.add_typer(analysis.import_app, name="import", help="Import traffic captures.")
app.add_typer(api.app, name="api", help="Compare observed API behaviour.")
app.add_typer(export.app, name="export", help="Export workspace data.")
app.add_typer(graph.app, name="graph", help="Query the evidence graph.")
app.add_typer(doctor.app, name="doctor", help="Check the local environment.")
app.add_typer(ui.app, name="ui", help="Run the local desktop UI bridge.")


@app.callback()
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", help="Show the TraceForge version and exit.", is_eager=True
    ),
) -> None:
    """TraceForge - understand software through observable evidence."""
    if ctx.invoked_subcommand is not None:
        return
    if version:
        typer.echo(f"traceforge {__version__}")
        raise typer.Exit(ExitCode.SUCCESS)


@app.command("version")
def version_command(json_output: bool = typer.Option(False, "--json", help="JSON output.")) -> None:
    """Show version information."""
    payload = {
        "name": "traceforge",
        "version": __version__,
        "python": sys.version.split()[0],
    }
    if json_output:
        import json

        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    typer.echo(f"traceforge {__version__} (Python {payload['python']})")


@app.command("annotate")
def annotate(
    finding_id: str = typer.Argument(..., help="Identifier of the finding to annotate."),
    text: str = typer.Option(..., "--text", "-t", help="The annotation body."),
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    json_output: bool = JSON_MODE,
) -> None:
    """Attach a note to a finding.

    Annotations are how a human records a manual confirmation, for example
    after verifying that a hypothesis about an endpoint was correct.
    """
    from traceforge.cli.common import resolve_workspace

    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    with ws.session_scope() as session:
        repo = ws.repository(session)
        row = repo.get_finding(finding_id)
        if row is None:
            typer.echo(f"Error: finding not found ({finding_id})", err=True)
            raise typer.Exit(ExitCode.NOT_FOUND)
        repo.set_annotation(finding_id, text)

    if json_output:
        import json

        typer.echo(json.dumps({"finding": finding_id, "annotation": text}, indent=2))
        return
    typer.echo(f"Annotated {finding_id}")


@app.command("show")
def show_finding(
    finding_id: str = typer.Argument(..., help="Identifier of the finding."),
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    json_output: bool = JSON_MODE,
) -> None:
    """Show a finding together with its provenance."""
    import json

    from traceforge.cli.common import resolve_workspace
    from traceforge.storage.repository import row_to_finding

    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    with ws.session_scope() as session:
        repo = ws.repository(session)
        row = repo.get_finding(finding_id)
        if row is None:
            typer.echo(f"Error: finding not found ({finding_id})", err=True)
            raise typer.Exit(ExitCode.NOT_FOUND)
        finding = row_to_finding(row)
        neighbours = repo.neighbors(finding_id)

    payload = {
        "finding": json.loads(finding.model_dump_json()),
        "relationships": [
            {
                "kind": edge.kind,
                "from": edge.from_id,
                "to": edge.to_id,
                "confidence": edge.confidence,
                "verified": edge.verified,
                "summary": edge.summary,
            }
            for edge in neighbours
        ],
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return

    typer.echo(f"[bold]{finding.type}[/bold]  {finding.summary}")
    typer.echo(f"  id:         {finding.id}")
    typer.echo(f"  confidence: {finding.confidence.value}")
    typer.echo(f"  method:     {finding.method}")
    typer.echo(f"  tool:       {finding.tool_name} {finding.tool_version}")
    typer.echo(f"  artifact:   {finding.artifact_id}")
    typer.echo(f"  created:    {finding.created_at}")
    for evidence in finding.evidence:
        typer.echo(f"  evidence:   {evidence.kind} {evidence.ref} {evidence.detail or ''}")
    for limitation in finding.limitations:
        typer.echo(f"  limitation: {limitation}")
    if finding.annotation:
        typer.echo(f"  annotation: {finding.annotation}")


def run() -> int:
    """Console entry point that maps errors onto documented exit codes.

    The Typer application runs in *standalone* mode so that the underlying
    command line library owns argument parsing, ``--help`` rendering and
    usage errors.  Typer ships its own vendored copy of that library, so this
    module never imports it directly: the exit status is obtained from the
    :class:`SystemExit` that standalone mode raises.
    """
    try:
        app()
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return ExitCode.SUCCESS
        if isinstance(code, int):
            return int(code)
        typer.echo(f"Error: {code}", err=True)
        return ExitCode.INTERNAL_ERROR
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        return exc.exit_code
    except KeyboardInterrupt:  # pragma: no cover - interactive
        typer.echo("Interrupted.", err=True)
        return 130
    except Exception as exc:  # pragma: no cover - defensive
        typer.echo(f"Error: {exc}", err=True)
        return ExitCode.INTERNAL_ERROR
    return ExitCode.SUCCESS


def main() -> None:  # pragma: no cover - console script shim
    sys.exit(run())


if __name__ == "__main__":  # pragma: no cover
    main()
