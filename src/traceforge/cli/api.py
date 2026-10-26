"""API comparison commands."""

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
from traceforge.services.analysis_service import diff_artifacts

app = typer.Typer(help="Compare observed API behaviour.", no_args_is_help=True)


def _resolve_capture(ws, reference: str):
    """Resolve a capture reference: an artifact id, a display name or a file path."""
    from traceforge.domain.enums import ArtifactKind

    with ws.session_scope() as session:
        repo = ws.repository(session)
        row = repo.get_artifact(reference)
        if row is not None:
            return row.id

        for candidate in repo.list_artifacts(kind=ArtifactKind.HAR):
            if candidate.display_name == reference or candidate.sha256 == reference:
                return candidate.id

    # Treat the reference as a file path and import it on the fly.
    from traceforge.services.analysis_service import import_har

    path = Path(reference).expanduser()
    if path.exists():
        outcome = import_har(ws, path, settings=load_settings())
        return outcome.artifact_id

    raise TraceForgeError(
        "Could not resolve the capture",
        detail=f"'{reference}' is neither a known artefact nor an existing file",
    )


@app.command("diff")
def diff(
    capture_a: str = typer.Argument(..., help="First capture: artefact id, name or file."),
    capture_b: str = typer.Argument(..., help="Second capture: artefact id, name or file."),
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    root: Path = WORKSPACE_ROOT,
    no_persist: bool = typer.Option(
        False, "--no-persist", help="Do not store the diff as findings."
    ),
    json_output: bool = JSON_MODE,
) -> None:
    """Compare two traffic captures and report the differences."""
    try:
        ws = resolve_workspace(workspace, root)
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    try:
        artifact_a = _resolve_capture(ws, capture_a)
        artifact_b = _resolve_capture(ws, capture_b)
        result = diff_artifacts(
            ws, artifact_a, artifact_b, settings=load_settings(), persist=not no_persist
        )
    except TraceForgeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc

    payload = {
        "captures": {"a": result.left_label, "b": result.right_label},
        "summary": result.summary(),
        "added": [
            {
                "method": s.method,
                "origin": s.origin,
                "path_key": s.path_key,
                "count": s.count,
                "status_codes": list(s.status_codes),
            }
            for s in result.added
        ],
        "removed": [
            {
                "method": s.method,
                "origin": s.origin,
                "path_key": s.path_key,
                "count": s.count,
                "status_codes": list(s.status_codes),
            }
            for s in result.removed
        ],
        "changed": [
            {
                "method": c.method,
                "origin": c.origin,
                "path_key": c.path_key,
                "category": c.category,
                "detail": c.detail,
            }
            for c in result.changed
        ],
        "unclassified": result.unclassified,
        "notes": [
            "Differences describe the observed traffic, not the server implementation.",
            "A missing endpoint may mean removal, or simply that a capture did not exercise it.",
        ],
    }

    if json_output:
        emit_json(payload)
        return

    summary = result.summary()
    console().print(f"[bold]Diff[/bold] {result.left_label} -> {result.right_label}")
    console().print(
        f"  added: {summary['added']}  removed: {summary['removed']}  "
        f"changed: {summary['changed']}  unclassified: {summary['unclassified']}"
    )

    if result.added:
        table = Table(title="Added endpoints")
        table.add_column("Method")
        table.add_column("Path")
        for snapshot in result.added:
            table.add_row(snapshot.method, snapshot.path_key)
        console().print(table)

    if result.removed:
        table = Table(title="Removed endpoints")
        table.add_column("Method")
        table.add_column("Path")
        for snapshot in result.removed:
            table.add_row(snapshot.method, snapshot.path_key)
        console().print(table)

    if result.changed:
        table = Table(title="Changed endpoints")
        table.add_column("Method")
        table.add_column("Path")
        table.add_column("Category")
        table.add_column("Detail")
        for change in result.changed:
            table.add_row(change.method, change.path_key, change.category, change.detail)
        console().print(table)
