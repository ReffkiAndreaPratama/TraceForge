"""Shared CLI helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from traceforge.config import Settings
from traceforge.errors import TraceForgeError
from traceforge.services.workspace import Workspace, find_workspace

#: The global output mode.
JSON_MODE = typer.Option(False, "--json", help="Emit machine readable JSON on stdout.")
#: The workspace root directory.
WORKSPACE_ROOT = typer.Option(
    None,
    "--workspace-root",
    help="Directory that contains workspaces (default: ~/.traceforge/workspaces).",
    envvar="TRACEFORGE_WORKSPACE_ROOT",
)


def console() -> Console:
    """Return a Rich console that never emits colour codes when piped."""
    return Console(no_color=False, soft_wrap=False)


def error_console() -> Console:
    return Console(stderr=True)


def load_settings() -> Settings:
    return Settings.from_env()


def resolve_workspace(name: str, root: Path | None) -> Workspace:
    """Open a workspace by name (or by path when the name looks like a path)."""
    candidate = Path(name).expanduser()
    if candidate.is_dir():
        from traceforge.services.workspace import open_workspace

        return open_workspace(candidate)
    return find_workspace(name, root=root)


def emit_json(payload: Any) -> None:
    """Print a JSON payload to stdout."""
    typer.echo(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, default=str))


def fail(message: str, *, code: int = 1, json_mode: bool = False) -> None:
    """Print an error and raise ``typer.Exit`` with the given code."""
    if json_mode:
        typer.echo(
            json.dumps({"error": {"message": message, "exit_code": code}}, indent=2),
            err=True,
        )
    else:
        error_console().print(f"[bold red]Error:[/bold red] {message}")
    raise typer.Exit(code)


def handle_error(exc: TraceForgeError, *, json_mode: bool = False) -> None:
    """Map a TraceForge error onto a documented exit code."""
    fail(
        exc.message if not exc.detail else f"{exc.message} ({exc.detail})",
        code=exc.exit_code,
        json_mode=json_mode,
    )


def truncate(value: str, length: int = 80) -> str:
    """Shorten a string for table display."""
    if len(value) <= length:
        return value
    return value[: length - 1] + "…"
