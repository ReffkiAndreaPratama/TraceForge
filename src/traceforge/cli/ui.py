"""Launch the local desktop UI (loopback-only HTTP bridge)."""

from __future__ import annotations

import secrets
import webbrowser
from pathlib import Path

import typer

from traceforge.cli.common import WORKSPACE_ROOT, console
from traceforge.errors import ExitCode, TraceForgeError

app = typer.Typer(help="Run the local desktop UI bridge.", no_args_is_help=False)


@app.callback(invoke_without_command=True)
def ui(
    root: Path = WORKSPACE_ROOT,
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address (loopback only)."),
    port: int = typer.Option(8765, "--port", help="TCP port to listen on."),
    token_file: Path = typer.Option(
        None,
        "--token-file",
        help="Where to write the token/port file (default: ~/.traceforge/bridge.json).",
    ),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Open a browser window."),
) -> None:
    """Serve the desktop UI locally.

    The bridge reuses the exact services the CLI uses, binds to the loopback
    interface and never makes outbound network requests.
    """
    if host not in {"127.0.0.1", "localhost", "::1"}:
        typer.echo("Error: the bridge only binds to the loopback interface", err=True)
        raise typer.Exit(ExitCode.USAGE_ERROR)

    try:
        import uvicorn  # noqa: F401
    except ImportError as exc:  # pragma: no cover - optional dependency
        typer.echo(
            "Error: the desktop bridge needs the 'desktop' extra "
            "(pip install 'traceforge[desktop]')",
            err=True,
        )
        raise typer.Exit(ExitCode.USAGE_ERROR) from exc

    from traceforge.bridge.server import create_app, write_token_file
    from traceforge.services.workspace import default_root

    workspace_root = Path(root).expanduser() if root is not None else default_root()
    token = secrets.token_urlsafe(32)
    token_path = token_file or (Path.home() / ".traceforge" / "bridge.json")
    write_token_file(token_path, token, host=host, port=port)

    url = f"http://{host}:{port}/"
    console().print(f"[green]TraceForge bridge[/green] {url}")
    console().print(f"  workspace root: {workspace_root}")
    console().print(f"  token file:     {token_path}")
    console().print("  network:        loopback only, no outbound access")
    if open_browser:
        webbrowser.open(url)

    try:
        application = create_app(workspace_root=workspace_root, token=token)
        uvicorn.run(application, host=host, port=port, log_level="warning", access_log=False)
    except OSError as exc:  # pragma: no cover - port in use
        typer.echo(f"Error: could not start the bridge: {exc}", err=True)
        raise typer.Exit(ExitCode.INTERNAL_ERROR) from exc
    except TraceForgeError as exc:  # pragma: no cover - defensive
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exc.exit_code) from exc
