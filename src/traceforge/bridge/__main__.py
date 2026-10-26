"""Entry point for ``python -m traceforge.bridge``."""

from __future__ import annotations

import argparse
import secrets
import sys
import webbrowser
from pathlib import Path

from traceforge.bridge.server import create_app, write_token_file
from traceforge.services.workspace import default_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="traceforge-bridge",
        description=(
            "Serve the TraceForge desktop UI on the loopback interface. "
            "No outbound network access is performed."
        ),
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (loopback only).")
    parser.add_argument("--port", type=int, default=8765, help="TCP port to listen on.")
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=None,
        help="Directory containing workspaces (default: ~/.traceforge/workspaces).",
    )
    parser.add_argument(
        "--token-file",
        type=Path,
        default=None,
        help="Where to write the token/port file used by the dev front-end.",
    )
    parser.add_argument("--open", action="store_true", help="Open a browser window.")
    args = parser.parse_args(argv)

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("The bridge only binds to the loopback interface")

    import uvicorn

    root = (args.workspace_root or default_root()).expanduser()
    token = secrets.token_urlsafe(32)
    token_file = args.token_file or (Path.home() / ".traceforge" / "bridge.json")
    write_token_file(token_file, token, host=args.host, port=args.port)

    app = create_app(workspace_root=root, token=token)
    url = f"http://{args.host}:{args.port}/"
    print(f"TraceForge bridge listening on {url}")
    print(f"Token file: {token_file}")
    print("Press Ctrl+C to stop. The bridge is loopback-only and offline.")
    if args.open:
        webbrowser.open(url)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning", access_log=False)
    return 0


if __name__ == "__main__":  # pragma: no cover - module entry point
    sys.exit(main())
