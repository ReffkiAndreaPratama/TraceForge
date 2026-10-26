"""Environment diagnostics.

``traceforge doctor`` reports what is available in the current environment so
that a user can tell whether a missing feature is a configuration problem or a
missing dependency.
"""

from __future__ import annotations

import importlib
import platform
import sys
from pathlib import Path
from typing import Any

import typer
from rich.table import Table

from traceforge.cli.common import JSON_MODE, console, emit_json
from traceforge.config import Settings
from traceforge.version import __version__

app = typer.Typer(
    help="Check the local environment.",
    invoke_without_command=True,
    no_args_is_help=False,
)

#: Optional dependencies and what they enable.
OPTIONAL_DEPENDENCIES: dict[str, str] = {
    "pefile": "PE (Windows) binary parsing",
    "elftools": "ELF binary parsing",
    "lief": "Mach-O symbol enrichment",
    "yaml": "YAML output (OpenAPI export)",
    "fastapi": "Local HTTP bridge for the desktop UI",
    "uvicorn": "Local HTTP bridge for the desktop UI",
    "hypothesis": "Property based tests",
}


def _dependency_report() -> list[dict[str, Any]]:
    report: list[dict[str, Any]] = []
    for module_name, purpose in OPTIONAL_DEPENDENCIES.items():
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            report.append(
                {
                    "module": module_name,
                    "available": False,
                    "version": None,
                    "purpose": purpose,
                }
            )
            continue
        version = getattr(module, "__version__", None)
        if version is None:
            try:
                from importlib.metadata import version as pkg_version

                version = pkg_version(module_name)
            except Exception:  # noqa: BLE001
                version = "unknown"
        report.append(
            {
                "module": module_name,
                "available": True,
                "version": str(version),
                "purpose": purpose,
            }
        )
    return report


@app.callback(invoke_without_command=True)
def doctor(
    ctx: typer.Context,
    json_output: bool = JSON_MODE,
) -> None:
    """Report the health of the local TraceForge installation."""
    if ctx.invoked_subcommand is not None:
        return
    settings = Settings.from_env()
    dependencies = _dependency_report()

    payload = {
        "traceforge": {"version": __version__},
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
            "supported": sys.version_info >= (3, 11),
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "network_policy": {
            "offline": settings.offline,
            "note": (
                "TraceForge performs no outbound network access and uploads nothing. "
                "The optional desktop bridge listens on 127.0.0.1 only."
            ),
        },
        "limits": {
            "max_file_bytes": settings.limits.max_file_bytes,
            "max_har_entries": settings.limits.max_har_entries,
            "max_strings": settings.limits.max_strings,
            "max_findings_per_run": settings.limits.max_findings_per_run,
        },
        "redaction": {
            "sensitive_headers": list(settings.redaction.sensitive_headers),
            "sensitive_parameters": list(settings.redaction.sensitive_parameters),
            "user_patterns": len(settings.redaction.extra_patterns),
        },
        "dependencies": dependencies,
        "workspace_root": str(_workspace_root()),
    }

    if json_output:
        emit_json(payload)
        return

    console().print(f"[bold]TraceForge {__version__}[/bold]")
    console().print(
        f"  Python {payload['python']['version']} "
        f"({payload['python']['implementation']}) on {payload['platform']['system']}"
    )
    console().print(f"  Workspace root: {payload['workspace_root']}")
    console().print(f"  Network access: none (offline by design)")

    table = Table(title="Optional dependencies")
    table.add_column("Module")
    table.add_column("Status")
    table.add_column("Version")
    table.add_column("Enables")
    for dependency in dependencies:
        status = "[green]available[/green]" if dependency["available"] else "[yellow]missing[/yellow]"
        table.add_row(
            dependency["module"],
            status,
            dependency["version"] or "-",
            dependency["purpose"],
        )
    console().print(table)


def _workspace_root() -> Path:
    """Return the effective workspace root, honouring the environment override."""
    import os

    from traceforge.config import ENV_PREFIX
    from traceforge.services.workspace import default_root

    override = os.environ.get(f"{ENV_PREFIX}WORKSPACE_ROOT")
    if override and override.strip():
        return Path(override.strip()).expanduser()
    return default_root()
