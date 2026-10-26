"""Integration tests for the CLI lifecycle."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from traceforge.cli.main import app


def test_workspace_init_list_info_delete(tmp_path: Path) -> None:
    runner = CliRunner()
    root = tmp_path / "workspaces"

    result = runner.invoke(app, ["workspace", "init", "demo", "--workspace-root", str(root), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["workspace"]["name"] == "demo"

    result = runner.invoke(app, ["workspace", "list", "--workspace-root", str(root), "--json"])
    assert result.exit_code == 0
    assert any(w["name"] == "demo" for w in json.loads(result.stdout)["workspaces"])

    result = runner.invoke(app, ["workspace", "info", "-w", "demo", "--workspace-root", str(root), "--json"])
    assert result.exit_code == 0
    info = json.loads(result.stdout)["workspace"]
    assert info["name"] == "demo"
    assert info["counts"]["artifacts"] == 0

    result = runner.invoke(app, ["workspace", "delete", "-w", "demo", "--workspace-root", str(root), "--yes", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["deleted"]


def test_analyze_binary_and_show(tmp_path: Path) -> None:
    runner = CliRunner()
    root = tmp_path / "workspaces"
    runner.invoke(app, ["workspace", "init", "demo", "--workspace-root", str(root)])

    from tests.fixtures.generators import build_elf

    path = tmp_path / "hello"
    path.write_bytes(build_elf())

    result = runner.invoke(
        app,
        ["analyze", "binary", str(path), "-w", "demo", "--workspace-root", str(root), "--json"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["artifact_id"]
    assert payload["findings"] >= 1

    listed = runner.invoke(
        app,
        ["export", "findings", "-w", "demo", "--workspace-root", str(root), "--json"],
    )
    assert listed.exit_code == 0
    finding_id = json.loads(listed.stdout)["findings"][0]["id"]

    result = runner.invoke(
        app,
        ["show", finding_id, "-w", "demo", "--workspace-root", str(root), "--json"],
    )
    assert result.exit_code == 0
    shown = json.loads(result.stdout)
    assert shown["finding"]["id"] == finding_id

    result = runner.invoke(
        app,
        [
            "annotate",
            finding_id,
            "-t",
            "confirmed by test",
            "-w",
            "demo",
            "--workspace-root",
            str(root),
            "--json",
        ],
    )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["finding"] == finding_id


def test_import_har_and_endpoints(tmp_path: Path) -> None:
    runner = CliRunner()
    root = tmp_path / "workspaces"
    runner.invoke(app, ["workspace", "init", "demo", "--workspace-root", str(root)])

    from tests.fixtures.generators import build_har

    path = tmp_path / "demo.har"
    path.write_text(json.dumps(build_har()), encoding="utf-8")

    result = runner.invoke(
        app,
        ["import", "har", str(path), "-w", "demo", "--workspace-root", str(root), "--json"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["detail"]["entries"] == 5
    assert payload["detail"]["endpoints"] >= 1

    result = runner.invoke(
        app,
        ["import", "endpoints", "-w", "demo", "--workspace-root", str(root), "--json"],
    )
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["kind"] == "endpoints"
    assert document["count"] >= 1


def test_api_diff_and_export(tmp_path: Path) -> None:
    runner = CliRunner()
    root = tmp_path / "workspaces"
    runner.invoke(app, ["workspace", "init", "demo", "--workspace-root", str(root)])

    from tests.fixtures.generators import build_har

    a = tmp_path / "a.har"
    b = tmp_path / "b.har"
    a.write_text(json.dumps(build_har()), encoding="utf-8")
    b.write_text(
        json.dumps(
            build_har(
                entries=[
                    {
                        "method": "GET",
                        "url": "https://api.example.test/v1/users/42",
                        "status": 200,
                        "content_type": "application/json",
                        "response": {"id": 42, "name": "Ada"},
                    },
                    {
                        "method": "GET",
                        "url": "https://api.example.test/v1/health",
                        "status": 200,
                        "content_type": "application/json",
                        "response": {"status": "ok", "version": "2"},
                    },
                ]
            )
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["api", "diff", str(a), str(b), "-w", "demo", "--workspace-root", str(root), "--json"],
    )
    assert result.exit_code == 0
    diff = json.loads(result.stdout)
    assert "added" in diff and "removed" in diff

    result = runner.invoke(
        app,
        ["export", "openapi", "-w", "demo", "--workspace-root", str(root), "-o", str(tmp_path / "openapi.yaml")],
    )
    assert result.exit_code == 0
    text = (tmp_path / "openapi.yaml").read_text(encoding="utf-8")
    assert "openapi:" in text

    result = runner.invoke(
        app,
        ["export", "findings", "-w", "demo", "--workspace-root", str(root), "--json"],
    )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["kind"] == "findings"

    result = runner.invoke(
        app,
        ["export", "report", "-w", "demo", "--workspace-root", str(root), "-o", str(tmp_path / "report.md")],
    )
    assert result.exit_code == 0
    assert (tmp_path / "report.md").exists()

    result = runner.invoke(
        app,
        ["graph", "show", "-w", "demo", "--workspace-root", str(root), "--json"],
    )
    assert result.exit_code == 0
    graph = json.loads(result.stdout)
    assert graph["kind"] == "graph"
