"""Regression tests for deterministic behaviour."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from traceforge.adapters.binary.strings import extract_strings
from traceforge.adapters.http.har import parse_har
from traceforge.analysis.schema import infer_schema, schemas_differ
from traceforge.cli.main import app
from tests.fixtures.generators import build_elf, build_har


def test_string_extraction_is_deterministic() -> None:
    data = build_elf()
    assert extract_strings(data) == extract_strings(data)


def test_schema_inference_is_deterministic() -> None:
    samples = [{"id": 1, "name": "a"}, {"id": 2}, {"id": 3, "name": "b"}]
    left = infer_schema(samples)
    right = infer_schema(samples)
    assert left == right
    assert schemas_differ(left, right) == []


def test_har_parsing_is_deterministic() -> None:
    document = build_har()
    first = parse_har(document)
    second = parse_har(document)
    assert len(first.entries) == len(second.entries)
    assert [e.request.url for e in first.entries] == [e.request.url for e in second.entries]


def test_cli_json_output_is_deterministic(tmp_path: Path) -> None:
    runner = CliRunner()
    root = tmp_path / "workspaces"
    runner.invoke(app, ["workspace", "init", "demo", "--workspace-root", str(root)])
    path = tmp_path / "hello"
    path.write_bytes(build_elf())
    result1 = runner.invoke(
        app,
        ["analyze", "binary", str(path), "-w", "demo", "--workspace-root", str(root), "--json"],
    )
    result2 = runner.invoke(
        app,
        ["analyze", "binary", str(path), "-w", "demo", "--workspace-root", str(root), "--json"],
    )
    assert result1.exit_code == 0 and result2.exit_code == 0
    payload1 = json.loads(result1.stdout)
    payload2 = json.loads(result2.stdout)
    # Re-running on an identical file is idempotent; artifact identity is deterministic.
    assert payload1["artifact_id"] == payload2["artifact_id"]
