"""Shared pytest fixtures.

Every test in this repository works on **synthetic** data only.  The binary
and HAR fixtures are generated programmatically by
:mod:`tests.fixtures.generators` so that no third-party binary, capture or
credential is ever committed to the repository.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from traceforge.config import Limits, Settings
from traceforge.domain.enums import ArtifactKind
from traceforge.services.workspace import Workspace, create_workspace
from tests.fixtures.generators import build_elf, build_har, build_pe


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------
@pytest.fixture
def workspace_root(tmp_path: Path) -> Path:
    """A directory that holds workspaces during a test."""
    root = tmp_path / "workspaces"
    root.mkdir(parents=True, exist_ok=True)
    return root


@pytest.fixture
def workspace(workspace_root: Path) -> Workspace:
    """A freshly created, empty workspace."""
    return create_workspace("demo", root=workspace_root)


@pytest.fixture
def settings() -> Settings:
    """Default settings with the standard safety limits."""
    return Settings()


@pytest.fixture
def tight_limits() -> Limits:
    """Small limits used to exercise the rejection paths cheaply."""
    return Limits(
        max_file_bytes=64 * 1024,
        max_har_entries=3,
        max_body_bytes=1024,
        max_json_depth=4,
        max_json_keys=4,
        min_string_length=4,
        max_strings=50,
        max_string_length=64,
        max_string_scan_bytes=1024 * 1024,
        max_endpoints_per_artifact=5,
        max_findings_per_run=20,
    )


# ---------------------------------------------------------------------------
# synthetic binary fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def pe_bytes() -> bytes:
    """A synthetic 32-bit PE file."""
    return build_pe()


@pytest.fixture
def elf_bytes() -> bytes:
    """A synthetic 64-bit ELF file."""
    return build_elf()


@pytest.fixture
def pe_file(tmp_path: Path, pe_bytes: bytes) -> Path:
    """The synthetic PE written to disk."""
    path = tmp_path / "hello-world.exe"
    path.write_bytes(pe_bytes)
    return path


@pytest.fixture
def elf_file(tmp_path: Path, elf_bytes: bytes) -> Path:
    """The synthetic ELF written to disk."""
    path = tmp_path / "hello-world"
    path.write_bytes(elf_bytes)
    return path


# ---------------------------------------------------------------------------
# synthetic HAR fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def har_document() -> dict[str, Any]:
    """The default synthetic HAR document."""
    return build_har()


@pytest.fixture
def har_file(tmp_path: Path, har_document: dict[str, Any]) -> Path:
    """The default synthetic HAR written to disk."""
    path = tmp_path / "demo.har"
    path.write_text(json.dumps(har_document, indent=2), encoding="utf-8")
    return path


@pytest.fixture
def har_v2_file(tmp_path: Path) -> Path:
    """A second synthetic HAR that differs from the first one."""
    document = build_har(
        entries=[
            {
                "method": "GET",
                "url": "https://api.example.test/v1/users/42",
                "status": 200,
                "content_type": "application/json",
                "response": {"id": 42, "name": "Ada", "email": "ada@example.test"},
                "headers": {"Content-Type": "application/json"},
            },
            {
                "method": "GET",
                "url": "https://api.example.test/v1/health",
                "status": 200,
                "content_type": "application/json",
                "response": {"status": "ok", "version": "2"},
                "headers": {"Content-Type": "application/json"},
            },
            {
                "method": "GET",
                "url": "https://api.example.test/v1/metrics",
                "status": 200,
                "content_type": "application/json",
                "response": {"cpu": 0.5},
                "headers": {"Content-Type": "application/json"},
            },
        ]
    )
    path = tmp_path / "demo-v2.har"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


@pytest.fixture
def artifact_kind_binary() -> ArtifactKind:
    return ArtifactKind.BINARY


@pytest.fixture
def artifact_kind_har() -> ArtifactKind:
    return ArtifactKind.HAR
