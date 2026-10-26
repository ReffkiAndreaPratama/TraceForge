"""Integration tests for the local HTTP bridge."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from traceforge.bridge.server import TOKEN_HEADER, create_app
from traceforge.config import Limits
from tests.fixtures.generators import build_elf, build_har

TOKEN = "test-token-not-a-secret"


@pytest.fixture
def client(workspace_root: Path) -> TestClient:
    app = create_app(
        workspace_root=workspace_root,
        token=TOKEN,
        allowed_origins=("http://127.0.0.1:5173",),
        limits=Limits(max_file_bytes=1024 * 1024),
        static_dir=workspace_root / "no-ui-here",
    )
    return TestClient(app)


@pytest.fixture
def auth() -> dict[str, str]:
    return {TOKEN_HEADER: TOKEN}


def _create_workspace(client: TestClient, auth: dict[str, str], name: str = "demo") -> None:
    response = client.post("/api/workspaces", json={"name": name}, headers=auth)
    assert response.status_code == 200, response.text


def test_health_needs_no_token(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["offline"] is True


def test_api_requires_the_token(client: TestClient) -> None:
    assert client.get("/api/workspaces").status_code == 401
    assert client.get("/api/workspaces", headers={TOKEN_HEADER: "wrong"}).status_code == 401


def test_workspace_lifecycle(client: TestClient, auth: dict[str, str]) -> None:
    _create_workspace(client, auth)
    listing = client.get("/api/workspaces", headers=auth).json()
    assert [item["name"] for item in listing["workspaces"]] == ["demo"]

    overview = client.get("/api/workspaces/demo/overview", headers=auth)
    assert overview.status_code == 200
    assert overview.json()["counts"]["artifacts"] == 0


def test_unknown_workspace_is_404(client: TestClient, auth: dict[str, str]) -> None:
    assert client.get("/api/workspaces/nope/overview", headers=auth).status_code == 404


def test_binary_upload_and_findings(client: TestClient, auth: dict[str, str]) -> None:
    _create_workspace(client, auth)
    response = client.post(
        "/api/workspaces/demo/analyses/binary",
        headers=auth,
        files={"file": ("hello", build_elf(), "application/octet-stream")},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["artifact_id"].startswith("art_")
    assert body["findings"] >= 1

    findings = client.get("/api/workspaces/demo/findings", headers=auth).json()
    assert findings["count"] >= 1
    first = findings["findings"][0]
    assert first["confidence"] in {"observed", "inferred", "hypothesis"}

    detail = client.get(
        f"/api/workspaces/demo/findings/{first['id']}", headers=auth
    )
    assert detail.status_code == 200
    assert detail.json()["finding"]["id"] == first["id"]

    annotation = client.post(
        f"/api/workspaces/demo/findings/{first['id']}/annotation",
        headers=auth,
        json={"text": "reviewed"},
    )
    assert annotation.status_code == 200


def test_har_upload_builds_endpoint_inventory(client: TestClient, auth: dict[str, str]) -> None:
    _create_workspace(client, auth)
    response = client.post(
        "/api/workspaces/demo/imports/har",
        headers=auth,
        files={"file": ("demo.har", json.dumps(build_har()).encode(), "application/json")},
    )
    assert response.status_code == 200, response.text
    assert response.json()["detail"]["entries"] == 5

    endpoints = client.get("/api/workspaces/demo/endpoints", headers=auth).json()
    assert endpoints["count"] >= 1
    graph = client.get("/api/workspaces/demo/graph", headers=auth).json()
    assert graph["kind"] == "graph"
    search = client.get("/api/workspaces/demo/search", params={"q": "example"}, headers=auth)
    assert search.status_code == 200


def test_upload_size_limit_is_enforced(workspace_root: Path, auth: dict[str, str]) -> None:
    app = create_app(
        workspace_root=workspace_root,
        token=TOKEN,
        limits=Limits(max_file_bytes=100),
        static_dir=workspace_root / "no-ui-here",
    )
    client = TestClient(app)
    client.post("/api/workspaces", json={"name": "demo"}, headers=auth)
    response = client.post(
        "/api/workspaces/demo/analyses/binary",
        headers=auth,
        files={"file": ("big.bin", b"MZ" + b"x" * 500, "application/octet-stream")},
    )
    assert response.status_code == 413


def test_cors_preflight_only_allows_the_configured_origin(client: TestClient) -> None:
    allowed = client.options(
        "/api/workspaces",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": TOKEN_HEADER,
        },
    )
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"

    denied = client.options(
        "/api/workspaces",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert "access-control-allow-origin" not in denied.headers
