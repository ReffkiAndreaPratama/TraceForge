"""Local HTTP bridge for the TraceForge desktop UI.

The bridge is a thin adapter over the same services the CLI uses: it does not
re-implement any analysis.  It listens on the loopback interface only, never
performs outbound requests and never serves files outside the workspace.

Security model (see ``docs/threat-model.md``):

* bind address is ``127.0.0.1`` and cannot be changed from the UI,
* every ``/api`` request except ``/api/health`` and ``/api/session`` must carry
  the per-run token in the ``X-TraceForge-Token`` header,
* CORS is restricted to the configured front-end origins,
* uploads are the only way to bring a file in; arbitrary paths are never read.

A local process running as the same user can read the token file and therefore
use the bridge.  That is accepted: such a process can already read every file
the user can read.  The token exists to stop *cross-site* requests from a web
page, which cannot set custom headers without a successful CORS preflight.
"""

from __future__ import annotations

import secrets
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from traceforge.cli.common import load_settings
from traceforge.config import Limits
from traceforge.errors import ExitCode, TraceForgeError
from traceforge.exporters.json_export import (
    export_endpoints_document,
    export_findings_document,
    export_graph_document,
)
from traceforge.graph.builder import build_graph_document
from traceforge.graph.queries import neighbours, search_nodes
from traceforge.services.analysis_service import (
    analyze_binary,
    export_openapi_document,
    import_har,
)
from traceforge.services.workspace import (
    Workspace,
    create_workspace,
    find_workspace,
    list_workspaces,
    workspace_stats,
)
from traceforge.storage.repository import row_to_finding
from traceforge.version import __version__

TOKEN_HEADER = "X-TraceForge-Token"

#: Workspace name used when the caller does not name one.
DEFAULT_WORKSPACE = "default"

#: Front-end development server origins that may call the bridge.
DEFAULT_ORIGINS = (
    "http://127.0.0.1:5173",
    "http://localhost:5173",
)


def _workspace_or_404(root: Path, name: str) -> Workspace:
    try:
        return find_workspace(name, root=root)
    except TraceForgeError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _http_status_for(exit_code: int) -> int:
    """Translate a documented CLI exit code into an HTTP status."""
    return {
        ExitCode.USAGE_ERROR: 422,
        ExitCode.NOT_FOUND: 404,
        ExitCode.REJECTED: 413,
        ExitCode.ANALYSIS_FAILED: 500,
    }.get(exit_code, 500)


def _dump_row(row: Any) -> dict[str, Any]:
    """Convert a finding row into the export shape used by the CLI."""
    finding = row_to_finding(row)
    return {
        "id": finding.id,
        "type": finding.type.value,
        "summary": finding.summary,
        "confidence": finding.confidence.value,
        "method": finding.method,
        "tool": {"name": finding.tool_name, "version": finding.tool_version},
        "artifact_id": finding.artifact_id,
        "run_id": finding.run_id,
        "key": finding.key,
        "data": finding.data,
        "evidence": [e.model_dump(mode="json") for e in finding.evidence],
        "limitations": list(finding.limitations),
        "annotation": finding.annotation,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
    }


def create_app(
    *,
    workspace_root: Path,
    token: str | None = None,
    allowed_origins: tuple[str, ...] = DEFAULT_ORIGINS,
    limits: Limits | None = None,
    static_dir: Path | None = None,
) -> FastAPI:
    """Build the bridge application.

    ``token`` defaults to a fresh random value; pass one explicitly to make an
    integration test reproducible.
    """
    bridge_token = token or secrets.token_urlsafe(32)
    root = Path(workspace_root).expanduser()
    limits = limits or load_settings().limits
    static_dir = static_dir or (Path(__file__).resolve().parents[3] / "apps" / "desktop" / "dist")

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield

    app = FastAPI(
        title="TraceForge local bridge",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.workspace_root = root
    app.state.token = bridge_token

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", TOKEN_HEADER],
    )

    def require_token(request: Request) -> None:
        supplied = request.headers.get(TOKEN_HEADER, "")
        if not secrets.compare_digest(supplied, bridge_token):
            raise HTTPException(status_code=401, detail="Missing or invalid bridge token")

    def current_workspace(name: str) -> Workspace:
        return _workspace_or_404(root, name)

    # ------------------------------------------------------------------
    # session / health
    # ------------------------------------------------------------------
    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "workspace_root": str(root),
            "offline": True,
        }

    @app.get("/api/session")
    def session_info() -> dict[str, Any]:
        """Hand the per-run token to the bundled front-end.

        This route is unauthenticated by design; it is protected by the CORS
        policy instead.  See the module docstring for the reasoning.
        """
        return {
            "token": bridge_token,
            "version": __version__,
            "workspace_root": str(root),
            "network_policy": "loopback only; no outbound requests",
        }

    # ------------------------------------------------------------------
    # workspaces
    # ------------------------------------------------------------------
    @app.get("/api/workspaces", dependencies=[Depends(require_token)])
    def workspaces() -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        for workspace in list_workspaces(root):
            try:
                items.append(
                    {
                        "id": workspace.id,
                        "name": workspace.name,
                        "root": str(workspace.root),
                        "counts": workspace_stats(workspace),
                    }
                )
            finally:
                workspace.close()
        return {"workspaces": items}

    @app.post("/api/workspaces", dependencies=[Depends(require_token)])
    def create_workspace_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        name = str(payload.get("name") or "").strip()
        if not name:
            raise HTTPException(status_code=422, detail="A workspace name is required")
        try:
            workspace = create_workspace(
                name,
                root=root,
                description=payload.get("description"),
                exist_ok=True,
            )
        except TraceForgeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            return {
                "workspace": {
                    "id": workspace.id,
                    "name": workspace.name,
                    "root": str(workspace.root),
                    "counts": workspace_stats(workspace),
                }
            }
        finally:
            workspace.close()

    @app.get("/api/workspaces/{name}/overview", dependencies=[Depends(require_token)])
    def overview(name: str) -> dict[str, Any]:
        workspace = current_workspace(name)
        try:
            counts = workspace_stats(workspace)
            with workspace.session_scope() as session:
                repo = workspace.repository(session)
                artifacts = [
                    {
                        "id": row.id,
                        "kind": row.kind,
                        "display_name": row.display_name,
                        "sha256": row.sha256,
                        "size_bytes": row.size_bytes,
                        "created_at": row.created_at.isoformat() if row.created_at else None,
                    }
                    for row in repo.list_artifacts()
                ]
                runs = [
                    {
                        "id": row.id,
                        "kind": row.kind,
                        "status": row.status,
                        "artifact_id": row.artifact_id,
                        "started_at": row.started_at.isoformat() if row.started_at else None,
                    }
                    for row in repo.list_runs()
                ]
            return {
                "workspace": {
                    "id": workspace.id,
                    "name": workspace.name,
                    "root": str(workspace.root),
                },
                "counts": counts,
                "artifacts": artifacts,
                "runs": runs,
            }
        finally:
            workspace.close()

    # ------------------------------------------------------------------
    # findings
    # ------------------------------------------------------------------
    @app.get("/api/workspaces/{name}/findings", dependencies=[Depends(require_token)])
    def findings(
        name: str,
        q: str | None = None,
        type: str | None = None,  # noqa: A002 - query parameter name
        artifact: str | None = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        workspace = current_workspace(name)
        try:
            with workspace.session_scope() as session:
                repo = workspace.repository(session)
                rows = repo.list_findings(
                    artifact_id=artifact,
                    finding_type=type,
                    search=q,
                    limit=max(1, min(int(limit), 2000)),
                )
                return {
                    "workspace": workspace.name,
                    "count": len(rows),
                    "findings": [_dump_row(row) for row in rows],
                }
        finally:
            workspace.close()

    @app.get(
        "/api/workspaces/{name}/findings/{finding_id}",
        dependencies=[Depends(require_token)],
    )
    def finding_detail(name: str, finding_id: str) -> dict[str, Any]:
        workspace = current_workspace(name)
        try:
            with workspace.session_scope() as session:
                repo = workspace.repository(session)
                row = repo.get_finding(finding_id)
                if row is None:
                    raise HTTPException(status_code=404, detail="Finding not found")
                edges = repo.neighbors(finding_id)
            return {
                "finding": _dump_row(row),
                "relationships": [
                    {
                        "kind": edge.kind,
                        "from": edge.from_id,
                        "to": edge.to_id,
                        "confidence": edge.confidence,
                        "verified": edge.verified,
                        "summary": edge.summary,
                    }
                    for edge in edges
                ],
            }
        finally:
            workspace.close()

    @app.post(
        "/api/workspaces/{name}/findings/{finding_id}/annotation",
        dependencies=[Depends(require_token)],
    )
    def annotate(name: str, finding_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        text = payload.get("text")
        workspace = current_workspace(name)
        try:
            with workspace.session_scope() as session:
                repo = workspace.repository(session)
                if repo.get_finding(finding_id) is None:
                    raise HTTPException(status_code=404, detail="Finding not found")
                repo.set_annotation(finding_id, text)
            return {"finding": finding_id, "annotation": text}
        finally:
            workspace.close()

    # ------------------------------------------------------------------
    # endpoints / graph
    # ------------------------------------------------------------------
    @app.get("/api/workspaces/{name}/endpoints", dependencies=[Depends(require_token)])
    def endpoints(name: str) -> dict[str, Any]:
        workspace = current_workspace(name)
        try:
            with workspace.session_scope() as session:
                repo = workspace.repository(session)
                return export_endpoints_document(repo, workspace_name=workspace.name)
        finally:
            workspace.close()

    @app.get("/api/workspaces/{name}/graph", dependencies=[Depends(require_token)])
    def graph(name: str) -> dict[str, Any]:
        workspace = current_workspace(name)
        try:
            with workspace.session_scope() as session:
                repo = workspace.repository(session)
                document = build_graph_document(repo, workspace_name=workspace.name)
                return export_graph_document(document)
        finally:
            workspace.close()

    @app.get("/api/workspaces/{name}/search", dependencies=[Depends(require_token)])
    def search(name: str, q: str = "", limit: int = 100) -> dict[str, Any]:
        workspace = current_workspace(name)
        try:
            with workspace.session_scope() as session:
                repo = workspace.repository(session)
                document = build_graph_document(repo, workspace_name=workspace.name)
                found = search_nodes(document, q, limit=max(1, min(int(limit), 500)))
                return {
                    "query": q,
                    "count": len(found),
                    "nodes": [
                        {
                            "id": node.id,
                            "type": node.type,
                            "label": node.label,
                            "confidence": node.confidence.value,
                        }
                        for node in found
                    ],
                }
        finally:
            workspace.close()

    @app.get(
        "/api/workspaces/{name}/graph/neighbors/{node_id}",
        dependencies=[Depends(require_token)],
    )
    def graph_neighbors(name: str, node_id: str) -> dict[str, Any]:
        workspace = current_workspace(name)
        try:
            with workspace.session_scope() as session:
                repo = workspace.repository(session)
                document = build_graph_document(repo, workspace_name=workspace.name)
                found = neighbours(document, node_id)
            return {
                "node": node_id,
                "neighbours": [
                    {
                        "id": item.node.id,
                        "type": item.node.type,
                        "label": item.node.label,
                        "direction": item.direction,
                        "edges": [
                            {
                                "kind": edge.kind,
                                "confidence": edge.confidence.value,
                                "summary": edge.summary,
                                "verified": edge.verified,
                                "limitations": edge.limitations,
                            }
                            for edge in item.edges
                        ],
                    }
                    for item in found
                ],
            }
        finally:
            workspace.close()

    # ------------------------------------------------------------------
    # ingestion (uploads only - the bridge never reads a caller supplied path)
    # ------------------------------------------------------------------
    def _store_upload(upload: UploadFile) -> Path:
        suffix = Path(upload.filename or "upload.bin").suffix
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        try:
            written = 0
            while chunk := upload.file.read(1024 * 1024):
                written += len(chunk)
                if written > limits.max_file_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=(
                            "The file exceeds the maximum allowed size "
                            f"({limits.max_file_bytes} bytes)"
                        ),
                    )
                handle.write(chunk)
        finally:
            handle.close()
            upload.file.close()
        return Path(handle.name)

    def analyze_import(workspace: Workspace, path: Path, *, kind: str) -> dict[str, Any]:
        settings = load_settings()
        try:
            if kind == "har":
                outcome = import_har(workspace, path, settings=settings)
            else:
                outcome = analyze_binary(workspace, path, settings=settings)
        except TraceForgeError as exc:
            raise HTTPException(
                status_code=_http_status_for(exc.exit_code), detail=str(exc)
            ) from exc
        payload = outcome.as_dict()
        payload["workspace"] = workspace.name
        return payload

    @app.post("/api/workspaces/{name}/imports/har", dependencies=[Depends(require_token)])
    def upload_har(name: str, file: UploadFile = File(...)) -> dict[str, Any]:
        workspace = current_workspace(name)
        temporary = _store_upload(file)
        try:
            return analyze_import(workspace, temporary, kind="har")
        finally:
            temporary.unlink(missing_ok=True)
            workspace.close()

    @app.post("/api/workspaces/{name}/analyses/binary", dependencies=[Depends(require_token)])
    def upload_binary(name: str, file: UploadFile = File(...)) -> dict[str, Any]:
        workspace = current_workspace(name)
        temporary = _store_upload(file)
        try:
            return analyze_import(workspace, temporary, kind="binary")
        finally:
            temporary.unlink(missing_ok=True)
            workspace.close()

    # ------------------------------------------------------------------
    # exports
    # ------------------------------------------------------------------
    @app.get("/api/workspaces/{name}/exports/openapi", dependencies=[Depends(require_token)])
    def export_openapi(name: str) -> PlainTextResponse:
        workspace = current_workspace(name)
        try:
            import yaml

            document = export_openapi_document(workspace)
            return PlainTextResponse(
                yaml.safe_dump(document, sort_keys=True, allow_unicode=True),
                media_type="application/yaml",
            )
        finally:
            workspace.close()

    @app.get("/api/workspaces/{name}/exports/findings", dependencies=[Depends(require_token)])
    def export_findings(name: str) -> dict[str, Any]:
        workspace = current_workspace(name)
        try:
            with workspace.session_scope() as session:
                repo = workspace.repository(session)
                return export_findings_document(repo, workspace_name=workspace.name)
        finally:
            workspace.close()

    # ------------------------------------------------------------------
    # errors
    # ------------------------------------------------------------------
    @app.exception_handler(TraceForgeError)
    async def traceforge_error_handler(_request: Request, exc: TraceForgeError) -> JSONResponse:
        return JSONResponse(
            status_code=400, content={"error": {"message": str(exc), "detail": exc.detail}}
        )

    if static_dir.is_dir():
        app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="ui")

    return app


def write_token_file(path: Path, token: str, *, host: str, port: int) -> Path:
    """Write the bridge connection details for the local front-end."""
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"token": token, "host": host, "port": port}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover - not supported on every filesystem
        pass
    return path


__all__ = ["TOKEN_HEADER", "create_app", "write_token_file"]
