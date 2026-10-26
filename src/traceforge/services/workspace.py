"""Workspace lifecycle: create, open, list and delete.

A workspace is a directory that contains:

``traceforge.db``
    The SQLite database holding artifacts, findings and relationships.
``artifacts/``
    Copies of imported files, stored under generated identifiers.
``exports/``
    Generated export documents.

The workspace root defaults to ``~/.traceforge/workspaces`` but any path can
be used, including a path inside a Git repository that is checked into
version control.
"""

from __future__ import annotations

import shutil
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from traceforge.domain.enums import ArtifactKind
from traceforge.errors import WorkspaceNotFoundError
from traceforge.ids import workspace_id as make_workspace_id
from traceforge.security.paths import ensure_directory, sanitize_display_name
from traceforge.storage.db import create_engine_for, init_database, session_scope
from traceforge.storage.models import WorkspaceRow
from traceforge.version import DB_SCHEMA_VERSION

DB_FILENAME = "traceforge.db"
ARTIFACTS_DIRNAME = "artifacts"
EXPORTS_DIRNAME = "exports"


def default_root() -> Path:
    """The default directory that holds workspaces."""
    return Path.home() / ".traceforge" / "workspaces"


@dataclass(slots=True)
class Workspace:
    """A handle on an open workspace."""

    id: str
    name: str
    root: Path
    engine: Engine
    db_path: Path

    @property
    def artifacts_dir(self) -> Path:
        return self.root / ARTIFACTS_DIRNAME

    @property
    def exports_dir(self) -> Path:
        return self.root / EXPORTS_DIRNAME

    def session(self) -> Session:
        return sessionmaker(bind=self.engine, expire_on_commit=False, future=True)()

    def close(self) -> None:
        """Release the database handle.

        On Windows an open SQLite handle prevents the workspace directory from
        being deleted, so every workspace that is opened only to *look* at it
        has to be closed again.
        """
        self.engine.dispose()

    def session_scope(self):
        """Return a context manager yielding a transactional session."""
        return session_scope(self.engine)

    def repository(self, session: Session):
        """Return a repository bound to this workspace."""
        from traceforge.storage.repository import WorkspaceRepository

        return WorkspaceRepository(session, self.id)


def workspace_slug(name: str) -> str:
    """Return a filesystem-safe slug for a workspace name."""
    return sanitize_display_name(name, fallback="workspace")


def create_workspace(
    name: str,
    *,
    root: Path | None = None,
    description: str | None = None,
    exist_ok: bool = False,
) -> Workspace:
    """Create a new workspace on disk and initialise its database."""
    base = Path(root) if root is not None else default_root()
    slug = workspace_slug(name)
    workspace_root = base / slug

    if workspace_root.exists():
        if not exist_ok:
            raise FileExistsError(f"A workspace already exists at {workspace_root}")
    else:
        ensure_directory(workspace_root)

    ensure_directory(workspace_root / ARTIFACTS_DIRNAME)
    ensure_directory(workspace_root / EXPORTS_DIRNAME)

    db_path = workspace_root / DB_FILENAME
    init_database(db_path)
    engine = create_engine_for(db_path)

    ws_id = make_workspace_id(slug, namespace=str(base))
    now = datetime.now().astimezone()
    with session_scope(engine) as session:
        existing = session.get(WorkspaceRow, ws_id)
        if existing is None:
            session.add(
                WorkspaceRow(
                    id=ws_id,
                    name=name,
                    slug=slug,
                    description=description,
                    root_path=str(workspace_root),
                    schema_version=DB_SCHEMA_VERSION,
                    created_at=now,
                    updated_at=now,
                )
            )
        else:
            existing.name = name
            existing.description = description
            existing.root_path = str(workspace_root)
            existing.updated_at = now

    return Workspace(id=ws_id, name=name, root=workspace_root, engine=engine, db_path=db_path)


def open_workspace(path: str | Path) -> Workspace:
    """Open an existing workspace by directory path."""
    root = Path(path).expanduser()
    if not root.exists():
        raise WorkspaceNotFoundError("Workspace directory does not exist", detail=str(root))
    db_path = root / DB_FILENAME
    if not db_path.exists():
        raise WorkspaceNotFoundError(
            "No TraceForge database found in this directory", detail=str(root)
        )
    engine = create_engine_for(db_path)
    with session_scope(engine) as session:
        row = session.execute(select(WorkspaceRow)).scalars().first()
        if row is None:
            raise WorkspaceNotFoundError("The workspace database is empty", detail=str(root))
        return Workspace(id=row.id, name=row.name, root=root, engine=engine, db_path=db_path)


def find_workspace(name: str, *, root: Path | None = None) -> Workspace:
    """Open a workspace by *name* from a workspaces root."""
    base = Path(root) if root is not None else default_root()
    candidate = base / workspace_slug(name)
    if candidate.exists():
        return open_workspace(candidate)
    # Fall back to a scan so that workspaces created with a different slug are
    # still reachable by their recorded name.
    if base.exists():
        for child in sorted(base.iterdir()):
            db = child / DB_FILENAME
            if not db.exists():
                continue
            try:
                workspace = open_workspace(child)
            except WorkspaceNotFoundError:
                continue
            if workspace.name == name:
                return workspace
            # Not the requested workspace: release the database handle again.
            workspace.close()
    raise WorkspaceNotFoundError("Workspace not found", detail=name)


def list_workspaces(root: Path | None = None) -> list[Workspace]:
    """Return every workspace found under ``root``."""
    base = Path(root) if root is not None else default_root()
    workspaces: list[Workspace] = []
    if not base.exists():
        return workspaces
    for child in sorted(base.iterdir()):
        if not (child / DB_FILENAME).exists():
            continue
        try:
            workspaces.append(open_workspace(child))
        except WorkspaceNotFoundError:  # pragma: no cover - defensive
            continue
    return workspaces


def delete_workspace(workspace: Workspace, *, remove_files: bool = True) -> None:
    """Delete a workspace.

    The database rows are removed first (so that a failure to delete files
    cannot leave dangling rows), then the database handle is released and
    finally the directory is removed.  On Windows a file that is still open
    cannot be deleted, so the removal is retried a few times.
    """
    with session_scope(workspace.engine) as session:
        session.query(WorkspaceRow).filter(WorkspaceRow.id == workspace.id).delete()
    workspace.close()
    if remove_files and workspace.root.exists():
        _remove_tree(workspace.root)


def _remove_tree(root: Path, *, attempts: int = 5) -> None:
    """Remove a directory tree, retrying while the OS still holds a handle."""
    last_error: OSError | None = None
    for attempt in range(attempts):
        try:
            shutil.rmtree(root)
            return
        except PermissionError as exc:  # pragma: no cover - platform dependent
            last_error = exc
            time.sleep(0.1 * (attempt + 1))
    if last_error is not None:  # pragma: no cover - platform dependent
        raise last_error


def workspace_stats(workspace: Workspace) -> dict[str, int]:
    """Return row counts for a workspace."""
    with workspace.session_scope() as session:
        repo = workspace.repository(session)
        return repo.counts()


def artifact_counts(workspace: Workspace) -> dict[str, int]:
    """Return the number of artifacts per kind."""
    with workspace.session_scope() as session:
        repo = workspace.repository(session)
        counts = {kind.value: 0 for kind in ArtifactKind}
        for row in repo.list_artifacts():
            counts[ArtifactKind(row.kind)] += 1  # type: ignore[index]
        return counts
