"""Database engine creation and schema migration.

The SQLite database is the single source of truth for a workspace.  Schema
changes are applied through explicit Alembic revisions - the database is never
mutated by ad-hoc ``CREATE TABLE`` statements.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from traceforge.errors import TraceForgeError
from traceforge.version import DB_SCHEMA_VERSION

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

#: PRAGMA applied to every SQLite connection.
_FOREIGN_KEYS_PRAGMA = "PRAGMA foreign_keys=ON"


def database_url(db_path: Path) -> str:
    """Return the SQLAlchemy URL for a SQLite file."""
    absolute = db_path.resolve().as_posix()
    return f"sqlite:///{absolute}"


def create_engine_for(db_path: Path, *, echo: bool = False) -> Engine:
    """Create an engine for the SQLite database at ``db_path``.

    The pool is a :class:`~sqlalchemy.pool.NullPool`: SQLite is a local file
    and a pooled connection keeps the file handle open, which on Windows stops
    the workspace directory from being deleted.  Opening the file per session
    is cheap and keeps the workspace movable at all times.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        database_url(db_path),
        echo=echo,
        future=True,
        poolclass=NullPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - driver callback
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute(_FOREIGN_KEYS_PRAGMA)
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
        finally:
            cursor.close()

    return engine


def _alembic_config(db_path: Path) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", database_url(db_path).replace("%", "%%"))
    cfg.attributes["configure_logger"] = False
    return cfg


def init_database(db_path: Path) -> Path:
    """Create (or upgrade) the database at ``db_path`` and return the path."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    cfg = _alembic_config(db_path)
    try:
        command.upgrade(cfg, "head")
    except Exception as exc:  # pragma: no cover - depends on alembic internals
        raise TraceForgeError("Failed to initialise the database", detail=str(exc)) from exc
    return db_path


def current_revision(db_path: Path) -> str | None:
    """Return the Alembic revision currently applied to ``db_path``."""
    cfg = _alembic_config(db_path)
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(cfg)
    head = script.get_current_head()
    return head


def check_schema_version(db_path: Path) -> int:
    """Return the schema version recorded in the database."""
    engine = create_engine_for(db_path)
    try:
        from sqlalchemy import inspect, text

        inspector = inspect(engine)
        if "workspaces" not in inspector.get_table_names():
            return 0
        with engine.connect() as connection:
            row = connection.execute(text("SELECT MAX(schema_version) FROM workspaces")).scalar()
        return int(row or DB_SCHEMA_VERSION)
    finally:
        engine.dispose()


@contextmanager
def session_scope(engine: Engine) -> Iterator[Session]:
    """Yield a session, committing on success and rolling back on failure."""
    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
