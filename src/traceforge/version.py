"""Single source of truth for the package version."""

from __future__ import annotations

__version__ = "0.1.0"

#: Schema version of the on-disk SQLite database. Bumped by Alembic migrations.
DB_SCHEMA_VERSION = 1

#: Version of the exported evidence-graph document format.
GRAPH_SCHEMA_VERSION = 1

#: Version of the relationship (edge) vocabulary. See docs/formats.md.
RELATIONSHIP_SCHEMA_VERSION = 1
