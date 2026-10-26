"""SQLAlchemy ORM models.

These are the *persistence* representation of the domain.  They are kept
separate from :mod:`traceforge.domain.models` so that the domain layer never
depends on a database.

Conventions
-----------
* Identifiers are short, prefixed, content-addressed strings (see
  :mod:`traceforge.ids`).
* Timestamps are stored as ISO-8601 UTC strings so that the on-disk format is
  identical on every platform and byte-comparable across machines.
* JSON payloads are stored through ``sqlalchemy.JSON``; the content is always
  already redacted when it reaches this layer.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class UTCDateTime(TypeDecorator):
    """Store datetimes as ISO-8601 UTC strings.

    Using a string keeps the on-disk representation stable and portable (SQLite
    would otherwise silently drop the timezone) and keeps exports deterministic.
    """

    impl = String(32)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> str | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")

    def process_result_value(self, value: str | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class Base(DeclarativeBase):
    """Declarative base for all TraceForge tables."""

    type_annotation_map = {dict[str, Any]: JSON, list[str]: JSON}


class WorkspaceRow(Base):
    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    root_path: Mapped[str] = mapped_column(Text, nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    artifacts: Mapped[list["ArtifactRow"]] = relationship(
        back_populates="workspace", cascade="all, delete-orphan"
    )


class ArtifactRow(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        UniqueConstraint("workspace_id", "kind", "sha256", name="uq_artifact_ws_kind_hash"),
        Index("ix_artifact_workspace_kind", "workspace_id", "kind"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    detected_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    storage_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    import_time: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    tool_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    workspace: Mapped[WorkspaceRow] = relationship(back_populates="artifacts")


class AnalysisRunRow(Base):
    __tablename__ = "analysis_runs"
    __table_args__ = (Index("ix_run_workspace_artifact", "workspace_id", "artifact_id"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    analyzer: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    diagnostics_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("artifact_id", "type", "key", name="uq_finding_artifact_type_key"),
        Index("ix_finding_workspace_type", "workspace_id", "type"),
        Index("ix_finding_workspace_artifact", "workspace_id", "artifact_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=True, index=True
    )
    run_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True
    )
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="observed")
    key: Mapped[str | None] = mapped_column(String(256), nullable=True)
    data_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    evidence_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    limitations_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    annotation: Mapped[str | None] = mapped_column(Text, nullable=True)


class ObservationRow(Base):
    __tablename__ = "observations"
    __table_args__ = (
        UniqueConstraint("artifact_id", "kind", "key", name="uq_observation_artifact_kind_key"),
        Index("ix_observation_workspace_kind", "workspace_id", "kind"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    key: Mapped[str] = mapped_column(String(256), nullable=False)
    value_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    source_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


class RelationshipRow(Base):
    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint("workspace_id", "from_id", "kind", "to_id", name="uq_relationship_edge"),
        Index("ix_relationship_workspace_from", "workspace_id", "from_id"),
        Index("ix_relationship_workspace_to", "workspace_id", "to_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    from_type: Mapped[str] = mapped_column(String(32), nullable=False)
    from_id: Mapped[str] = mapped_column(String(128), nullable=False)
    to_type: Mapped[str] = mapped_column(String(32), nullable=False)
    to_id: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="observed")
    evidence_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    limitations_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


class ApiEndpointRow(Base):
    __tablename__ = "api_endpoints"
    __table_args__ = (
        UniqueConstraint("workspace_id", "method", "origin", "path_key", name="uq_endpoint_key"),
        Index("ix_endpoint_workspace", "workspace_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    origin: Mapped[str] = mapped_column(String(256), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    path_key: Mapped[str] = mapped_column(Text, nullable=False)
    host: Mapped[str] = mapped_column(String(256), nullable=False)
    scheme: Mapped[str] = mapped_column(String(16), nullable=False, default="https")
    query_params_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    request_headers_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    response_headers_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    status_codes_json: Mapped[list[int]] = mapped_column(JSON, nullable=False, default=list)
    content_types_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    request_schema_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    response_schema_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    timings_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="observed")
    limitations_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    artifact_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


class EndpointObservationRow(Base):
    """Per-artifact observation of an endpoint (the unit of diffing)."""

    __tablename__ = "endpoint_observations"
    __table_args__ = (
        UniqueConstraint("artifact_id", "method", "origin", "path_key", name="uq_endpoint_obs"),
        Index("ix_endpoint_obs_workspace", "workspace_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id: Mapped[str] = mapped_column(
        ForeignKey("api_endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    origin: Mapped[str] = mapped_column(String(256), nullable=False)
    path_key: Mapped[str] = mapped_column(Text, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status_codes_json: Mapped[list[int]] = mapped_column(JSON, nullable=False, default=list)
    schema_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    param_names_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    content_types_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


class ExportRecordRow(Base):
    __tablename__ = "export_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    path: Mapped[str | None] = mapped_column(Text, nullable=True)
    checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parameters_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


class UserAnnotationRow(Base):
    __tablename__ = "user_annotations"
    __table_args__ = (
        Index("ix_annotation_subject", "workspace_id", "subject_type", "subject_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


__all__ = [
    "AnalysisRunRow",
    "ApiEndpointRow",
    "ArtifactRow",
    "Base",
    "EndpointObservationRow",
    "ExportRecordRow",
    "FindingRow",
    "ObservationRow",
    "RelationshipRow",
    "UserAnnotationRow",
    "UTCDateTime",
    "WorkspaceRow",
]
