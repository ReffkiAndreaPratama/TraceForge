"""Repository layer.

All SQL lives here.  Every statement is expressed with the SQLAlchemy ORM or
with bound parameters - user supplied strings are never interpolated into SQL
text.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from traceforge.domain.models import (
    AnalysisRun,
    ApiEndpoint,
    Artifact,
    Diagnostic,
    EvidenceRef,
    ExportRecord,
    Finding,
    HttpHeader,
    Observation,
    Relationship,
    UserAnnotation,
    utcnow,
)
from traceforge.domain.enums import ArtifactKind, FindingType, RelationKind
from traceforge.storage.models import (
    AnalysisRunRow,
    ApiEndpointRow,
    ArtifactRow,
    EndpointObservationRow,
    ExportRecordRow,
    FindingRow,
    ObservationRow,
    RelationshipRow,
    UserAnnotationRow,
    WorkspaceRow,
)


class WorkspaceRepository:
    """Data access for a single workspace."""

    def __init__(self, session: Session, workspace_id: str) -> None:
        self.session = session
        self.workspace_id = workspace_id

    # ------------------------------------------------------------------
    # workspace
    # ------------------------------------------------------------------
    def get_workspace(self) -> WorkspaceRow | None:
        return self.session.get(WorkspaceRow, self.workspace_id)

    def require_workspace(self) -> WorkspaceRow:
        row = self.get_workspace()
        if row is None:
            from traceforge.errors import WorkspaceNotFoundError

            raise WorkspaceNotFoundError("Workspace not found", detail=self.workspace_id)
        return row

    def touch_workspace(self) -> None:
        row = self.require_workspace()
        row.updated_at = utcnow()
        self.session.flush()

    # ------------------------------------------------------------------
    # artifacts
    # ------------------------------------------------------------------
    def upsert_artifact(
        self,
        *,
        artifact_id: str,
        kind: ArtifactKind,
        display_name: str,
        sha256: str,
        size_bytes: int,
        detected_type: str | None = None,
        storage_path: str | None = None,
        source_path: str | None = None,
        tool_version: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRow:
        existing = self.session.get(ArtifactRow, artifact_id)
        now = utcnow()
        if existing is not None:
            existing.display_name = display_name
            existing.detected_type = detected_type
            existing.storage_path = storage_path
            existing.source_path = source_path
            existing.tool_version = tool_version
            existing.metadata_json = metadata or {}
            existing.import_time = now
            self.session.flush()
            return existing
        row = ArtifactRow(
            id=artifact_id,
            workspace_id=self.workspace_id,
            kind=kind.value,
            display_name=display_name,
            sha256=sha256,
            size_bytes=size_bytes,
            detected_type=detected_type,
            storage_path=storage_path,
            source_path=source_path,
            import_time=now,
            tool_version=tool_version,
            metadata_json=metadata or {},
        )
        self.session.add(row)
        self.session.flush()
        return row

    def list_artifacts(self, kind: ArtifactKind | None = None) -> list[ArtifactRow]:
        stmt = select(ArtifactRow).where(ArtifactRow.workspace_id == self.workspace_id)
        if kind is not None:
            stmt = stmt.where(ArtifactRow.kind == kind.value)
        stmt = stmt.order_by(ArtifactRow.import_time.asc(), ArtifactRow.id.asc())
        return list(self.session.execute(stmt).scalars())

    def get_artifact(self, artifact_id: str) -> ArtifactRow | None:
        row = self.session.get(ArtifactRow, artifact_id)
        if row is None or row.workspace_id != self.workspace_id:
            return None
        return row

    def find_artifact_by_hash(self, kind: ArtifactKind, sha256: str) -> ArtifactRow | None:
        stmt = select(ArtifactRow).where(
            ArtifactRow.workspace_id == self.workspace_id,
            ArtifactRow.kind == kind.value,
            ArtifactRow.sha256 == sha256,
        )
        return self.session.execute(stmt).scalar_one_or_none()

    # ------------------------------------------------------------------
    # analysis runs
    # ------------------------------------------------------------------
    def create_run(
        self,
        *,
        run_id: str,
        artifact_id: str,
        analyzer: str,
        tool_name: str,
        tool_version: str,
        status: str,
        diagnostics: Sequence[Diagnostic] = (),
    ) -> AnalysisRunRow:
        row = AnalysisRunRow(
            id=run_id,
            workspace_id=self.workspace_id,
            artifact_id=artifact_id,
            analyzer=analyzer,
            tool_name=tool_name,
            tool_version=tool_version,
            status=status,
            started_at=utcnow(),
            finished_at=utcnow(),
            diagnostics_json=[d.model_dump(mode="json") for d in diagnostics],
        )
        self.session.add(row)
        self.session.flush()
        return row

    def list_runs(self, artifact_id: str | None = None) -> list[AnalysisRunRow]:
        stmt = select(AnalysisRunRow).where(AnalysisRunRow.workspace_id == self.workspace_id)
        if artifact_id is not None:
            stmt = stmt.where(AnalysisRunRow.artifact_id == artifact_id)
        stmt = stmt.order_by(AnalysisRunRow.started_at.asc())
        return list(self.session.execute(stmt).scalars())

    # ------------------------------------------------------------------
    # findings
    # ------------------------------------------------------------------
    def upsert_finding(self, finding: Finding) -> FindingRow:
        existing = self.session.get(FindingRow, finding.id)
        payload = {
            "summary": finding.summary,
            "method": finding.method,
            "tool_name": finding.tool_name,
            "tool_version": finding.tool_version,
            "confidence": finding.confidence.value,
            "data_json": finding.data,
            "evidence_json": [e.model_dump(mode="json") for e in finding.evidence],
            "limitations_json": list(finding.limitations),
            "run_id": finding.run_id,
            "annotation": finding.annotation,
        }
        if existing is not None:
            for key, value in payload.items():
                setattr(existing, key, value)
            self.session.flush()
            return existing
        row = FindingRow(
            id=finding.id,
            workspace_id=self.workspace_id,
            artifact_id=finding.artifact_id,
            type=finding.type.value,
            key=finding.key,
            created_at=finding.created_at,
            **payload,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def list_findings(
        self,
        *,
        artifact_id: str | None = None,
        finding_type: FindingType | None = None,
        search: str | None = None,
        limit: int | None = None,
    ) -> list[FindingRow]:
        stmt = select(FindingRow).where(FindingRow.workspace_id == self.workspace_id)
        if artifact_id is not None:
            stmt = stmt.where(FindingRow.artifact_id == artifact_id)
        if finding_type is not None:
            stmt = stmt.where(FindingRow.type == finding_type.value)
        if search:
            pattern = f"%{search.lower()}%"
            stmt = stmt.where(
                func.lower(FindingRow.summary).like(pattern)
                | func.lower(FindingRow.key).like(pattern)
            )
        stmt = stmt.order_by(FindingRow.type.asc(), FindingRow.id.asc())
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self.session.execute(stmt).scalars())

    def get_finding(self, finding_id: str) -> FindingRow | None:
        row = self.session.get(FindingRow, finding_id)
        if row is None or row.workspace_id != self.workspace_id:
            return None
        return row

    def delete_findings_for_artifact(self, artifact_id: str) -> int:
        result = self.session.execute(
            delete(FindingRow).where(
                FindingRow.workspace_id == self.workspace_id,
                FindingRow.artifact_id == artifact_id,
            )
        )
        return int(result.rowcount or 0)

    def set_annotation(self, finding_id: str, text: str | None) -> None:
        row = self.get_finding(finding_id)
        if row is None:
            from traceforge.errors import FindingNotFoundError

            raise FindingNotFoundError("Finding not found", detail=finding_id)
        row.annotation = text

    # ------------------------------------------------------------------
    # observations
    # ------------------------------------------------------------------
    def upsert_observation(self, observation: Observation) -> ObservationRow:
        existing = self.session.get(ObservationRow, observation.id)
        if existing is not None:
            existing.value_json = observation.value
            existing.count = observation.count
            existing.source_ref = observation.source_ref
            self.session.flush()
            return existing
        row = ObservationRow(
            id=observation.id,
            workspace_id=self.workspace_id,
            artifact_id=observation.artifact_id,
            kind=observation.kind.value,
            key=observation.key,
            value_json=observation.value,
            count=observation.count,
            source_ref=observation.source_ref,
            created_at=observation.created_at,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def list_observations(
        self, *, artifact_id: str | None = None, kind: str | None = None
    ) -> list[ObservationRow]:
        stmt = select(ObservationRow).where(ObservationRow.workspace_id == self.workspace_id)
        if artifact_id is not None:
            stmt = stmt.where(ObservationRow.artifact_id == artifact_id)
        if kind is not None:
            stmt = stmt.where(ObservationRow.kind == kind)
        stmt = stmt.order_by(ObservationRow.kind.asc(), ObservationRow.id.asc())
        return list(self.session.execute(stmt).scalars())

    # ------------------------------------------------------------------
    # relationships
    # ------------------------------------------------------------------
    def upsert_relationship(self, relationship: Relationship) -> RelationshipRow:
        existing = self.session.get(RelationshipRow, relationship.id)
        payload = {
            "summary": relationship.summary,
            "confidence": relationship.confidence.value,
            "evidence_json": [e.model_dump(mode="json") for e in relationship.evidence],
            "limitations_json": list(relationship.limitations),
            "verified": relationship.verified,
            "schema_version": relationship.schema_version,
        }
        if existing is not None:
            for key, value in payload.items():
                setattr(existing, key, value)
            self.session.flush()
            return existing
        row = RelationshipRow(
            id=relationship.id,
            workspace_id=self.workspace_id,
            from_type=relationship.from_type,
            from_id=relationship.from_id,
            to_type=relationship.to_type,
            to_id=relationship.to_id,
            kind=relationship.kind.value,
            created_at=relationship.created_at,
            **payload,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def list_relationships(self, *, kind: RelationKind | None = None) -> list[RelationshipRow]:
        stmt = select(RelationshipRow).where(RelationshipRow.workspace_id == self.workspace_id)
        if kind is not None:
            stmt = stmt.where(RelationshipRow.kind == kind.value)
        stmt = stmt.order_by(RelationshipRow.kind.asc(), RelationshipRow.id.asc())
        return list(self.session.execute(stmt).scalars())

    def neighbors(self, node_id: str) -> list[RelationshipRow]:
        stmt = select(RelationshipRow).where(
            RelationshipRow.workspace_id == self.workspace_id,
            (RelationshipRow.from_id == node_id) | (RelationshipRow.to_id == node_id),
        )
        return list(self.session.execute(stmt).scalars())

    # ------------------------------------------------------------------
    # endpoints
    # ------------------------------------------------------------------
    def upsert_endpoint(self, endpoint: ApiEndpoint) -> ApiEndpointRow:
        existing = self.session.get(ApiEndpointRow, endpoint.id)
        payload = {
            "path": endpoint.path,
            "host": endpoint.host,
            "scheme": endpoint.scheme,
            "query_params_json": list(endpoint.query_params),
            "request_headers_json": [h.model_dump(mode="json") for h in endpoint.request_headers],
            "response_headers_json": [h.model_dump(mode="json") for h in endpoint.response_headers],
            "status_codes_json": list(endpoint.status_codes),
            "content_types_json": list(endpoint.content_types),
            "request_schema_json": endpoint.request_schema,
            "response_schema_json": endpoint.response_schema,
            "timings_json": endpoint.timings,
            "count": endpoint.count,
            "confidence": endpoint.confidence.value,
            "limitations_json": list(endpoint.limitations),
            "artifact_ids_json": list(endpoint.artifact_ids),
        }
        if existing is not None:
            for key, value in payload.items():
                setattr(existing, key, value)
            existing.last_seen = utcnow()
            self.session.flush()
            return existing
        now = utcnow()
        row = ApiEndpointRow(
            id=endpoint.id,
            workspace_id=self.workspace_id,
            method=endpoint.method,
            origin=endpoint.origin,
            path_key=endpoint.path_key,
            first_seen=now,
            last_seen=now,
            **payload,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def list_endpoints(self) -> list[ApiEndpointRow]:
        stmt = (
            select(ApiEndpointRow)
            .where(ApiEndpointRow.workspace_id == self.workspace_id)
            .order_by(ApiEndpointRow.method.asc(), ApiEndpointRow.origin.asc(), ApiEndpointRow.path_key.asc())
        )
        return list(self.session.execute(stmt).scalars())

    def upsert_endpoint_observation(
        self,
        *,
        observation_id: str,
        artifact_id: str,
        endpoint_id: str,
        method: str,
        origin: str,
        path_key: str,
        count: int,
        status_codes: Sequence[int],
        schema: dict[str, Any] | None,
        param_names: Sequence[str],
        content_types: Sequence[str],
    ) -> EndpointObservationRow:
        existing = self.session.get(EndpointObservationRow, observation_id)
        payload = {
            "count": count,
            "status_codes_json": list(status_codes),
            "schema_json": schema,
            "param_names_json": list(param_names),
            "content_types_json": list(content_types),
        }
        if existing is not None:
            for key, value in payload.items():
                setattr(existing, key, value)
            existing.last_seen = utcnow()
            self.session.flush()
            return existing
        now = utcnow()
        row = EndpointObservationRow(
            id=observation_id,
            workspace_id=self.workspace_id,
            artifact_id=artifact_id,
            endpoint_id=endpoint_id,
            method=method,
            origin=origin,
            path_key=path_key,
            first_seen=now,
            last_seen=now,
            **payload,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def list_endpoint_observations(self, artifact_id: str | None = None) -> list[EndpointObservationRow]:
        stmt = select(EndpointObservationRow).where(
            EndpointObservationRow.workspace_id == self.workspace_id
        )
        if artifact_id is not None:
            stmt = stmt.where(EndpointObservationRow.artifact_id == artifact_id)
        stmt = stmt.order_by(
            EndpointObservationRow.method.asc(),
            EndpointObservationRow.origin.asc(),
            EndpointObservationRow.path_key.asc(),
        )
        return list(self.session.execute(stmt).scalars())

    # ------------------------------------------------------------------
    # exports & annotations
    # ------------------------------------------------------------------
    def create_export_record(
        self,
        *,
        export_id: str,
        kind: str,
        fmt: str,
        path: str | None,
        checksum: str | None,
        parameters: dict[str, Any] | None = None,
    ) -> ExportRecordRow:
        row = ExportRecordRow(
            id=export_id,
            workspace_id=self.workspace_id,
            kind=kind,
            format=fmt,
            path=path,
            checksum=checksum,
            parameters_json=parameters or {},
            created_at=utcnow(),
        )
        self.session.add(row)
        self.session.flush()
        return row

    def list_export_records(self) -> list[ExportRecordRow]:
        stmt = (
            select(ExportRecordRow)
            .where(ExportRecordRow.workspace_id == self.workspace_id)
            .order_by(ExportRecordRow.created_at.asc())
        )
        return list(self.session.execute(stmt).scalars())

    def add_annotation(self, annotation: UserAnnotation) -> UserAnnotationRow:
        row = UserAnnotationRow(
            id=annotation.id,
            workspace_id=self.workspace_id,
            subject_type=annotation.subject_type,
            subject_id=annotation.subject_id,
            body=annotation.body,
            created_at=annotation.created_at,
            updated_at=annotation.updated_at,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def list_annotations(self, subject_id: str | None = None) -> list[UserAnnotationRow]:
        stmt = select(UserAnnotationRow).where(
            UserAnnotationRow.workspace_id == self.workspace_id
        )
        if subject_id is not None:
            stmt = stmt.where(UserAnnotationRow.subject_id == subject_id)
        stmt = stmt.order_by(UserAnnotationRow.created_at.asc())
        return list(self.session.execute(stmt).scalars())

    # ------------------------------------------------------------------
    # statistics
    # ------------------------------------------------------------------
    def counts(self) -> dict[str, int]:
        def _count(model: Any) -> int:
            stmt = select(func.count()).select_from(model).where(
                model.workspace_id == self.workspace_id
            )
            return int(self.session.execute(stmt).scalar_one())

        return {
            "artifacts": _count(ArtifactRow),
            "findings": _count(FindingRow),
            "observations": _count(ObservationRow),
            "relationships": _count(RelationshipRow),
            "endpoints": _count(ApiEndpointRow),
            "runs": _count(AnalysisRunRow),
        }


def row_to_artifact(row: ArtifactRow) -> Artifact:
    return Artifact(
        id=row.id,
        workspace_id=row.workspace_id,
        kind=ArtifactKind(row.kind),
        display_name=row.display_name,
        sha256=row.sha256,
        size_bytes=row.size_bytes,
        detected_type=row.detected_type,
        import_time=row.import_time,
        tool_version=row.tool_version,
        metadata=row.metadata_json or {},
    )


def row_to_finding(row: FindingRow) -> Finding:
    return Finding(
        id=row.id,
        workspace_id=row.workspace_id,
        artifact_id=row.artifact_id,
        run_id=row.run_id,
        type=FindingType(row.type),
        summary=row.summary,
        method=row.method,
        tool_name=row.tool_name,
        tool_version=row.tool_version,
        confidence=row.confidence,  # type: ignore[arg-type]
        key=row.key,
        data=row.data_json or {},
        evidence=tuple(EvidenceRef.model_validate(e) for e in (row.evidence_json or [])),
        limitations=tuple(row.limitations_json or []),
        created_at=row.created_at,
        annotation=row.annotation,
    )


def row_to_observation(row: ObservationRow) -> Observation:
    return Observation(
        id=row.id,
        workspace_id=row.workspace_id,
        artifact_id=row.artifact_id,
        kind=row.kind,  # type: ignore[arg-type]
        key=row.key,
        value=row.value_json or {},
        count=row.count,
        source_ref=row.source_ref,
        created_at=row.created_at,
    )


def row_to_relationship(row: RelationshipRow) -> Relationship:
    return Relationship(
        id=row.id,
        workspace_id=row.workspace_id,
        from_type=row.from_type,
        from_id=row.from_id,
        to_type=row.to_type,
        to_id=row.to_id,
        kind=RelationKind(row.kind),
        summary=row.summary,
        confidence=row.confidence,  # type: ignore[arg-type]
        evidence=tuple(EvidenceRef.model_validate(e) for e in (row.evidence_json or [])),
        limitations=tuple(row.limitations_json or []),
        verified=row.verified,
        schema_version=row.schema_version,
        created_at=row.created_at,
    )


def row_to_endpoint(row: ApiEndpointRow) -> ApiEndpoint:
    return ApiEndpoint(
        id=row.id,
        workspace_id=row.workspace_id,
        method=row.method,
        origin=row.origin,
        path=row.path,
        path_key=row.path_key,
        host=row.host,
        scheme=row.scheme,
        query_params=tuple(row.query_params_json or []),
        request_headers=tuple(HttpHeader.model_validate(h) for h in (row.request_headers_json or [])),
        response_headers=tuple(
            HttpHeader.model_validate(h) for h in (row.response_headers_json or [])
        ),
        status_codes=tuple(row.status_codes_json or []),
        content_types=tuple(row.content_types_json or []),
        request_schema=row.request_schema_json,
        response_schema=row.response_schema_json,
        timings=row.timings_json,
        count=row.count,
        confidence=row.confidence,  # type: ignore[arg-type]
        limitations=tuple(row.limitations_json or []),
        artifact_ids=tuple(row.artifact_ids_json or []),
    )


def row_to_export_record(row: ExportRecordRow) -> ExportRecord:
    return ExportRecord(
        id=row.id,
        workspace_id=row.workspace_id,
        kind=row.kind,
        format=row.format,
        path=row.path,
        checksum=row.checksum,
        parameters=row.parameters_json or {},
        created_at=row.created_at,
    )


def rows_to_iterable(rows: Iterable[Any]) -> list[Any]:
    return list(rows)


def utc_timestamp(value: datetime) -> str:
    """Format a datetime as an ISO-8601 UTC string."""
    from datetime import UTC

    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
