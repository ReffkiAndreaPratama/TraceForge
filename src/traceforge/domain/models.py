"""Typed domain entities.

These Pydantic models are the contract between adapters, the analysis engine
and the exporters.  They are deliberately free of persistence concerns: the
SQLAlchemy models in :mod:`traceforge.storage.models` are separate and are
converted to/from these dataclasses at the boundary.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from traceforge.domain.enums import (
    ArtifactKind,
    BinaryFormat,
    Confidence,
    DiagnosticLevel,
    FindingType,
    ObservationKind,
    RelationKind,
)

ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(UTC)


class TraceForgeModel(BaseModel):
    """Base model: reject unknown keys so typos in adapter output fail loudly."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class Diagnostic(TraceForgeModel):
    """A structured message emitted by an adapter or analyzer."""

    level: DiagnosticLevel = DiagnosticLevel.WARNING
    code: str = "unknown"
    message: str
    detail: str | None = None
    source: str | None = Field(
        default=None, description="Optional pointer into the artifact, e.g. 'entry[12]'"
    )

    def render(self) -> str:
        base = f"[{self.level.value}] {self.code}: {self.message}"
        return f"{base} ({self.detail})" if self.detail else base


class Artifact(TraceForgeModel):
    """A file ingested into a workspace."""

    id: str
    workspace_id: str
    kind: ArtifactKind
    display_name: str
    sha256: str
    size_bytes: int
    detected_type: str | None = None
    import_time: datetime = Field(default_factory=utcnow)
    tool_version: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnalysisRun(TraceForgeModel):
    """One invocation of one analyzer over one artifact."""

    id: str
    workspace_id: str
    artifact_id: str
    analyzer: str
    tool_name: str
    tool_version: str
    status: str
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    diagnostics: tuple[Diagnostic, ...] = ()


class EvidenceRef(TraceForgeModel):
    """A pointer to the concrete place a claim was derived from."""

    kind: str = Field(description="observation kind or 'artifact'")
    ref: str = Field(description="Human readable locator, e.g. 'entry[12].request.url'")
    detail: str | None = None
    excerpt: str | None = Field(
        default=None, description="Short, already-redacted excerpt of the evidence"
    )


class Finding(TraceForgeModel):
    """A single analysed result, always traceable back to its source."""

    id: str
    workspace_id: str
    artifact_id: str | None = None
    run_id: str | None = None
    type: FindingType
    summary: str
    method: str = Field(description="Name of the detection method or rule")
    tool_name: str
    tool_version: str
    confidence: Confidence = Confidence.OBSERVED
    key: str | None = Field(default=None, description="Stable dedupe key within the artifact")
    data: dict[str, Any] = Field(default_factory=dict)
    evidence: tuple[EvidenceRef, ...] = ()
    limitations: tuple[str, ...] = ()
    created_at: datetime = Field(default_factory=utcnow)
    annotation: str | None = None


class Observation(TraceForgeModel):
    """A raw, located piece of evidence extracted from an artifact."""

    id: str
    workspace_id: str
    artifact_id: str
    kind: ObservationKind
    key: str
    value: dict[str, Any] = Field(default_factory=dict)
    count: int = 1
    source_ref: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


class Relationship(TraceForgeModel):
    """A directed, evidence-backed edge in the graph."""

    id: str
    workspace_id: str
    from_type: str
    from_id: str
    to_type: str
    to_id: str
    kind: RelationKind
    summary: str
    confidence: Confidence = Confidence.OBSERVED
    evidence: tuple[EvidenceRef, ...] = ()
    limitations: tuple[str, ...] = ()
    verified: bool = False
    schema_version: int = 1
    created_at: datetime = Field(default_factory=utcnow)


class HttpHeader(TraceForgeModel):
    name: str
    value: str
    redacted: bool = False


class ApiEndpoint(TraceForgeModel):
    """A normalised, grouped view of observed HTTP traffic."""

    id: str
    workspace_id: str
    method: str
    origin: str
    path: str
    path_key: str = Field(description="Normalised path with inferred parameters replaced")
    host: str
    scheme: str = "https"
    query_params: tuple[str, ...] = ()
    request_headers: tuple[HttpHeader, ...] = ()
    response_headers: tuple[HttpHeader, ...] = ()
    status_codes: tuple[int, ...] = ()
    content_types: tuple[str, ...] = ()
    request_schema: dict[str, Any] | None = None
    response_schema: dict[str, Any] | None = None
    timings: dict[str, Any] | None = None
    count: int = 1
    confidence: Confidence = Confidence.OBSERVED
    limitations: tuple[str, ...] = ()
    artifact_ids: tuple[str, ...] = ()


class ExportRecord(TraceForgeModel):
    """Audit trail of every export produced from a workspace."""

    id: str
    workspace_id: str
    kind: str
    format: str
    path: str | None = None
    checksum: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class UserAnnotation(TraceForgeModel):
    """A user authored note attached to any graph node."""

    id: str
    workspace_id: str
    subject_type: str
    subject_id: str
    body: str
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class BinarySection(TraceForgeModel):
    """A section (or segment) of a binary container.

    ``characteristics`` keeps the raw flag bitmask exactly as the container
    defines it; ``flags`` is the human readable decoding of that bitmask.
    """

    name: str
    virtual_address: int | None = None
    virtual_size: int | None = None
    raw_size: int | None = None
    entropy: float | None = None
    characteristics: int | None = None
    flags: str | None = None


class BinaryInfo(TraceForgeModel):
    """Result of fingerprinting a binary. Optional fields mean *unknown*."""

    format: BinaryFormat
    sha256: str
    size_bytes: int
    architecture: str | None = None
    endianness: str | None = None
    is_executable: bool | None = None
    is_stripped: bool | None = None
    subsystem: str | None = None
    compiler: str | None = None
    entry_point: str | None = None
    sections: tuple[BinarySection, ...] = ()
    imports: tuple[str, ...] = ()
    exports: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    libraries: tuple[str, ...] = ()
    strings: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    parser: str = "none"
    parser_version: str | None = None

    @field_validator("sections")
    @classmethod
    def _limit_sections(cls, value: tuple[BinarySection, ...]) -> tuple[BinarySection, ...]:
        return value
