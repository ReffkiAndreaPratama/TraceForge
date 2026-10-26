"""Analysis services.

These functions perform the actual work: ingest an artefact, run an adapter,
turn the results into findings with provenance, persist everything
transactionally and refresh the evidence graph.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from traceforge.adapters.binary.fingerprint import fingerprint
from traceforge.adapters.http.har import HarCapture, parse_har_file
from traceforge.analysis.diff import DiffResult, EndpointSnapshot, diff_snapshots
from traceforge.analysis.paths import normalize_path
from traceforge.analysis.schema import infer_schema, parse_json_samples
from traceforge.config import Settings
from traceforge.domain.enums import (
    ArtifactKind,
    Confidence,
    DiagnosticLevel,
    FindingType,
    ObservationKind,
    RelationKind,
    RunStatus,
)
from traceforge.domain.models import (
    ApiEndpoint,
    Diagnostic,
    EvidenceRef,
    Finding,
    HttpHeader,
    Observation,
)
from traceforge.errors import ArtifactNotFoundError
from traceforge.graph.builder import build_relationships
from traceforge.ids import (
    artifact_id as make_artifact_id,
)
from traceforge.ids import (
    endpoint_id as make_endpoint_id,
)
from traceforge.ids import (
    finding_id as make_finding_id,
)
from traceforge.ids import (
    observation_id as make_observation_id,
)
from traceforge.ids import run_id as make_run_id
from traceforge.ingestion.loader import ingest_file
from traceforge.security.redaction import Redactor
from traceforge.services.workspace import Workspace
from traceforge.storage.repository import WorkspaceRepository
from traceforge.version import __version__

#: Maximum number of JSON samples retained per endpoint for schema inference.
MAX_SCHEMA_SAMPLES = 100


@dataclass(slots=True)
class AnalysisOutcome:
    """The result of an analysis run."""

    artifact_id: str
    run_id: str
    status: str
    findings: int = 0
    observations: int = 0
    endpoints: int = 0
    relationships: int = 0
    diagnostics: list[Diagnostic] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "run_id": self.run_id,
            "status": self.status,
            "findings": self.findings,
            "observations": self.observations,
            "endpoints": self.endpoints,
            "relationships": self.relationships,
            "diagnostics": [d.model_dump(mode="json") for d in self.diagnostics],
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(UTC)


def _artifact_display(path: Path) -> str:
    from traceforge.security.paths import sanitize_display_name

    return sanitize_display_name(path.name)


def _origin_of(url: str) -> tuple[str, str, str]:
    """Return ``(origin, host, scheme)`` for a URL."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ("", "", "")
    scheme = parts.scheme or ""
    host = parts.netloc or ""
    if not host:
        return ("", host, scheme)
    return (f"{scheme}://{host}" if scheme else host, host, scheme)


def rebuild_graph(repo: WorkspaceRepository) -> int:
    """Recreate every relationship for a workspace. Returns the edge count."""
    relationships = build_relationships(repo)
    for relationship in relationships:
        repo.upsert_relationship(relationship)
    return len(relationships)


# ---------------------------------------------------------------------------
# binary analysis
# ---------------------------------------------------------------------------
def analyze_binary(
    workspace: Workspace,
    path: str | Path,
    *,
    settings: Settings | None = None,
) -> AnalysisOutcome:
    """Fingerprint a binary and store the resulting findings.

    The file is only read; it is never executed.
    """
    settings = settings or Settings()
    source = Path(path).expanduser()
    limits = settings.limits
    redactor = Redactor(settings.redaction)

    outcome = AnalysisOutcome(artifact_id="", run_id="", status=RunStatus.FAILED)

    with workspace.session_scope() as session:
        repo = workspace.repository(session)
        art_id = make_artifact_id(workspace.id, ArtifactKind.BINARY.value, _pending_hash(source))
        ingested = ingest_file(
            source,
            workspace_root=workspace.root,
            artifact_id=art_id,
            limits=limits,
            kind=ArtifactKind.BINARY,
        )
        art_id = make_artifact_id(workspace.id, ArtifactKind.BINARY.value, ingested.sha256)

        artifact_row = repo.upsert_artifact(
            artifact_id=art_id,
            kind=ArtifactKind.BINARY,
            display_name=ingested.display_name,
            sha256=ingested.sha256,
            size_bytes=ingested.size_bytes,
            detected_type=ingested.detected_type,
            storage_path=str(ingested.stored_path) if ingested.stored_path else None,
            source_path=str(ingested.source_path),
            tool_version=__version__,
            metadata={
                "imported_as": "binary",
                "parser": "traceforge.binary",
            },
        )

        result = fingerprint(ingested.source_path, limits=limits)
        diagnostics = list(result.diagnostics)

        run = repo.create_run(
            run_id=make_run_id(
                artifact_row.id, "binary.fingerprint", __version__, _now().isoformat()
            ),
            artifact_id=artifact_row.id,
            analyzer="binary.fingerprint",
            tool_name="traceforge",
            tool_version=__version__,
            status=RunStatus.SUCCESS,
            diagnostics=diagnostics,
        )

        info = result.info
        findings = _binary_findings(artifact_row.id, run.id, info, result, redactor, limits)
        stored = 0
        for finding in findings:
            if stored >= limits.max_findings_per_run:
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.WARNING,
                        code="analysis.findings_truncated",
                        message=(
                            "The number of findings exceeded the configured limit; "
                            "some results were not persisted."
                        ),
                        detail=f"limit={limits.max_findings_per_run}",
                    )
                )
                break
            repo.upsert_finding(finding)
            stored += 1

        observations = 0
        for item in result.strings:
            observation = Observation(
                id=make_observation_id(artifact_row.id, ObservationKind.BINARY_STRING.value, str(item.offset)),
                workspace_id=workspace.id,
                artifact_id=artifact_row.id,
                kind=ObservationKind.BINARY_STRING,
                key=f"string@{item.offset}",
                value={
                    "text": redactor.redact_text(item.text).value,
                    "encoding": item.encoding,
                    "offset": item.offset,
                },
                source_ref=f"offset:{item.offset}",
            )
            repo.upsert_observation(observation)
            observations += 1

        edge_count = rebuild_graph(repo)
        repo.touch_workspace()

        outcome.artifact_id = artifact_row.id
        outcome.run_id = run.id
        outcome.status = RunStatus.SUCCESS
        outcome.findings = stored
        outcome.observations = observations
        outcome.relationships = edge_count
        outcome.diagnostics = diagnostics
        outcome.detail = {
            "format": info.format.value,
            "architecture": info.architecture,
            "sha256": info.sha256,
            "size_bytes": info.size_bytes,
            "sections": len(info.sections),
            "imports": len(info.imports),
            "exports": len(info.exports),
            "strings": len(info.strings),
            "urls": len(info.urls),
            "domains": len(info.domains),
            "parser": info.parser,
            "parser_version": info.parser_version,
        }

    return outcome


def _pending_hash(source: Path) -> str:
    """A cheap placeholder hash used before the real hash is known."""
    from traceforge.security.validators import hash_file

    try:
        return hash_file(source)[0]
    except OSError:
        return "unknown"


def _binary_findings(
    artifact_id: str,
    run_id: str,
    info,
    result,
    redactor: Redactor,
    limits,
) -> list[Finding]:
    findings: list[Finding] = []
    now = _now()

    def _make(
        finding_type: FindingType,
        summary: str,
        key: str,
        data: dict[str, Any],
        *,
        confidence: Confidence = Confidence.OBSERVED,
        method: str = "binary.fingerprint",
        evidence: tuple[EvidenceRef, ...] = (),
        limitations: tuple[str, ...] = (),
    ) -> Finding:
        return Finding(
            id=make_finding_id(artifact_id, finding_type.value, key),
            workspace_id="",
            artifact_id=artifact_id,
            run_id=run_id,
            type=finding_type,
            summary=summary,
            method=method,
            tool_name="traceforge",
            tool_version=__version__,
            confidence=confidence,
            key=key,
            data=data,
            evidence=evidence,
            limitations=limitations,
            created_at=now,
        )

    findings.append(
        _make(
            FindingType.BINARY_HASH,
            f"SHA-256 {info.sha256}",
            "sha256",
            {"sha256": info.sha256, "size_bytes": info.size_bytes},
            method="hashlib.sha256",
            limitations=("The hash identifies the file; it says nothing about its behaviour.",),
        )
    )

    findings.append(
        _make(
            FindingType.BINARY_METADATA,
            f"{info.format.value.upper()} binary, {info.architecture or 'unknown architecture'}",
            "metadata",
            {
                "format": info.format.value,
                "architecture": info.architecture,
                "endianness": info.endianness,
                "is_executable": info.is_executable,
                "is_stripped": info.is_stripped,
                "subsystem": info.subsystem,
                "compiler": info.compiler,
                "entry_point": info.entry_point,
                "parser": info.parser,
                "parser_version": info.parser_version,
            },
            method="binary.fingerprint",
            limitations=(
                "Structural metadata only; the file was not executed and its behaviour "
                "was not observed.",
            ),
        )
    )

    for section in info.sections:
        findings.append(
            _make(
                FindingType.BINARY_SECTION,
                f"Section '{section.name}'",
                f"section:{section.name}",
                section.model_dump(mode="json"),
                method="binary.sections",
            )
        )

    for index, imported in enumerate(info.imports):
        findings.append(
            _make(
                FindingType.BINARY_IMPORT,
                f"Imports {imported}",
                f"import:{index}",
                {"symbol": imported},
                method="binary.imports",
            )
        )

    for index, exported in enumerate(info.exports):
        findings.append(
            _make(
                FindingType.BINARY_EXPORT,
                f"Exports {exported}",
                f"export:{index}",
                {"symbol": exported},
                method="binary.exports",
            )
        )

    for index, symbol in enumerate(info.symbols[: limits.max_findings_per_run]):
        findings.append(
            _make(
                FindingType.BINARY_SYMBOL,
                f"Symbol {symbol}",
                f"symbol:{index}:{symbol}",
                {"symbol": symbol},
                method="binary.symbols",
            )
        )

    for index, text in enumerate(info.strings):
        redacted = redactor.redact_text(text)
        findings.append(
            _make(
                FindingType.BINARY_STRING,
                f"String: {redacted.value[:120]}",
                f"string:{index}",
                {
                    "value": redacted.value,
                    "encoding": "auto",
                    "index": index,
                },
                method="binary.strings",
                evidence=(
                    EvidenceRef(kind="observation", ref=f"artifact:{artifact_id}", detail="extracted string"),
                ),
                limitations=(
                    "A string is a literal occurrence in the file. Its presence does not "
                    "imply that the code uses it at runtime.",
                ),
            )
        )

    for domain in info.domains:
        findings.append(
            _make(
                FindingType.BINARY_DOMAIN,
                f"Domain string: {domain}",
                f"domain:{domain}",
                {"value": domain},
                method="binary.indicators",
                confidence=Confidence.OBSERVED,
                limitations=(
                    "A domain string inside a binary is not evidence that the binary "
                    "contacts that host.",
                ),
            )
        )

    for url in info.urls:
        findings.append(
            _make(
                FindingType.BINARY_URL_LIKE,
                f"URL string: {url}",
                f"url:{url}",
                {"value": url},
                method="binary.indicators",
                limitations=(
                    "A URL string inside a binary is not evidence that the binary performs "
                    "requests to it.",
                ),
            )
        )

    for diagnostic in info.diagnostics:
        findings.append(
            _make(
                FindingType.PARSER_WARNING
                if diagnostic.level != DiagnosticLevel.ERROR
                else FindingType.PARSER_ERROR,
                diagnostic.message,
                f"diagnostic:{diagnostic.code}:{diagnostic.detail or ''}",
                diagnostic.model_dump(mode="json"),
                method="binary.diagnostics",
                confidence=Confidence.OBSERVED,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# HAR analysis
# ---------------------------------------------------------------------------
def import_har(
    workspace: Workspace,
    path: str | Path,
    *,
    settings: Settings | None = None,
) -> AnalysisOutcome:
    """Import a HAR capture, build the endpoint inventory and store findings."""
    settings = settings or Settings()
    limits = settings.limits
    redactor = Redactor(settings.redaction)
    source = Path(path).expanduser()

    outcome = AnalysisOutcome(artifact_id="", run_id="", status=RunStatus.FAILED)

    with workspace.session_scope() as session:
        repo = workspace.repository(session)
        art_id = make_artifact_id(workspace.id, ArtifactKind.HAR.value, _pending_hash(source))
        ingested = ingest_file(
            source,
            workspace_root=workspace.root,
            artifact_id=art_id,
            limits=limits,
            kind=ArtifactKind.HAR,
        )
        art_id = make_artifact_id(workspace.id, ArtifactKind.HAR.value, ingested.sha256)

        artifact_row = repo.upsert_artifact(
            artifact_id=art_id,
            kind=ArtifactKind.HAR,
            display_name=ingested.display_name,
            sha256=ingested.sha256,
            size_bytes=ingested.size_bytes,
            detected_type="har",
            storage_path=str(ingested.stored_path) if ingested.stored_path else None,
            source_path=str(ingested.source_path),
            tool_version=__version__,
            metadata={
                "imported_as": "har",
                "har_version": "1.2",
            },
        )

        capture = parse_har_file(ingested.source_path, limits=limits, redactor=redactor)
        diagnostics = list(capture.diagnostics)

        run = repo.create_run(
            run_id=make_run_id(artifact_row.id, "http.har", __version__, _now().isoformat()),
            artifact_id=artifact_row.id,
            analyzer="http.har",
            tool_name="traceforge",
            tool_version=__version__,
            status=RunStatus.SUCCESS,
            diagnostics=diagnostics,
        )

        endpoints, observations, findings = _har_analysis(
            workspace, repo, artifact_row.id, run.id, capture, limits
        )

        stored_findings = 0
        for finding in findings:
            if stored_findings >= limits.max_findings_per_run:
                break
            repo.upsert_finding(finding)
            stored_findings += 1

        stored_observations = 0
        for observation in observations:
            repo.upsert_observation(observation)
            stored_observations += 1

        edge_count = rebuild_graph(repo)
        repo.touch_workspace()

        outcome.artifact_id = artifact_row.id
        outcome.run_id = run.id
        outcome.status = RunStatus.SUCCESS
        outcome.findings = stored_findings
        outcome.observations = stored_observations
        outcome.endpoints = len(endpoints)
        outcome.relationships = edge_count
        outcome.diagnostics = diagnostics
        outcome.detail = {
            "har_version": capture.version,
            "creator": capture.creator,
            "entries": len(capture.entries),
            "endpoints": len(endpoints),
            "hosts": sorted({e.host for e in endpoints if e.host}),
        }

    return outcome


@dataclass
class _EndpointAccumulator:
    """Accumulates the observations that belong to one normalised endpoint."""

    method: str
    origin: str
    host: str
    scheme: str
    path_key: str
    example_path: str
    count: int = 0
    query_params: set[str] = field(default_factory=set)
    status_codes: set[int] = field(default_factory=set)
    content_types: set[str] = field(default_factory=set)
    request_headers: dict[str, tuple[str, bool]] = field(default_factory=dict)
    response_headers: dict[str, tuple[str, bool]] = field(default_factory=dict)
    request_samples: list[str] = field(default_factory=list)
    response_samples: list[str] = field(default_factory=list)
    timings: dict[str, Any] | None = None
    parameter_rules: list[dict[str, Any]] = field(default_factory=list)
    limitations: set[str] = field(default_factory=set)

    def add(self, entry, limits) -> None:
        self.count += 1
        self.query_params.update(param.name for param in entry.request.query_string)
        if entry.response.status:
            self.status_codes.add(entry.response.status)
        if entry.response.content and entry.response.content.mime_type:
            self.content_types.add(entry.response.content.mime_type.split(";")[0].strip())
        for header in entry.request.headers:
            self.request_headers.setdefault(header.name.lower(), (header.value, header.redacted))
        for header in entry.response.headers:
            self.response_headers.setdefault(header.name.lower(), (header.value, header.redacted))
        if entry.request.post_data and entry.request.post_data.text:
            if len(self.request_samples) < MAX_SCHEMA_SAMPLES:
                self.request_samples.append(entry.request.post_data.text)
        if entry.response.content and entry.response.content.text:
            if len(self.response_samples) < MAX_SCHEMA_SAMPLES:
                self.response_samples.append(entry.response.content.text)
        if self.timings is None and entry.timings is not None:
            self.timings = entry.timings.as_dict()


def _har_analysis(
    workspace: Workspace,
    repo: WorkspaceRepository,
    artifact_id: str,
    run_id: str,
    capture: HarCapture,
    limits,
) -> tuple[list[ApiEndpoint], list[Observation], list[Finding]]:
    """Turn a parsed capture into endpoints, observations and findings."""
    accumulators: dict[str, _EndpointAccumulator] = {}
    observations: list[Observation] = []
    now = _now()

    for entry in capture.entries:
        origin, host, scheme = _origin_of(entry.request.url)
        normalized = normalize_path(entry.request.url)
        key = f"{entry.request.method.upper()} {origin}{normalized.path_key}"

        accumulator = accumulators.get(key)
        if accumulator is None:
            if len(accumulators) >= limits.max_endpoints_per_artifact:
                continue
            accumulator = _EndpointAccumulator(
                method=entry.request.method.upper(),
                origin=origin,
                host=host,
                scheme=scheme or "https",
                path_key=normalized.path_key,
                example_path=normalized.path,
                parameter_rules=[p.as_dict() for p in normalized.parameters],
            )
            accumulators[key] = accumulator
        if normalized.parameters:
            accumulator.limitations.add(
                "Path parameters were inferred by a heuristic and may not match the server's "
                "actual routing."
            )
        accumulator.add(entry, limits)

        observation = Observation(
            id=make_observation_id(
                artifact_id, ObservationKind.HTTP_REQUEST.value, str(entry.index)
            ),
            workspace_id=workspace.id,
            artifact_id=artifact_id,
            kind=ObservationKind.HTTP_REQUEST,
            key=f"entry[{entry.index}]",
            value={
                "method": entry.request.method.upper(),
                "url": entry.request.url,
                "origin": origin,
                "path": normalized.original,
                "path_key": normalized.path_key,
                "status": entry.response.status,
                "content_type": (
                    entry.response.content.mime_type if entry.response.content else None
                ),
                "request_content_type": (
                    entry.request.post_data.mime_type if entry.request.post_data else None
                ),
                "query_params": [p.name for p in entry.request.query_string],
                "time_ms": entry.time_ms,
                "server_ip": entry.server_ip,
            },
            source_ref=f"entry[{entry.index}]",
        )
        observations.append(observation)

    endpoints: list[ApiEndpoint] = []
    findings: list[Finding] = []

    for key in sorted(accumulators):
        accumulator = accumulators[key]
        endpoint_id = make_endpoint_id(
            workspace.id, accumulator.method, accumulator.origin, accumulator.path_key
        )

        request_samples, request_errors = parse_json_samples(
            accumulator.request_samples, limits=limits
        )
        response_samples, response_errors = parse_json_samples(
            accumulator.response_samples, limits=limits
        )
        request_schema = infer_schema(request_samples, limits=limits)
        response_schema = infer_schema(response_samples, limits=limits)

        endpoint = ApiEndpoint(
            id=endpoint_id,
            workspace_id=workspace.id,
            method=accumulator.method,
            origin=accumulator.origin,
            path=accumulator.example_path,
            path_key=accumulator.path_key,
            host=accumulator.host,
            scheme=accumulator.scheme,
            query_params=tuple(sorted(accumulator.query_params)),
            request_headers=tuple(
                HttpHeader(name=name, value=value, redacted=redacted)
                for name, (value, redacted) in sorted(accumulator.request_headers.items())
            ),
            response_headers=tuple(
                HttpHeader(name=name, value=value, redacted=redacted)
                for name, (value, redacted) in sorted(accumulator.response_headers.items())
            ),
            status_codes=tuple(sorted(accumulator.status_codes)),
            content_types=tuple(sorted(accumulator.content_types)),
            request_schema=request_schema,
            response_schema=response_schema,
            timings=accumulator.timings,
            count=accumulator.count,
            confidence=Confidence.INFERRED if accumulator.parameter_rules else Confidence.OBSERVED,
            limitations=tuple(sorted(accumulator.limitations)),
            artifact_ids=(artifact_id,),
        )
        endpoints.append(endpoint)

        repo.upsert_endpoint(endpoint)
        repo.upsert_endpoint_observation(
            observation_id=make_observation_id(
                artifact_id, "http.endpoint_observation", endpoint_id
            ),
            artifact_id=artifact_id,
            endpoint_id=endpoint_id,
            method=accumulator.method,
            origin=accumulator.origin,
            path_key=accumulator.path_key,
            count=accumulator.count,
            status_codes=tuple(sorted(accumulator.status_codes)),
            schema=response_schema,
            param_names=tuple(sorted(accumulator.query_params)),
            content_types=tuple(sorted(accumulator.content_types)),
        )

        findings.append(
            Finding(
                id=make_finding_id(artifact_id, FindingType.HTTP_ENDPOINT.value, key),
                workspace_id=workspace.id,
                artifact_id=artifact_id,
                run_id=run_id,
                type=FindingType.HTTP_ENDPOINT,
                summary=f"{accumulator.method} {accumulator.origin}{accumulator.path_key}",
                method="http.har",
                tool_name="traceforge",
                tool_version=__version__,
                confidence=endpoint.confidence,
                key=key,
                data={
                    "method": accumulator.method,
                    "origin": accumulator.origin,
                    "path": accumulator.example_path,
                    "path_key": accumulator.path_key,
                    "host": accumulator.host,
                    "query_params": sorted(accumulator.query_params),
                    "status_codes": sorted(accumulator.status_codes),
                    "content_types": sorted(accumulator.content_types),
                    "count": accumulator.count,
                    "path_parameters": accumulator.parameter_rules,
                    "request_schema": request_schema,
                    "response_schema": response_schema,
                },
                evidence=(
                    EvidenceRef(
                        kind="observation",
                        ref=f"artifact:{artifact_id}",
                        detail=f"{accumulator.count} observed request(s) grouped by method, "
                        "origin and normalised path",
                    ),
                ),
                limitations=endpoint.limitations
                + (
                    "The endpoint inventory reflects only the traffic that was captured.",
                ),
                created_at=now,
            )
        )

        if accumulator.host:
            findings.append(
                Finding(
                    id=make_finding_id(artifact_id, FindingType.HTTP_HOST.value, accumulator.host),
                    workspace_id=workspace.id,
                    artifact_id=artifact_id,
                    run_id=run_id,
                    type=FindingType.HTTP_HOST,
                    summary=f"Observed host {accumulator.host}",
                    method="http.har",
                    tool_name="traceforge",
                    tool_version=__version__,
                    confidence=Confidence.OBSERVED,
                    key=accumulator.host,
                    data={"host": accumulator.host, "origin": accumulator.origin},
                    limitations=("A host is observed in traffic; ownership was not verified.",),
                    created_at=now,
                )
            )

        for status in sorted(accumulator.status_codes):
            findings.append(
                Finding(
                    id=make_finding_id(
                        artifact_id, FindingType.HTTP_STATUS.value, f"{key}:{status}"
                    ),
                    workspace_id=workspace.id,
                    artifact_id=artifact_id,
                    run_id=run_id,
                    type=FindingType.HTTP_STATUS,
                    summary=f"{accumulator.method} {accumulator.path_key} returned {status}",
                    method="http.har",
                    tool_name="traceforge",
                    tool_version=__version__,
                    confidence=Confidence.OBSERVED,
                    key=f"{key}:{status}",
                    data={"status": status, "endpoint": key},
                    created_at=now,
                )
            )

        for param in sorted(accumulator.query_params):
            findings.append(
                Finding(
                    id=make_finding_id(
                        artifact_id, FindingType.HTTP_PARAMETER.value, f"{key}:{param}"
                    ),
                    workspace_id=workspace.id,
                    artifact_id=artifact_id,
                    run_id=run_id,
                    type=FindingType.HTTP_PARAMETER,
                    summary=f"Query parameter '{param}' on {accumulator.method} {accumulator.path_key}",
                    method="http.har",
                    tool_name="traceforge",
                    tool_version=__version__,
                    confidence=Confidence.OBSERVED,
                    key=f"{key}:{param}",
                    data={"parameter": param, "endpoint": key},
                    limitations=("Parameter values are redacted; only names are reported.",),
                    created_at=now,
                )
            )

        if request_errors or response_errors:
            findings.append(
                Finding(
                    id=make_finding_id(
                        artifact_id, FindingType.PARSER_WARNING.value, f"{key}:body"
                    ),
                    workspace_id=workspace.id,
                    artifact_id=artifact_id,
                    run_id=run_id,
                    type=FindingType.PARSER_WARNING,
                    summary=(
                        f"{len(request_errors) + len(response_errors)} body/bodies could not be "
                        f"parsed as JSON for {accumulator.method} {accumulator.path_key}"
                    ),
                    method="http.schema",
                    tool_name="traceforge",
                    tool_version=__version__,
                    confidence=Confidence.OBSERVED,
                    key=f"{key}:body",
                    data={"request_errors": request_errors[:5], "response_errors": response_errors[:5]},
                    created_at=now,
                )
            )

    for diagnostic in capture.diagnostics:
        findings.append(
            Finding(
                id=make_finding_id(
                    artifact_id, FindingType.PARSER_WARNING.value, f"{diagnostic.code}"
                ),
                workspace_id=workspace.id,
                artifact_id=artifact_id,
                run_id=run_id,
                type=FindingType.PARSER_WARNING,
                summary=diagnostic.message,
                method="http.har",
                tool_name="traceforge",
                tool_version=__version__,
                confidence=Confidence.OBSERVED,
                key=diagnostic.code,
                data=diagnostic.model_dump(mode="json"),
                created_at=now,
            )
        )

    return endpoints, observations, findings


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------
def _snapshots_for_artifact(
    repo: WorkspaceRepository, artifact_id: str
) -> list[EndpointSnapshot]:
    snapshots: list[EndpointSnapshot] = []
    for row in repo.list_endpoint_observations(artifact_id=artifact_id):
        snapshots.append(
            EndpointSnapshot(
                method=row.method,
                origin=row.origin,
                path_key=row.path_key,
                count=row.count,
                status_codes=tuple(row.status_codes_json or []),
                param_names=tuple(row.param_names_json or []),
                content_types=tuple(row.content_types_json or []),
                schema=row.schema_json,
                artifact_id=artifact_id,
            )
        )
    return snapshots


def diff_artifacts(
    workspace: Workspace,
    artifact_a: str,
    artifact_b: str,
    *,
    settings: Settings | None = None,
    persist: bool = True,
) -> DiffResult:
    """Compare two imported traffic captures inside a workspace."""
    with workspace.session_scope() as session:
        repo = workspace.repository(session)
        row_a = repo.get_artifact(artifact_a)
        row_b = repo.get_artifact(artifact_b)
        if row_a is None:
            raise ArtifactNotFoundError("Capture A not found", detail=artifact_a)
        if row_b is None:
            raise ArtifactNotFoundError("Capture B not found", detail=artifact_b)

        left = _snapshots_for_artifact(repo, artifact_a)
        right = _snapshots_for_artifact(repo, artifact_b)
        result = diff_snapshots(
            left, right, left_label=row_a.display_name, right_label=row_b.display_name
        )

        if persist:
            _persist_diff(repo, workspace, artifact_a, artifact_b, result)

    return result


def _persist_diff(
    repo: WorkspaceRepository,
    workspace: Workspace,
    artifact_a: str,
    artifact_b: str,
    result: DiffResult,
) -> None:
    """Store the diff as findings so it becomes part of the evidence graph."""
    now = _now()
    run_id = make_run_id(artifact_a, "api.diff", __version__, now.isoformat())

    # The findings reference the run, so the run has to exist first.
    repo.create_run(
        run_id=run_id,
        artifact_id=artifact_a,
        analyzer="api.diff",
        tool_name="traceforge",
        tool_version=__version__,
        status=RunStatus.SUCCESS,
    )

    for snapshot in result.added:
        repo.upsert_finding(
            Finding(
                id=make_finding_id(
                    artifact_b, FindingType.DIFF_ENDPOINT_ADDED.value, snapshot.key
                ),
                workspace_id=workspace.id,
                artifact_id=artifact_b,
                run_id=run_id,
                type=FindingType.DIFF_ENDPOINT_ADDED,
                summary=f"Endpoint added: {snapshot.key}",
                method="api.diff",
                tool_name="traceforge",
                tool_version=__version__,
                confidence=Confidence.OBSERVED,
                key=snapshot.key,
                data={"endpoint": snapshot.key, "added": True},
                evidence=(
                    EvidenceRef(kind="observation", ref=f"artifact:{artifact_b}"),
                ),
                limitations=(
                    "The endpoint is absent from capture A; this may mean it is new, or that "
                    "capture A simply did not exercise it.",
                ),
                created_at=now,
            )
        )

    for snapshot in result.removed:
        repo.upsert_finding(
            Finding(
                id=make_finding_id(
                    artifact_b, FindingType.DIFF_ENDPOINT_REMOVED.value, snapshot.key
                ),
                workspace_id=workspace.id,
                artifact_id=artifact_b,
                run_id=run_id,
                type=FindingType.DIFF_ENDPOINT_REMOVED,
                summary=f"Endpoint removed: {snapshot.key}",
                method="api.diff",
                tool_name="traceforge",
                tool_version=__version__,
                confidence=Confidence.OBSERVED,
                key=snapshot.key,
                data={"endpoint": snapshot.key, "removed": True},
                evidence=(EvidenceRef(kind="observation", ref=f"artifact:{artifact_a}"),),
                limitations=(
                    "The endpoint is absent from capture B; it may have been removed, or "
                    "capture B may not have exercised it.",
                ),
                created_at=now,
            )
        )

    for change in result.changed:
        repo.upsert_finding(
            Finding(
                id=make_finding_id(
                    artifact_b, FindingType.DIFF_ENDPOINT_CHANGED.value, f"{change.key}:{change.category}"
                ),
                workspace_id=workspace.id,
                artifact_id=artifact_b,
                run_id=run_id,
                type=FindingType.DIFF_ENDPOINT_CHANGED,
                summary=f"Endpoint changed ({change.category}): {change.key}",
                method="api.diff",
                tool_name="traceforge",
                tool_version=__version__,
                confidence=Confidence.OBSERVED,
                key=f"{change.key}:{change.category}",
                data={
                    "endpoint": change.key,
                    "category": change.category,
                    "detail": change.detail,
                    "before": change.before,
                    "after": change.after,
                },
                evidence=(
                    EvidenceRef(kind="observation", ref=f"artifact:{artifact_a}"),
                    EvidenceRef(kind="observation", ref=f"artifact:{artifact_b}"),
                ),
                limitations=(
                    "A difference between two captures describes what changed in the "
                    "observed traffic, not necessarily what changed in the server.",
                ),
                created_at=now,
            )
        )

    for message in result.unclassified:
        repo.upsert_finding(
            Finding(
                id=make_finding_id(artifact_b, FindingType.DIFF_UNCLASSIFIED.value, message[:120]),
                workspace_id=workspace.id,
                artifact_id=artifact_b,
                run_id=run_id,
                type=FindingType.DIFF_UNCLASSIFIED,
                summary=f"Unclassified difference: {message}",
                method="api.diff",
                tool_name="traceforge",
                tool_version=__version__,
                confidence=Confidence.HYPOTHESIS,
                key=message[:120],
                data={"detail": message},
                limitations=("TraceForge could not classify this difference confidently.",),
                created_at=now,
            )
        )

    rebuild_graph(repo)


def export_openapi_document(workspace: Workspace) -> dict[str, Any]:
    """Build an OpenAPI document from the workspace endpoint inventory."""
    from traceforge.exporters.openapi import build_openapi

    with workspace.session_scope() as session:
        repo = workspace.repository(session)
        endpoints = repo.list_endpoints()
        return build_openapi(
            endpoints,
            title=f"{workspace.name} - observed API",
            version=__version__,
        )


def dumps_json(payload: Any, *, indent: int = 2) -> str:
    """Serialise a payload as JSON with stable key ordering."""
    return json.dumps(payload, indent=indent, sort_keys=True, ensure_ascii=False, default=str)
