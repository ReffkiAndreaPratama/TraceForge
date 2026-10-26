"""Controlled vocabularies used across TraceForge.

These enums are part of the exported document contract: values are stable
strings and are documented in ``docs/formats.md``.
"""

from __future__ import annotations

from enum import StrEnum


class ArtifactKind(StrEnum):
    """The kind of imported artifact."""

    HAR = "har"
    BINARY = "binary"
    JSON = "json"
    UNKNOWN = "unknown"


class BinaryFormat(StrEnum):
    """Recognised executable container formats."""

    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    UNKNOWN = "unknown"


class FindingType(StrEnum):
    """Categories of finding stored in the evidence graph."""

    # --- binary ---------------------------------------------------------
    BINARY_METADATA = "binary.metadata"
    BINARY_SECTION = "binary.section"
    BINARY_IMPORT = "binary.import"
    BINARY_EXPORT = "binary.export"
    BINARY_SYMBOL = "binary.symbol"
    BINARY_STRING = "binary.string"
    BINARY_DOMAIN = "binary.domain"
    BINARY_URL_LIKE = "binary.url_like"
    BINARY_ENTROPY = "binary.entropy"
    BINARY_HASH = "binary.hash"

    # --- http ------------------------------------------------------------
    HTTP_ENDPOINT = "http.endpoint"
    HTTP_PARAMETER = "http.parameter"
    HTTP_STATUS = "http.status"
    HTTP_CONTENT_TYPE = "http.content_type"
    HTTP_SCHEMA = "http.schema"
    HTTP_HOST = "http.host"
    HTTP_HEADER = "http.header"

    # --- analysis --------------------------------------------------------
    DIFF_ENDPOINT_ADDED = "diff.endpoint_added"
    DIFF_ENDPOINT_REMOVED = "diff.endpoint_removed"
    DIFF_ENDPOINT_CHANGED = "diff.endpoint_changed"
    DIFF_STATUS_CHANGED = "diff.status_changed"
    DIFF_PARAMETER_CHANGED = "diff.parameter_changed"
    DIFF_SCHEMA_CHANGED = "diff.schema_changed"
    DIFF_UNCLASSIFIED = "diff.unclassified"

    # --- diagnostics -----------------------------------------------------
    PARSER_WARNING = "parser.warning"
    PARSER_ERROR = "parser.error"
    ANALYSIS_LIMIT = "analysis.limit"


class ObservationKind(StrEnum):
    """The kind of raw observation extracted from an artifact.

    Observations are the lowest-level evidence layer: they point back to a
    concrete location inside a source artifact (for example a HAR entry index
    or a byte offset in a binary).
    """

    HTTP_REQUEST = "http.request"
    HTTP_RESPONSE = "http.response"
    HTTP_HEADER = "http.header"
    HTTP_QUERY_PARAM = "http.query_param"
    HTTP_BODY_FIELD = "http.body_field"
    BINARY_STRING = "binary.string"
    BINARY_SECTION = "binary.section"
    BINARY_IMPORT = "binary.import"
    BINARY_SYMBOL = "binary.symbol"


class Confidence(StrEnum):
    """How strongly a claim is supported by evidence.

    TraceForge never collapses these into a single score: a reader must always
    be able to tell observation from inference from hypothesis.
    """

    #: Directly read from the artifact; no interpretation applied.
    OBSERVED = "observed"
    #: Derived from observed data by a documented, deterministic rule.
    INFERRED = "inferred"
    #: A candidate link that is *not* proven; requires human confirmation.
    HYPOTHESIS = "hypothesis"


class RelationKind(StrEnum):
    """The relationship (edge) vocabulary of the evidence graph."""

    #: artifact -> binary.string finding
    CONTAINS_STRING = "contains_string"
    #: artifact -> binary.domain finding
    CONTAINS_DOMAIN = "contains_domain"
    #: artifact -> http.endpoint finding
    OBSERVED_ENDPOINT = "observed_endpoint"
    #: http.endpoint finding -> http.host finding
    TARGETS_HOST = "targets_host"
    #: artifact -> artifact, both ingested into the same workspace
    CO_LOCATED_IN_WORKSPACE = "co_located_in_workspace"
    #: artifact (binary) -> http.endpoint finding; UNVERIFIED hypothesis
    CANDIDATE_ENDPOINT_REFERENCE = "candidate_endpoint_reference"
    #: finding -> artifact, the artifact that produced the finding
    DERIVED_FROM = "derived_from"
    #: finding -> finding, a differential relationship
    DIFFERS_FROM = "differs_from"


class RunStatus(StrEnum):
    """Lifecycle status of an analysis run."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class DiagnosticLevel(StrEnum):
    """Severity of a parser diagnostic."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
