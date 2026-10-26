"""Error hierarchy for TraceForge.

Every error carries a stable ``exit_code`` so that the CLI can map failures to
documented exit codes without string matching.
"""

from __future__ import annotations


class ExitCode:
    """Documented process exit codes.

    These are part of the public CLI contract; see ``docs/architecture.md``.
    """

    SUCCESS = 0
    #: Generic, unexpected failure (a bug in TraceForge).
    INTERNAL_ERROR = 1
    #: Usage / validation error. Matches Click/Typer's default for bad arguments.
    USAGE_ERROR = 2
    #: A workspace, artifact or finding was not found.
    NOT_FOUND = 3
    #: The input was rejected by a safety policy (size limit, unsupported format...).
    REJECTED = 4
    #: Analysis completed but the result is not usable (e.g. diff of unrelated captures).
    ANALYSIS_FAILED = 5


class TraceForgeError(Exception):
    """Base class for all TraceForge errors."""

    exit_code: int = ExitCode.INTERNAL_ERROR

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def __str__(self) -> str:  # pragma: no cover - trivial
        if self.detail:
            return f"{self.message} ({self.detail})"
        return self.message


class ConfigurationError(TraceForgeError):
    """Raised when configuration is missing or contradictory."""

    exit_code = ExitCode.USAGE_ERROR


class ValidationError(TraceForgeError):
    """Raised when user supplied data fails validation."""

    exit_code = ExitCode.USAGE_ERROR


class WorkspaceNotFoundError(TraceForgeError):
    """Raised when a workspace cannot be located."""

    exit_code = ExitCode.NOT_FOUND


class ArtifactNotFoundError(TraceForgeError):
    """Raised when an artifact cannot be located."""

    exit_code = ExitCode.NOT_FOUND


class FindingNotFoundError(TraceForgeError):
    """Raised when a finding cannot be located."""

    exit_code = ExitCode.NOT_FOUND


class UnsupportedFormatError(TraceForgeError):
    """Raised when an input format is not supported by any adapter."""

    exit_code = ExitCode.REJECTED


class SecurityLimitExceeded(TraceForgeError):
    """Raised when an input exceeds a configured safety limit."""

    exit_code = ExitCode.REJECTED


class AdapterError(TraceForgeError):
    """Raised when an adapter fails to process an input.

    Adapters are expected to convert failures into structured diagnostics
    rather than propagating exceptions, so this is a last-resort error.
    """

    exit_code = ExitCode.ANALYSIS_FAILED


class AnalysisError(TraceForgeError):
    """Raised when an analysis run cannot produce a usable result."""

    exit_code = ExitCode.ANALYSIS_FAILED
