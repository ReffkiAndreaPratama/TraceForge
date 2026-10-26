"""Runtime configuration.

Configuration is resolved from (in order of precedence):

1. explicit keyword arguments passed by the caller,
2. environment variables prefixed with ``TRACEFORGE_``,
3. the defaults declared in :class:`Limits`.

Nothing here performs network access.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Any

from traceforge.errors import ConfigurationError

ENV_PREFIX = "TRACEFORGE_"

MB = 1024 * 1024


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(f"{ENV_PREFIX}{name}")
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigurationError(
            f"Environment variable {ENV_PREFIX}{name} must be an integer",
            detail=raw,
        ) from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(f"{ENV_PREFIX}{name}")
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class Limits:
    """Safety limits applied to every untrusted input.

    These are hard caps: an input that exceeds them is rejected rather than
    partially processed, so that a hostile file cannot exhaust memory or CPU.
    """

    #: Maximum size of an imported artifact (bytes).
    max_file_bytes: int = 64 * MB
    #: Maximum number of entries inspected in a HAR file.
    max_har_entries: int = 50_000
    #: Maximum size of a single HTTP body retained for schema inference.
    max_body_bytes: int = 2 * MB
    #: Maximum JSON nesting depth accepted while inferring schemas.
    max_json_depth: int = 32
    #: Maximum number of keys tracked inside a single JSON object.
    max_json_keys: int = 512
    #: Minimum printable-string length extracted from binaries.
    min_string_length: int = 4
    #: Maximum number of strings extracted from a single binary.
    max_strings: int = 100_000
    #: Maximum length of a single extracted string.
    max_string_length: int = 4096
    #: Maximum bytes scanned for strings (bounds runtime on huge binaries).
    max_string_scan_bytes: int = 64 * MB
    #: Maximum size of a stored request/response body preview.
    max_body_preview_bytes: int = 4096
    #: Maximum number of endpoints retained per artifact.
    max_endpoints_per_artifact: int = 20_000
    #: Maximum number of findings persisted by a single analysis run.
    max_findings_per_run: int = 20_000
    #: Maximum number of relationships created per analysis run.
    max_relationships_per_run: int = 200_000

    def __post_init__(self) -> None:
        for field_name in self.__slots__:
            value = getattr(self, field_name)
            if value <= 0:
                raise ConfigurationError(f"Limit '{field_name}' must be positive", detail=str(value))


@dataclass(frozen=True, slots=True)
class RedactionSettings:
    """Configuration for the redaction pipeline.

    Redaction happens *before* persistence, so secrets never reach the database
    and can never leak through an export.
    """

    #: Header names (case-insensitive) whose values are always replaced.
    sensitive_headers: tuple[str, ...] = (
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-authorization",
        "x-csrf-token",
        "x-xsrf-token",
        "x-session-id",
        "x-amz-security-token",
    )
    #: Query/body parameter names (case-insensitive) whose values are replaced.
    sensitive_parameters: tuple[str, ...] = (
        "authorization",
        "auth",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "key",
        "secret",
        "client_secret",
        "password",
        "passwd",
        "pwd",
        "session",
        "sessionid",
        "session_id",
        "signature",
        "sig",
        "jwt",
        "bearer",
    )
    #: Extra user-supplied regular expressions applied to header values, query
    #: values and string payloads.  The whole match is replaced by the
    #: placeholder.
    extra_patterns: tuple[str, ...] = ()
    #: Placeholder written in place of a redacted value.
    placeholder: str = "[REDACTED]"
    #: Redact values that look like a JWT.
    redact_jwt: bool = True
    #: Redact values that look like a bearer token.
    redact_bearer: bool = True

    def with_extra_patterns(self, patterns: list[str] | tuple[str, ...]) -> RedactionSettings:
        return replace(self, extra_patterns=tuple(patterns))


@dataclass(frozen=True, slots=True)
class Settings:
    """Top level settings object."""

    limits: Limits = field(default_factory=Limits)
    redaction: RedactionSettings = field(default_factory=RedactionSettings)
    #: Emit verbose diagnostics on stderr.
    verbose: bool = False
    #: Never contact the network. Present so that the intent is explicit and testable.
    offline: bool = True

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from ``TRACEFORGE_*`` environment variables."""
        limits = Limits(
            max_file_bytes=_env_int("MAX_FILE_BYTES", 64 * MB),
            max_har_entries=_env_int("MAX_HAR_ENTRIES", 50_000),
            max_body_bytes=_env_int("MAX_BODY_BYTES", 2 * MB),
            max_json_depth=_env_int("MAX_JSON_DEPTH", 32),
            max_json_keys=_env_int("MAX_JSON_KEYS", 512),
            min_string_length=_env_int("MIN_STRING_LENGTH", 4),
            max_strings=_env_int("MAX_STRINGS", 100_000),
            max_string_length=_env_int("MAX_STRING_LENGTH", 4096),
            max_string_scan_bytes=_env_int("MAX_STRING_SCAN_BYTES", 64 * MB),
            max_endpoints_per_artifact=_env_int("MAX_ENDPOINTS_PER_ARTIFACT", 20_000),
            max_findings_per_run=_env_int("MAX_FINDINGS_PER_RUN", 20_000),
        )
        redaction = RedactionSettings()
        patterns = os.environ.get(f"{ENV_PREFIX}REDACTION_PATTERNS", "")
        if patterns.strip():
            redaction = redaction.with_extra_patterns(
                tuple(p.strip() for p in patterns.split(";") if p.strip())
            )
        return cls(
            limits=limits,
            redaction=redaction,
            verbose=_env_bool("VERBOSE", False),
        )

    def merged(self, **overrides: Any) -> Settings:
        """Return a copy of these settings with ``overrides`` applied.

        ``None`` values are ignored so that callers can pass optional arguments
        straight through.
        """
        clean = {k: v for k, v in overrides.items() if v is not None}
        return replace(self, **clean) if clean else self
