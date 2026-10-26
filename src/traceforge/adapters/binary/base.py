"""Common adapter interfaces.

Adapters convert an untrusted artifact into typed, structured results.  They
never raise for malformed input: instead they return diagnostics so that a
single broken artifact cannot abort a whole workspace.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from traceforge.domain.models import BinaryInfo, Diagnostic


@dataclass(slots=True)
class AdapterResult:
    """The result of running an adapter over an artifact."""

    ok: bool
    data: dict | None = None
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @classmethod
    def success(cls, data: dict | None = None) -> AdapterResult:
        return cls(ok=True, data=data or {})

    @classmethod
    def failure(cls, message: str, code: str = "adapter.error") -> AdapterResult:
        from traceforge.domain.enums import DiagnosticLevel

        return cls(
            ok=False,
            diagnostics=[Diagnostic(level=DiagnosticLevel.ERROR, code=code, message=message)],
        )


@runtime_checkable
class BinaryAdapter(Protocol):
    """Interface implemented by each binary format adapter."""

    name: str

    def supports(self, head: bytes) -> bool:
        """Return ``True`` when this adapter recognises the container."""

    def parse(self, path: Path, *, head: bytes) -> BinaryInfo:
        """Parse ``path`` and return the extracted information."""
