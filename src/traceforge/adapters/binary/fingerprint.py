"""Binary fingerprinting orchestrator.

This module ties the format specific adapters together with the string
extractor and produces a single, uniform :class:`BinaryInfo` result plus the
structured findings that the evidence graph stores.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from traceforge.adapters.binary.base import BinaryAdapter
from traceforge.adapters.binary.elf import ELFAdapter
from traceforge.adapters.binary.macho import MachOAdapter
from traceforge.adapters.binary.pe import PEAdapter
from traceforge.adapters.binary.strings import ExtractedString, extract_strings_from_file
from traceforge.adapters.binary.indicators import extract_domains, extract_urls
from traceforge.config import Limits
from traceforge.domain.enums import BinaryFormat, DiagnosticLevel
from traceforge.domain.models import BinaryInfo, Diagnostic
from traceforge.security.validators import hash_file, sniff_format


@dataclass(slots=True)
class FingerprintResult:
    """Everything the analysis layer needs after fingerprinting a binary."""

    info: BinaryInfo
    strings: list[ExtractedString] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    scan_truncated: bool = False

    @property
    def diagnostics(self) -> tuple[Diagnostic, ...]:
        return self.info.diagnostics


def available_adapters() -> list[BinaryAdapter]:
    """Return the adapters whose optional dependencies are installed."""
    adapters: list[BinaryAdapter] = []
    pe = PEAdapter()
    if pe.version is not None:
        adapters.append(pe)
    elf = ELFAdapter()
    if elf.version is not None:
        adapters.append(elf)
    adapters.append(MachOAdapter())
    return adapters


def select_adapter(head: bytes) -> BinaryAdapter | None:
    """Return the first adapter that recognises ``head``."""
    for adapter in available_adapters():
        try:
            if adapter.supports(head):
                return adapter
        except Exception:  # noqa: BLE001 - adapters must never crash selection
            continue
    return None


def fingerprint(path: Path, *, limits: Limits | None = None) -> FingerprintResult:
    """Fingerprint a binary file without executing it.

    The file is only ever *read*.  No code from the sample is loaded, mapped or
    run - this is a hard rule of the project.
    """
    limits = limits or Limits()
    diagnostics: list[Diagnostic] = []

    sha256, size = hash_file(path)
    with path.open("rb") as handle:
        head = handle.read(64)

    sniffed = sniff_format(head)
    adapter = select_adapter(head)

    if adapter is None:
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.ERROR,
                code="binary.unknown_format",
                message=(
                    "The file format could not be identified. "
                    "Only PE, ELF and Mach-O containers are supported."
                ),
                detail=f"sniffed={sniffed.kind}",
            )
        )
        info = BinaryInfo(
            format=BinaryFormat.UNKNOWN,
            sha256=sha256,
            size_bytes=size,
            diagnostics=tuple(diagnostics),
        )
        return FingerprintResult(info=info)

    try:
        info = adapter.parse(path, head=head)
    except Exception as exc:  # noqa: BLE001 - adapter failures become diagnostics
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.ERROR,
                code="binary.parse_failed",
                message=f"The {sniffed.kind.upper()} adapter could not parse this file",
                detail=str(exc),
                source=adapter.name,
            )
        )
        info = BinaryInfo(
            format=sniffed.kind,  # type: ignore[arg-type]
            sha256=sha256,
            size_bytes=size,
            diagnostics=tuple(diagnostics),
            parser=adapter.name,
            parser_version=getattr(adapter, "version", None),
        )
        return FingerprintResult(info=info)

    # Fill in the facts the format adapter cannot know about.
    info = info.model_copy(
        update={
            "sha256": sha256,
            "size_bytes": size,
            "diagnostics": tuple(info.diagnostics) + tuple(diagnostics),
        }
    )

    strings, truncated = extract_strings_from_file(path, limits=limits)
    if truncated:
        info = info.model_copy(
            update={
                "diagnostics": info.diagnostics
                + (
                    Diagnostic(
                        level=DiagnosticLevel.WARNING,
                        code="binary.scan_truncated",
                        message=(
                            "The string scan was truncated because the file exceeds the "
                            "configured scan limit; results cover only the beginning of the file."
                        ),
                        detail=f"limit={limits.max_string_scan_bytes} bytes",
                    ),
                )
            }
        )

    texts = [item.text for item in strings]
    urls = extract_urls(texts)
    domains = extract_domains(texts)

    info = info.model_copy(
        update={
            "strings": tuple(texts),
            "urls": tuple(urls),
            "domains": tuple(domains),
        }
    )

    return FingerprintResult(info=info, strings=strings, urls=urls, domains=domains, scan_truncated=truncated)
