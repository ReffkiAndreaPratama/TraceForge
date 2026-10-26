"""Input validation and safety limits.

All untrusted input passes through here *before* it reaches a parser.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from traceforge.config import Limits
from traceforge.errors import SecurityLimitExceeded, UnsupportedFormatError, ValidationError
from traceforge.security.paths import resolve_existing_file

#: Magic byte signatures used for container sniffing.
PE_MAGICS: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "dos"),
)
ELF_MAGIC = b"\x7fELF"
MACHO_MAGICS: tuple[bytes, ...] = (
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit big endian
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit little endian
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit big endian
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit little endian
    b"\xca\xfe\xba\xbe",  # Mach-O universal / Java class
)
ZIP_MAGIC = b"PK\x03\x04"
GZIP_MAGIC = b"\x1f\x8b"


@dataclass(frozen=True, slots=True)
class SniffResult:
    """Outcome of sniffing a file's container format."""

    kind: str
    detail: str | None = None

    @property
    def is_binary_container(self) -> bool:
        return self.kind in {"pe", "elf", "macho"}


def sniff_format(head: bytes) -> SniffResult:
    """Identify the container format from the first bytes of a file.

    This is a *hint*, never an authoritative classification: the real verdict
    comes from the format-specific adapter, which also reports how confident it
    is.
    """
    if not head:
        return SniffResult("unknown", "empty file")
    if head.startswith(ELF_MAGIC):
        return SniffResult("elf")
    if any(head.startswith(magic) for magic in MACHO_MAGICS):
        return SniffResult("macho")
    if head.startswith(b"MZ"):
        return SniffResult("pe")
    if head.startswith(ZIP_MAGIC):
        return SniffResult("zip")
    if head.startswith(GZIP_MAGIC):
        return SniffResult("gzip")
    stripped = head.lstrip()
    if stripped[:1] in {b"{", b"["}:
        return SniffResult("json")
    if stripped[:1] == b"<":
        return SniffResult("xml")
    return SniffResult("unknown")


def check_size(size: int, limits: Limits, *, label: str = "file") -> None:
    """Raise if ``size`` exceeds the configured limit."""
    if size > limits.max_file_bytes:
        raise SecurityLimitExceeded(
            f"{label} exceeds the maximum allowed size",
            detail=f"{size} bytes > {limits.max_file_bytes} bytes",
        )


def hash_file(path: Path, *, chunk_size: int = 1024 * 1024) -> tuple[str, int]:
    """Return ``(sha256_hex, size_bytes)`` for a file, streaming it in chunks."""
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            size += len(chunk)
            hasher.update(chunk)
    return hasher.hexdigest(), size


def validate_input_file(path: str | Path, limits: Limits) -> Path:
    """Validate an untrusted input file and return its resolved path.

    Checks, in order: existence, regular-file-ness, symlink rejection and the
    maximum size limit.
    """
    resolved = resolve_existing_file(path)
    size = resolved.stat().st_size
    check_size(size, limits)
    return resolved


def read_head(path: Path, length: int = 64) -> bytes:
    """Read up to ``length`` bytes from the start of a file."""
    with path.open("rb") as handle:
        return handle.read(length)


def require_mapping(value: object, what: str) -> dict:
    """Validate that ``value`` is a JSON object, raising a friendly error."""
    if not isinstance(value, dict):
        raise UnsupportedFormatError(f"Expected {what} to be a JSON object")
    return value
