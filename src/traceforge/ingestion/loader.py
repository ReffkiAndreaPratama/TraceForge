"""File intake.

Artifacts are *copied* into the workspace under a generated identifier.  The
user supplied file name never becomes a storage path, which removes a whole
class of path traversal and overwrite problems.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from traceforge.config import Limits
from traceforge.domain.enums import ArtifactKind
from traceforge.errors import UnsupportedFormatError
from traceforge.security.paths import safe_join, sanitize_display_name
from traceforge.security.validators import (
    hash_file,
    sniff_format,
    validate_input_file,
)


@dataclass(slots=True)
class IngestedFile:
    """Metadata about a file that has been copied into a workspace."""

    source_path: Path
    stored_path: Path | None
    display_name: str
    sha256: str
    size_bytes: int
    kind: ArtifactKind
    detected_type: str | None


def detect_kind(path: Path, *, forced: ArtifactKind | None = None) -> tuple[ArtifactKind, str | None]:
    """Return the artifact kind and a detected type for ``path``."""
    if forced is not None:
        return forced, forced.value

    with path.open("rb") as handle:
        head = handle.read(64)

    sniffed = sniff_format(head)
    if sniffed.kind == "json":
        return ArtifactKind.JSON, "json"
    if sniffed.kind in {"pe", "elf", "macho"}:
        return ArtifactKind.BINARY, sniffed.kind
    if sniffed.kind == "unknown":
        # Fall back to a textual check: HAR files are JSON objects with a log.
        try:
            text = path.read_text(encoding="utf-8", errors="strict")[:4096]
        except (UnicodeDecodeError, OSError):
            return ArtifactKind.UNKNOWN, sniffed.kind
        stripped = text.lstrip()
        if stripped.startswith("{") and '"log"' in text:
            return ArtifactKind.HAR, "har"
        return ArtifactKind.UNKNOWN, sniffed.kind
    return ArtifactKind.UNKNOWN, sniffed.kind


def ingest_file(
    path: str | Path,
    *,
    workspace_root: Path,
    artifact_id: str,
    limits: Limits | None = None,
    kind: ArtifactKind | None = None,
    copy: bool = True,
) -> IngestedFile:
    """Validate and import a file into a workspace.

    The file is validated (size, symlink, regular file), hashed and optionally
    copied into the workspace store under ``artifact_id``.
    """
    limits = limits or Limits()
    resolved = validate_input_file(path, limits)
    sha256, size = hash_file(resolved)
    detected_kind, detected_type = detect_kind(resolved, forced=kind)
    display_name = sanitize_display_name(resolved.name)

    stored_path: Path | None = None
    if copy:
        target_dir = safe_join(workspace_root, "artifacts", detected_kind.value)
        target_dir.mkdir(parents=True, exist_ok=True)
        stored_path = safe_join(target_dir, f"{artifact_id}.bin")
        shutil.copyfile(resolved, stored_path)

    return IngestedFile(
        source_path=resolved,
        stored_path=stored_path,
        display_name=display_name,
        sha256=sha256,
        size_bytes=size,
        kind=detected_kind,
        detected_type=detected_type,
    )


def require_kind(file: IngestedFile, expected: ArtifactKind) -> None:
    """Raise when the ingested file is not of the expected kind."""
    if file.kind != expected:
        raise UnsupportedFormatError(
            f"Expected a {expected.value} artifact but the file was detected as {file.kind.value}",
            detail=file.detected_type,
        )
