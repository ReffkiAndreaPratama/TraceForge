"""File intake."""

from traceforge.ingestion.loader import IngestedFile, detect_kind, ingest_file, require_kind

__all__ = ["IngestedFile", "detect_kind", "ingest_file", "require_kind"]
