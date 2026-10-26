"""Deterministic, content-addressed identifiers.

Identifiers are derived from the content they describe rather than randomly
generated.  Two consequences matter:

* **Idempotency** - re-importing the same file into the same workspace updates
  the existing artifact instead of creating a duplicate.
* **Reproducible exports** - identical inputs produce identical identifiers, so
  normalised exports can be compared byte-for-byte.

The prefix makes the identifier type obvious when reading raw JSON.
"""

from __future__ import annotations

import hashlib
import re

_UUID_RE = re.compile(r"^[0-9a-f]{32}$")


def _digest(*parts: str, length: int = 16) -> str:
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(part.encode("utf-8", errors="replace"))
        hasher.update(b"\x1f")  # unit separator prevents join ambiguity
    return hasher.hexdigest()[:length]


def workspace_id(name: str, namespace: str = "default") -> str:
    """Identifier for a workspace, derived from its name and namespace."""
    return f"ws_{_digest(namespace, name.strip().lower())}"


def artifact_id(ws_id: str, kind: str, content_hash: str) -> str:
    """Identifier for an artifact inside a workspace."""
    return f"art_{_digest(ws_id, kind, content_hash)}"


def finding_id(artifact: str | None, finding_type: str, key: str) -> str:
    """Identifier for a finding."""
    return f"fnd_{_digest(artifact or '-', finding_type, key)}"


def observation_id(artifact: str, kind: str, key: str) -> str:
    """Identifier for an observation."""
    return f"obs_{_digest(artifact, kind, key)}"


def relationship_id(ws_id: str, from_id: str, kind: str, to_id: str) -> str:
    """Identifier for a relationship edge."""
    return f"rel_{_digest(ws_id, from_id, kind, to_id)}"


def endpoint_id(ws_id: str, method: str, origin: str, path_key: str) -> str:
    """Identifier for a normalised API endpoint."""
    return f"ep_{_digest(ws_id, method.upper(), origin.lower(), path_key)}"


def run_id(artifact: str, analyzer: str, tool_version: str, nonce: str) -> str:
    """Identifier for an analysis run.

    A nonce is mixed in because repeated runs of the same analyzer over the same
    artifact are distinct historical records.
    """
    return f"run_{_digest(artifact, analyzer, tool_version, nonce)}"


def export_id(ws_id: str, kind: str, fmt: str, nonce: str) -> str:
    """Identifier for an export record."""
    return f"exp_{_digest(ws_id, kind, fmt, nonce)}"


def annotation_id(ws_id: str, subject_type: str, subject_id: str, nonce: str) -> str:
    """Identifier for a user annotation."""
    return f"ann_{_digest(ws_id, subject_type, subject_id, nonce)}"


def is_valid_identifier(value: str) -> bool:
    """Return ``True`` when ``value`` looks like a TraceForge identifier."""
    if not isinstance(value, str) or not value:
        return False
    prefix, _, digest = value.partition("_")
    if not prefix or not digest:
        return False
    return bool(re.fullmatch(r"[0-9a-f]+", digest)) and len(digest) >= 8
