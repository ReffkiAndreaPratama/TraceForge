"""Comparison of two traffic captures.

The diff works on *normalised endpoint observations*: two captures can only be
compared when they were normalised with the same rules.  The comparison is
explicit about what it can and cannot classify - anything ambiguous is
reported as unclassified rather than guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from traceforge.analysis.schema import schemas_differ

#: Change categories reported by the differ.
CATEGORY_STATUS = "status_codes"
CATEGORY_PARAMETERS = "parameters"
CATEGORY_SCHEMA = "schema"
CATEGORY_CONTENT_TYPE = "content_types"
CATEGORY_COUNT = "occurrences"


@dataclass(slots=True)
class EndpointSnapshot:
    """The normalised view of one endpoint within one capture."""

    method: str
    origin: str
    path_key: str
    count: int = 0
    status_codes: tuple[int, ...] = ()
    param_names: tuple[str, ...] = ()
    content_types: tuple[str, ...] = ()
    schema: dict[str, Any] | None = None
    artifact_id: str | None = None

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.origin}{self.path_key}"

    def sort_key(self) -> tuple[str, str, str]:
        return (self.method.upper(), self.origin, self.path_key)


@dataclass(slots=True)
class EndpointChange:
    """A classified change on an endpoint present in both captures."""

    method: str
    origin: str
    path_key: str
    category: str
    detail: str
    before: Any = None
    after: Any = None

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.origin}{self.path_key}"


@dataclass(slots=True)
class DiffResult:
    """The complete outcome of comparing two captures."""

    added: list[EndpointSnapshot] = field(default_factory=list)
    removed: list[EndpointSnapshot] = field(default_factory=list)
    changed: list[EndpointChange] = field(default_factory=list)
    unclassified: list[str] = field(default_factory=list)
    left_label: str = "a"
    right_label: str = "b"

    @property
    def is_identical(self) -> bool:
        return not (self.added or self.removed or self.changed or self.unclassified)

    def summary(self) -> dict[str, int]:
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "changed": len(self.changed),
            "unclassified": len(self.unclassified),
        }


def _index(snapshots: list[EndpointSnapshot]) -> dict[str, EndpointSnapshot]:
    return {snapshot.key: snapshot for snapshot in snapshots}


def diff_snapshots(
    left: list[EndpointSnapshot],
    right: list[EndpointSnapshot],
    *,
    left_label: str = "a",
    right_label: str = "b",
) -> DiffResult:
    """Compare two sets of endpoint observations."""
    result = DiffResult(left_label=left_label, right_label=right_label)
    left_index = _index(left)
    right_index = _index(right)

    for key in sorted(set(left_index) | set(right_index)):
        before = left_index.get(key)
        after = right_index.get(key)

        if before is None and after is not None:
            result.added.append(after)
            continue
        if after is None and before is not None:
            result.removed.append(before)
            continue
        if before is None or after is None:  # pragma: no cover - unreachable
            continue

        before_status = set(before.status_codes)
        after_status = set(after.status_codes)
        if before_status != after_status:
            added = sorted(after_status - before_status)
            removed = sorted(before_status - after_status)
            result.changed.append(
                EndpointChange(
                    method=after.method,
                    origin=after.origin,
                    path_key=after.path_key,
                    category=CATEGORY_STATUS,
                    detail=(
                        f"status codes added={added or 'none'} removed={removed or 'none'}"
                    ),
                    before=sorted(before_status),
                    after=sorted(after_status),
                )
            )

        before_params = set(before.param_names)
        after_params = set(after.param_names)
        if before_params != after_params:
            added = sorted(after_params - before_params)
            removed = sorted(before_params - after_params)
            result.changed.append(
                EndpointChange(
                    method=after.method,
                    origin=after.origin,
                    path_key=after.path_key,
                    category=CATEGORY_PARAMETERS,
                    detail=f"parameters added={added or 'none'} removed={removed or 'none'}",
                    before=sorted(before_params),
                    after=sorted(after_params),
                )
            )

        before_types = set(before.content_types)
        after_types = set(after.content_types)
        if before_types != after_types:
            result.changed.append(
                EndpointChange(
                    method=after.method,
                    origin=after.origin,
                    path_key=after.path_key,
                    category=CATEGORY_CONTENT_TYPE,
                    detail=(
                        f"content types changed from {sorted(before_types)} to "
                        f"{sorted(after_types)}"
                    ),
                    before=sorted(before_types),
                    after=sorted(after_types),
                )
            )

        schema_differences = schemas_differ(before.schema, after.schema)
        if schema_differences:
            result.changed.append(
                EndpointChange(
                    method=after.method,
                    origin=after.origin,
                    path_key=after.path_key,
                    category=CATEGORY_SCHEMA,
                    detail="; ".join(schema_differences[:10]),
                    before=before.schema,
                    after=after.schema,
                )
            )

        if before.count != after.count:
            result.changed.append(
                EndpointChange(
                    method=after.method,
                    origin=after.origin,
                    path_key=after.path_key,
                    category=CATEGORY_COUNT,
                    detail=f"observed occurrences changed from {before.count} to {after.count}",
                    before=before.count,
                    after=after.count,
                )
            )

    result.added.sort(key=lambda s: s.sort_key())
    result.removed.sort(key=lambda s: s.sort_key())
    result.changed.sort(key=lambda c: (c.method.upper(), c.origin, c.path_key, c.category))
    return result
