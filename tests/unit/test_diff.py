"""Unit tests for the capture differ."""

from __future__ import annotations

from traceforge.analysis.diff import (
    CATEGORY_COUNT,
    CATEGORY_PARAMETERS,
    CATEGORY_SCHEMA,
    CATEGORY_STATUS,
    EndpointSnapshot,
    diff_snapshots,
)
from traceforge.analysis.schema import infer_schema


def snapshot(
    path_key: str,
    *,
    method: str = "GET",
    origin: str = "https://api.example.test",
    count: int = 1,
    status_codes: tuple[int, ...] = (200,),
    param_names: tuple[str, ...] = (),
    content_types: tuple[str, ...] = ("application/json",),
    schema: dict | None = None,
) -> EndpointSnapshot:
    return EndpointSnapshot(
        method=method,
        origin=origin,
        path_key=path_key,
        count=count,
        status_codes=status_codes,
        param_names=param_names,
        content_types=content_types,
        schema=schema,
    )


class TestDiffSnapshots:
    def test_identical_captures_have_no_differences(self) -> None:
        left = [snapshot("/v1/health")]
        right = [snapshot("/v1/health")]
        result = diff_snapshots(left, right)
        assert result.is_identical is True
        assert result.summary() == {"added": 0, "removed": 0, "changed": 0, "unclassified": 0}

    def test_added_endpoint_is_detected(self) -> None:
        result = diff_snapshots([snapshot("/v1/health")], [snapshot("/v1/metrics")])
        assert [item.path_key for item in result.added] == ["/v1/metrics"]
        assert [item.path_key for item in result.removed] == ["/v1/health"]

    def test_removed_endpoint_is_detected(self) -> None:
        result = diff_snapshots([snapshot("/v1/missing")], [snapshot("/v1/health")])
        assert [item.path_key for item in result.removed] == ["/v1/missing"]
        assert [item.path_key for item in result.added] == ["/v1/health"]

    def test_status_code_change_is_classified(self) -> None:
        result = diff_snapshots(
            [snapshot("/v1/health", status_codes=(200,))],
            [snapshot("/v1/health", status_codes=(200, 404))],
        )
        categories = [change.category for change in result.changed]
        assert CATEGORY_STATUS in categories
        change = next(c for c in result.changed if c.category == CATEGORY_STATUS)
        assert change.before == [200]
        assert change.after == [200, 404]

    def test_parameter_change_is_classified(self) -> None:
        result = diff_snapshots(
            [snapshot("/v1/search", param_names=("q",))],
            [snapshot("/v1/search", param_names=("q", "page"))],
        )
        change = next(c for c in result.changed if c.category == CATEGORY_PARAMETERS)
        assert change.after == ["page", "q"]

    def test_schema_change_is_classified(self) -> None:
        result = diff_snapshots(
            [snapshot("/v1/health", schema=infer_schema([{"status": "ok"}]))],
            [snapshot("/v1/health", schema=infer_schema([{"status": "ok", "v": "2"}]))],
        )
        change = next(c for c in result.changed if c.category == CATEGORY_SCHEMA)
        assert "v" in change.detail

    def test_occurrence_change_is_classified(self) -> None:
        result = diff_snapshots(
            [snapshot("/v1/health", count=1)],
            [snapshot("/v1/health", count=5)],
        )
        change = next(c for c in result.changed if c.category == CATEGORY_COUNT)
        assert change.before == 1
        assert change.after == 5

    def test_results_are_deterministically_ordered(self) -> None:
        left = [snapshot("/v1/z"), snapshot("/v1/a")]
        right = [snapshot("/v1/m"), snapshot("/v1/b")]
        result = diff_snapshots(left, right)
        assert [item.path_key for item in result.added] == ["/v1/b", "/v1/m"]
        assert [item.path_key for item in result.removed] == ["/v1/a", "/v1/z"]

    def test_different_methods_are_different_endpoints(self) -> None:
        result = diff_snapshots(
            [snapshot("/v1/items", method="GET")],
            [snapshot("/v1/items", method="POST")],
        )
        assert len(result.added) == 1
        assert len(result.removed) == 1

    def test_labels_are_carried_through(self) -> None:
        result = diff_snapshots([], [], left_label="old.har", right_label="new.har")
        assert result.left_label == "old.har"
        assert result.right_label == "new.har"
