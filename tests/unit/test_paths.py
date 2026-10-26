"""Unit tests for path normalisation and the path-parameter heuristics."""

from __future__ import annotations

import pytest

from traceforge.analysis.paths import RESERVED_SEGMENTS, normalize_path


class TestNormalizePath:
    def test_empty_input_becomes_root(self) -> None:
        result = normalize_path("")
        assert result.path_key == "/"
        assert result.parameters == ()

    def test_plain_path_is_unchanged(self) -> None:
        result = normalize_path("/v1/health")
        assert result.path_key == "/v1/health"
        assert result.has_parameters is False

    def test_full_url_is_reduced_to_its_path(self) -> None:
        result = normalize_path("https://api.example.test/v1/health")
        assert result.path_key == "/v1/health"
        assert result.path == "/v1/health"
        assert result.original == "https://api.example.test/v1/health"

    def test_query_string_is_dropped(self) -> None:
        result = normalize_path("https://api.example.test/v1/items?page=2&size=10")
        assert result.path_key == "/v1/items"

    def test_fragment_is_dropped(self) -> None:
        result = normalize_path("https://api.example.test/v1/items#section")
        assert result.path_key == "/v1/items"

    def test_duplicate_slashes_are_collapsed(self) -> None:
        result = normalize_path("/v1//items///detail")
        assert result.path_key == "/v1/items/detail"

    def test_trailing_slash_is_preserved(self) -> None:
        assert normalize_path("/v1/items/").path_key == "/v1/items/"
        assert normalize_path("/").path_key == "/"

    def test_percent_encoding_is_decoded(self) -> None:
        result = normalize_path("/v1/users/Ada%20Lovelace")
        assert result.path == "/v1/users/Ada%20Lovelace"
        assert "Ada Lovelace" in result.path_key

    def test_origin_is_always_stripped_even_without_query(self) -> None:
        """Regression: the origin used to leak into the path key."""
        for url in (
            "https://api.example.test/v1/users/42",
            "https://api.example.test/v1/health",
            "http://api.example.test:8080/v1/health",
        ):
            result = normalize_path(url)
            assert "api.example.test" not in result.path_key
            assert not result.path_key.startswith("/http")


class TestPathParameterHeuristics:
    def test_numeric_segment_becomes_a_placeholder(self) -> None:
        result = normalize_path("/v1/users/42")
        assert result.path_key == "/v1/users/{users_id}"
        assert len(result.parameters) == 1
        assert result.parameters[0].rule == "numeric"
        assert result.parameters[0].original == "42"

    def test_uuid_segment_is_detected(self) -> None:
        value = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
        result = normalize_path(f"/v1/objects/{value}")
        assert result.parameters[0].rule == "uuid"

    def test_email_segment_is_detected(self) -> None:
        result = normalize_path("/v1/contacts/ada@example.test")
        assert result.parameters[0].rule == "email"
        assert result.path_key == "/v1/contacts/{email}"

    def test_reserved_segments_are_never_parameterised(self) -> None:
        for segment in sorted(RESERVED_SEGMENTS):
            if segment in {"favicon.ico", "robots.txt", "sitemap.xml"}:
                continue
            result = normalize_path(f"/v1/{segment}")
            assert result.has_parameters is False, segment

    def test_placeholder_without_a_preceding_stem_is_generic(self) -> None:
        result = normalize_path("/v1/42")
        assert result.path_key == "/v1/{id}"

    def test_parameters_report_their_index(self) -> None:
        result = normalize_path("/v1/users/42/orders/7")
        indexes = {p.index for p in result.parameters}
        assert indexes == {2, 4}

    def test_confidence_is_inferred_for_parameterised_paths(self) -> None:
        assert normalize_path("/v1/users/42").confidence.value == "inferred"
        assert normalize_path("/v1/users").confidence.value == "observed"

    def test_parameter_dict_is_serialisable(self) -> None:
        payload = normalize_path("/v1/users/42").parameters[0].as_dict()
        assert set(payload) == {"index", "original", "placeholder", "rule"}


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://api.example.test/v1/users/42", "/v1/users/{users_id}"),
        ("https://api.example.test/v1/users/43", "/v1/users/{users_id}"),
        ("https://api.example.test/v1/items", "/v1/items"),
        ("https://api.example.test/v1/items/", "/v1/items/"),
    ],
)
def test_grouping_is_stable_across_similar_urls(url: str, expected: str) -> None:
    assert normalize_path(url).path_key == expected
