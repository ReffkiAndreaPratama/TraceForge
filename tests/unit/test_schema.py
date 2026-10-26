"""Unit tests for JSON schema inference and schema comparison."""

from __future__ import annotations

from traceforge.analysis.schema import (
    T_BOOLEAN,
    T_INTEGER,
    T_NULL,
    T_OBJECT,
    T_STRING,
    infer_schema,
    json_type,
    parse_json_samples,
    schemas_differ,
    to_json_schema,
)
from traceforge.config import Limits


class TestJsonType:
    def test_primitives(self) -> None:
        assert json_type(None) == T_NULL
        assert json_type(True) == T_BOOLEAN
        assert json_type(1) == T_INTEGER
        assert json_type(1.5) == "number"
        assert json_type("x") == T_STRING
        assert json_type([]) == "array"
        assert json_type({}) == T_OBJECT

    def test_bool_is_not_an_integer(self) -> None:
        assert json_type(False) == T_BOOLEAN


class TestInferSchema:
    def test_no_samples_produces_no_schema(self) -> None:
        assert infer_schema([]) is None

    def test_object_fields_are_recorded(self) -> None:
        schema = infer_schema([{"id": 1, "name": "a"}])
        assert schema is not None
        assert schema["type"] == T_OBJECT
        assert set(schema["properties"]) == {"id", "name"}
        assert schema["properties"]["id"]["type"] == T_INTEGER
        assert schema["required"] == ["id", "name"]

    def test_optional_fields_are_detected(self) -> None:
        schema = infer_schema([{"id": 1, "name": "a"}, {"id": 2}])
        assert schema is not None
        # The root object was present in every sample, so it is not optional.
        assert schema["optional"] is False
        assert schema["properties"]["name"]["optional"] is True
        assert schema["properties"]["id"]["optional"] is False
        assert schema["optional_fields"] == ["name"]
        assert schema["required"] == ["id"]

    def test_conflicting_types_are_reported_not_hidden(self) -> None:
        schema = infer_schema([{"id": 1}, {"id": "one"}])
        assert schema is not None
        node = schema["properties"]["id"]
        assert node["conflicting"] is True
        assert set(node["observed_types"]) == {"integer", "string"}

    def test_all_null_field_keeps_the_null_type(self) -> None:
        schema = infer_schema([{"id": None}])
        assert schema is not None
        assert schema["properties"]["id"]["type"] == T_NULL

    def test_nested_objects_are_described(self) -> None:
        schema = infer_schema([{"user": {"id": 1, "name": "a"}}])
        assert schema is not None
        user = schema["properties"]["user"]
        assert user["type"] == T_OBJECT
        assert set(user["properties"]) == {"id", "name"}

    def test_arrays_describe_their_items(self) -> None:
        schema = infer_schema([{"tags": ["a", "b"]}])
        assert schema is not None
        assert schema["properties"]["tags"]["type"] == "array"
        assert schema["properties"]["tags"]["items"]["type"] == T_STRING

    def test_depth_limit_stops_the_descent(self) -> None:
        limits = Limits(max_json_depth=2)
        payload: dict = {"a": {"b": {"c": {"d": 1}}}}
        schema = infer_schema([payload], limits=limits)
        assert schema is not None
        assert "note" in schema["properties"]["a"]["properties"]["b"]

    def test_key_limit_is_reported(self) -> None:
        limits = Limits(max_json_keys=2)
        schema = infer_schema([{"a": 1, "b": 2, "c": 3, "d": 4}], limits=limits)
        assert schema is not None
        assert len(schema["properties"]) == 2
        assert "note" in schema

    def test_metadata_is_attached_to_the_root(self) -> None:
        schema = infer_schema([{"a": 1}])
        assert schema is not None
        assert schema["inferred"] is True
        assert schema["sample_count"] == 1
        assert schema["source"] == "observed traffic only"


class TestParseJsonSamples:
    def test_invalid_json_is_reported_not_raised(self) -> None:
        samples, errors = parse_json_samples(["{not json", '{"a": 1}'])
        assert samples == [{"a": 1}]
        assert len(errors) == 1

    def test_oversized_body_is_skipped(self) -> None:
        limits = Limits(max_body_bytes=10)
        samples, errors = parse_json_samples(['{"a": "0123456789abcdef"}'], limits=limits)
        assert samples == []
        assert errors


class TestSchemasDiffer:
    def test_identical_schemas_do_not_differ(self) -> None:
        left = infer_schema([{"id": 1}])
        right = infer_schema([{"id": 2}])
        assert schemas_differ(left, right) == []

    def test_added_field_is_reported(self) -> None:
        left = infer_schema([{"id": 1}])
        right = infer_schema([{"id": 1, "email": "a@b.test"}])
        assert schemas_differ(left, right) == ["email: added"]

    def test_removed_field_is_reported(self) -> None:
        left = infer_schema([{"id": 1, "email": "a@b.test"}])
        right = infer_schema([{"id": 1}])
        assert schemas_differ(left, right) == ["email: removed"]

    def test_optionality_change_is_reported(self) -> None:
        left = infer_schema([{"id": 1, "email": "a@b.test"}])
        right = infer_schema([{"id": 1}, {"id": 2, "email": "a@b.test"}])
        differences = schemas_differ(left, right)
        assert any("optionality changed" in item for item in differences)

    def test_one_sided_schema_is_reported(self) -> None:
        assert schemas_differ(None, None) == []
        assert schemas_differ(None, {"type": T_OBJECT}) == [
            "schema present in only one of the captures"
        ]


class TestToJsonSchema:
    def test_conversion_produces_plain_json_schema(self) -> None:
        schema = infer_schema([{"id": 1, "name": "a"}])
        converted = to_json_schema(schema)
        assert converted is not None
        assert converted["type"] == T_OBJECT
        assert converted["properties"]["id"]["type"] == T_INTEGER
        assert converted["required"] == ["id", "name"]
        # TraceForge specific counters must not pollute the JSON Schema.
        assert "present_count" not in converted
        assert "observed_types" not in converted

    def test_observation_metadata_moves_into_the_extension(self) -> None:
        schema = infer_schema([{"id": 1}])
        converted = to_json_schema(schema)
        assert converted is not None
        extension = converted["x-traceforge"]
        assert extension["inferred"] is True
        assert extension["present_count"] == 1

    def test_none_converts_to_none(self) -> None:
        assert to_json_schema(None) is None
