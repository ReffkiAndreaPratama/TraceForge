"""JSON schema inference from observed samples.

The goal is an *honest* description of what was seen, not a guess at the
server's real contract.  Every node therefore records:

* ``type`` - the dominant observed type,
* ``observed_types`` - every type that was actually observed,
* ``present_count`` / ``total_count`` - how often the field appeared,
* ``optional`` - whether the field was missing from at least one sample,
* ``conflicting`` - whether samples disagreed about the type.

A field that was always ``null`` has type ``null``; that is a real observation
and is not silently upgraded to ``string``.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from traceforge.config import Limits

#: JSON type names used in the inferred schema.
T_OBJECT = "object"
T_ARRAY = "array"
T_STRING = "string"
T_INTEGER = "integer"
T_NUMBER = "number"
T_BOOLEAN = "boolean"
T_NULL = "null"
T_UNKNOWN = "unknown"


def json_type(value: Any) -> str:
    """Return the JSON type name of a Python value."""
    if value is None:
        return T_NULL
    if isinstance(value, bool):
        return T_BOOLEAN
    if isinstance(value, int):
        return T_INTEGER
    if isinstance(value, float):
        return T_NUMBER
    if isinstance(value, str):
        return T_STRING
    if isinstance(value, list):
        return T_ARRAY
    if isinstance(value, dict):
        return T_OBJECT
    return T_UNKNOWN


@dataclass
class _Node:
    """Accumulator for one position in the observed structure."""

    types: Counter[str] = field(default_factory=Counter)
    present: int = 0
    total: int = 0
    children: dict[str, "_Node"] = field(default_factory=dict)
    items: "_Node | None" = None
    truncated_keys: bool = False
    #: The contents of this value were not inspected (depth limit reached).
    depth_exceeded: bool = False
    #: The children of this value were not inspected (depth limit reached).
    truncated_depth: bool = False

    def observe(self, value: Any, limits: Limits, depth: int = 0) -> None:
        self.total += 1
        kind = json_type(value)
        self.types[kind] += 1
        if kind != T_NULL:
            self.present += 1

        if depth > limits.max_json_depth:
            # The value itself was observed, but nothing below it was.
            self.depth_exceeded = True
            return

        if kind == T_OBJECT:
            if depth + 1 > limits.max_json_depth:
                self.truncated_depth = True
            for index, (key, child) in enumerate(value.items()):
                if index >= limits.max_json_keys:
                    self.truncated_keys = True
                    break
                node = self.children.get(key)
                if node is None:
                    node = _Node()
                    self.children[key] = node
                node.observe(child, limits, depth + 1)
        elif kind == T_ARRAY:
            if self.items is None:
                self.items = _Node()
            for element in value[: limits.max_json_keys]:
                self.items.observe(element, limits, depth + 1)

    def serialise(
        self,
        limits: Limits,
        depth: int = 0,
        parent_total: int | None = None,
    ) -> dict[str, Any]:
        """Render the accumulated observations.

        ``parent_total`` is the number of observations of the *parent* value; it
        is what makes "optional" meaningful: a field is optional when it was
        missing from at least one of the parent's observations.
        """
        observed = sorted(self.types)
        dominant = self.types.most_common(1)[0][0] if self.types else T_UNKNOWN
        conflicting = len(observed) > 1

        node: dict[str, Any] = {
            "type": dominant,
            "observed_types": observed,
            "present_count": self.present,
            "total_count": self.total,
            "optional": parent_total is not None and self.total < parent_total,
            "conflicting": conflicting,
        }
        if conflicting:
            node["type_note"] = (
                "Samples disagreed about the type; the dominant type is shown but the "
                "observation set is reported in observed_types."
            )

        if dominant == T_OBJECT or self.children:
            properties: dict[str, Any] = {}
            for key in sorted(self.children):
                properties[key] = self.children[key].serialise(
                    limits, depth + 1, parent_total=self.total
                )
            node["properties"] = properties
            required = [
                key for key, child in self.children.items() if child.total >= self.total
            ]
            node["required"] = sorted(required)
            node["optional_fields"] = sorted(set(self.children) - set(required))
            if self.truncated_keys:
                node["note"] = "Some keys were not inspected because the key limit was reached"
            elif self.truncated_depth:
                node["note"] = (
                    "Maximum depth reached; the contents of the nested values were not inspected"
                )

        if self.items is not None:
            node["items"] = self.items.serialise(limits, depth + 1, parent_total=self.total)

        if self.depth_exceeded:
            node["note"] = (
                "Maximum depth reached; the contents of this value were not inspected"
            )

        return node


def infer_schema(
    samples: list[Any], *, limits: Limits | None = None
) -> dict[str, Any] | None:
    """Infer a schema from one or more decoded JSON samples.

    Returns ``None`` when there is nothing to infer from.
    """
    limits = limits or Limits()
    if not samples:
        return None

    root = _Node()
    for sample in samples:
        root.observe(sample, limits)

    schema = root.serialise(limits)
    schema["inferred"] = True
    schema["sample_count"] = len(samples)
    schema["source"] = "observed traffic only"
    return schema


def parse_json_samples(
    texts: list[str], *, limits: Limits | None = None
) -> tuple[list[Any], list[str]]:
    """Decode JSON texts, returning ``(samples, errors)``.

    A body that is not valid JSON is skipped and reported rather than
    aborting the whole analysis.
    """
    limits = limits or Limits()
    samples: list[Any] = []
    errors: list[str] = []
    for text in texts:
        if not text:
            continue
        if len(text.encode("utf-8", errors="replace")) > limits.max_body_bytes:
            errors.append("body exceeded the maximum size and was skipped")
            continue
        try:
            samples.append(json.loads(text))
        except (json.JSONDecodeError, ValueError) as exc:
            errors.append(str(exc))
    return samples, errors


def to_json_schema(schema: dict[str, Any] | None) -> dict[str, Any] | None:
    """Convert an internal inferred schema into plain JSON Schema.

    The internal schema carries observation counters (``observed_types``,
    ``present_count`` ...) that are meaningful to TraceForge but are not part
    of JSON Schema.  Those are moved into an ``x-traceforge`` extension so the
    exported document stays a valid JSON Schema while remaining honest about
    what was actually seen.
    """
    if schema is None:
        return None

    converted = _to_json_schema_node(schema)
    if converted is None:
        return None
    extension = _extension_for(schema)
    if extension:
        converted["x-traceforge"] = extension
    return converted


def _extension_for(node: dict[str, Any]) -> dict[str, Any]:
    """Collect the observation metadata of a schema node."""
    extension: dict[str, Any] = {}
    for key in ("observed_types", "present_count", "total_count", "optional", "conflicting"):
        if key in node:
            extension[key] = node[key]
    if node.get("inferred") is not None:
        extension["inferred"] = node["inferred"]
    if node.get("sample_count") is not None:
        extension["sample_count"] = node["sample_count"]
    if node.get("source") is not None:
        extension["source"] = node["source"]
    if node.get("optional_fields"):
        extension["optional_fields"] = node["optional_fields"]
    if node.get("note"):
        extension["note"] = node["note"]
    if node.get("type_note"):
        extension["type_note"] = node["type_note"]
    return extension


def _to_json_schema_node(node: dict[str, Any]) -> dict[str, Any] | None:
    """Convert one schema node (recursively)."""
    if not isinstance(node, dict):
        return None

    kind = node.get("type")
    converted: dict[str, Any] = {}
    if kind and kind != T_UNKNOWN:
        converted["type"] = kind

    properties = node.get("properties")
    if isinstance(properties, dict):
        child_properties: dict[str, Any] = {}
        for key in sorted(properties):
            child = _to_json_schema_node(properties[key])
            if child is not None:
                child_properties[key] = child
        if child_properties:
            converted["properties"] = child_properties

    required = node.get("required")
    if isinstance(required, list) and required:
        converted["required"] = sorted(required)

    items = node.get("items")
    if isinstance(items, dict):
        child_items = _to_json_schema_node(items)
        if child_items is not None:
            converted["items"] = child_items

    if not converted:
        return None
    return converted


def schemas_differ(left: dict[str, Any] | None, right: dict[str, Any] | None) -> list[str]:
    """Return human readable descriptions of the differences between two schemas."""
    if left is None and right is None:
        return []
    if left is None or right is None:
        return ["schema present in only one of the captures"]

    differences: list[str] = []

    def _walk(a: dict[str, Any], b: dict[str, Any], prefix: str) -> None:
        a_props = a.get("properties") or {}
        b_props = b.get("properties") or {}
        for key in sorted(set(a_props) | set(b_props)):
            path = f"{prefix}.{key}" if prefix else key
            if key not in a_props:
                differences.append(f"{path}: added")
                continue
            if key not in b_props:
                differences.append(f"{path}: removed")
                continue
            a_node = a_props[key]
            b_node = b_props[key]
            a_type = a_node.get("type")
            b_type = b_node.get("type")
            a_observed = set(a_node.get("observed_types") or [])
            b_observed = set(b_node.get("observed_types") or [])
            if a_observed != b_observed:
                differences.append(
                    f"{path}: observed types changed from {sorted(a_observed)} to {sorted(b_observed)}"
                )
            elif a_type != b_type:
                differences.append(f"{path}: type changed from {a_type} to {b_type}")
            if bool(a_node.get("optional")) != bool(b_node.get("optional")):
                differences.append(
                    f"{path}: optionality changed "
                    f"(was optional={bool(a_node.get('optional'))}, now optional={bool(b_node.get('optional'))})"
                )
            if a_node.get("type") == T_OBJECT or b_node.get("type") == T_OBJECT:
                _walk(a_node, b_node, path)

        a_items = a.get("items")
        b_items = b.get("items")
        if a_items and b_items:
            _walk(a_items, b_items, f"{prefix}[]" if prefix else "[]")

    _walk(left, right, "")
    return differences
