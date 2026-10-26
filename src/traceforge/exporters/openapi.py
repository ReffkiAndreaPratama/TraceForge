"""OpenAPI 3.1 export.

The generated document describes **only what was observed**.  Every operation
carries an ``x-traceforge`` extension recording how the information was
derived, so a consumer can tell an observed contract from an inferred one.
"""

from __future__ import annotations

import re
from typing import Any

from traceforge.analysis.schema import to_json_schema
from traceforge.version import __version__

OPENAPI_VERSION = "3.1.0"

#: Matches a ``{name}`` placeholder in a normalised path.
_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z0-9_]+)\}")

#: Extension key used to attach TraceForge metadata.
EXTENSION = "x-traceforge"

#: Limitations attached to every generated operation.
_GLOBAL_LIMITATIONS = [
    "This document was generated from observed traffic only.",
    "Endpoints that were never observed are not present.",
    "Schemas are inferred from the samples that were captured and may be incomplete.",
    "Path parameters were inserted by a documented heuristic and may be wrong.",
]


def _path_parameters(path_key: str) -> list[dict[str, Any]]:
    parameters: list[dict[str, Any]] = []
    for name in _PLACEHOLDER_RE.findall(path_key):
        parameters.append(
            {
                "name": name,
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
                "description": "Parameter inferred from observed path values.",
                EXTENSION: {"inferred": True, "source": "path heuristic"},
            }
        )
    return parameters


def _query_parameters(query_params: list[str]) -> list[dict[str, Any]]:
    parameters: list[dict[str, Any]] = []
    for name in sorted(set(query_params)):
        parameters.append(
            {
                "name": name,
                "in": "query",
                "required": False,
                "schema": {"type": "string"},
                "description": "Parameter observed in the query string.",
                EXTENSION: {"observed": True},
            }
        )
    return parameters


def _media_type(content_types: list[str], fallback: str = "application/json") -> str:
    for candidate in content_types:
        if candidate and "/" in candidate:
            return candidate.split(";")[0].strip()
    return fallback


def _response_description(status: int) -> str:
    descriptions = {
        200: "OK",
        201: "Created",
        202: "Accepted",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        409: "Conflict",
        422: "Unprocessable Entity",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
    }
    return descriptions.get(status, "Observed response")


def build_openapi(
    endpoints: list[Any],
    *,
    title: str = "TraceForge observed API",
    version: str = "0.1.0",
    description: str | None = None,
) -> dict[str, Any]:
    """Build an OpenAPI 3.1 document from a list of endpoint rows.

    ``endpoints`` are :class:`traceforge.storage.models.ApiEndpointRow` objects
    (or any object exposing the same attributes).
    """
    paths: dict[str, dict[str, Any]] = {}
    servers: dict[str, str] = {}

    for endpoint in endpoints:
        path_key = endpoint.path_key
        operation = paths.setdefault(path_key, {})

        parameters = _path_parameters(path_key) + _query_parameters(
            endpoint.query_params_json or []
        )

        responses: dict[str, Any] = {}
        for status in sorted(endpoint.status_codes_json or []):
            response: dict[str, Any] = {
                "description": _response_description(int(status)),
                EXTENSION: {"observed": True, "observed_status": int(status)},
            }
            schema = endpoint.response_schema_json
            if schema:
                media = _media_type(endpoint.content_types_json or [])
                response["content"] = {media: {"schema": to_json_schema(schema)}}
            responses[str(int(status))] = response

        if not responses:
            responses["default"] = {
                "description": "No response status was observed for this endpoint.",
                EXTENSION: {"observed": False},
            }

        request_body: dict[str, Any] | None = None
        if endpoint.request_schema_json:
            media = _media_type(endpoint.content_types_json or [], "application/json")
            request_body = {
                "content": {media: {"schema": to_json_schema(endpoint.request_schema_json)}},
                "required": False,
                EXTENSION: {"inferred": True},
            }

        content_types = endpoint.content_types_json or []
        operation_info: dict[str, Any] = {
            "operationId": _operation_id(endpoint.method, path_key),
            "summary": f"Observed {endpoint.method} {path_key}",
            "description": (
                f"Observed {endpoint.count} time(s) in imported traffic captures."
            ),
            "tags": [endpoint.host],
            "responses": responses,
            EXTENSION: {
                "observed": True,
                "confidence": endpoint.confidence,
                "observed_count": endpoint.count,
                "status_codes": endpoint.status_codes_json or [],
                "content_types": content_types,
                "origin": endpoint.origin,
                "path_key": path_key,
                "limitations": list(endpoint.limitations_json or []),
            },
        }
        if parameters:
            operation_info["parameters"] = parameters
        if request_body:
            operation_info["requestBody"] = request_body

        method = endpoint.method.lower()
        if method in {"get", "put", "post", "delete", "options", "head", "patch", "trace"}:
            operation[method] = operation_info

        origin = endpoint.origin
        if origin:
            servers[origin] = origin

    document: dict[str, Any] = {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": title,
            "version": version,
            "description": description
            or (
                "OpenAPI 3.1 document generated by TraceForge from observed HTTP traffic. "
                "It is a record of what was seen, not a contract guaranteed by the server."
            ),
        },
        "paths": dict(sorted(paths.items())),
        EXTENSION: {
            "generator": {"name": "traceforge", "version": __version__},
            "inferred": True,
            "limitations": _GLOBAL_LIMITATIONS,
        },
    }
    if servers:
        document["servers"] = [{"url": url} for url in sorted(servers)]
    return document


def _operation_id(method: str, path_key: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", path_key).strip("_")
    return f"{method.lower()}_{slug}" if slug else method.lower()
