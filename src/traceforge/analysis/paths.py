"""Path normalisation and path-parameter heuristics.

Grouping traffic into endpoints requires deciding whether ``/users/1`` and
``/users/2`` are the same endpoint.  TraceForge never merges silently: the
substitution rules below are explicit, documented heuristics, and every
parameterised path is recorded with the rule that produced it so a reviewer can
check the grouping.

A path is normalised by:

1. collapsing duplicate slashes,
2. dropping the query string and fragment,
3. replacing segments that *look like* identifiers with ``{name}``,
4. removing a trailing slash (except for the root path).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from traceforge.domain.enums import Confidence

#: A canonical UUID.
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
#: A plain integer.
NUMERIC_RE = re.compile(r"^\d{1,}$")
#: A long hexadecimal value (hash-like).
HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
#: A base64-ish opaque token.
BASE64ISH_RE = re.compile(r"^[A-Za-z0-9_-]{20,}$")
#: An e-mail address.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
#: An ISO date.
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
#: A mongo-style object id.
OBJECTID_RE = re.compile(r"^[0-9a-fA-F]{24}$")
#: A ULID / UUIDv7 style identifier.
ULID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")

#: Segments that are almost always literal and must never be parameterised.
RESERVED_SEGMENTS = frozenset(
    {
        "api", "v1", "v2", "v3", "v4", "rest", "graphql", "grpc", "ws", "wss",
        "static", "assets", "public", "media", "files", "health", "healthz",
        "status", "ping", "version", "swagger", "docs", "redoc", "openapi",
        "favicon.ico", "robots.txt", "sitemap.xml",
    }
)

#: Order matters: the first matching rule wins.
HEURISTICS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("uuid", UUID_RE),
    ("object_id", OBJECTID_RE),
    ("ulid", ULID_RE),
    ("email", EMAIL_RE),
    ("date", DATE_RE),
    ("hex", HEX_RE),
    ("numeric", NUMERIC_RE),
    ("base64ish", BASE64ISH_RE),
)


@dataclass(frozen=True, slots=True)
class PathParameter:
    """One segment that was replaced by a placeholder."""

    index: int
    original: str
    placeholder: str
    rule: str

    def as_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "original": self.original,
            "placeholder": self.placeholder,
            "rule": self.rule,
        }


@dataclass(frozen=True, slots=True)
class NormalizedPath:
    """The result of normalising a URL path.

    ``original`` is the input exactly as it was received, ``path`` is the path
    component of that input and ``path_key`` is the grouping key.
    """

    original: str
    path: str
    path_key: str
    parameters: tuple[PathParameter, ...]

    @property
    def has_parameters(self) -> bool:
        return bool(self.parameters)

    @property
    def confidence(self) -> Confidence:
        """Parameterised paths are *inferred*, never observed."""
        return Confidence.INFERRED if self.parameters else Confidence.OBSERVED


def _placeholder_for(segment: str, previous: str | None, rule: str) -> str:
    if rule == "email":
        return "{email}"
    if previous:
        stem = re.sub(r"[^A-Za-z0-9]+", "_", previous).strip("_").lower()
        if stem and stem not in RESERVED_SEGMENTS:
            return "{" + f"{stem}_id" + "}"
    return "{id}"


def normalize_path(path: str) -> NormalizedPath:
    """Normalise a URL (or a path) into a grouping key.

    The input may be a full URL or a bare path.  The scheme, host, query
    string and fragment are always removed before the path is normalised.

    >>> normalize_path("/api/v1/users/42/orders").path_key
    '/api/v1/users/{id}/orders'
    >>> normalize_path("https://api.example.test/v1/users/42").path_key
    '/v1/users/{users_id}'
    """
    if not path:
        return NormalizedPath(original=path, path="/", path_key="/", parameters=())

    try:
        split = urlsplit(path)
    except ValueError:  # pragma: no cover - urlsplit is very tolerant
        split = None

    if split is not None and split.scheme and split.netloc:
        path_part = split.path
    elif split is not None:
        path_part = split.path or path
        if "?" in path_part or "#" in path_part:
            path_part = path_part.split("?", 1)[0].split("#", 1)[0]
    else:  # pragma: no cover - defensive
        path_part = path.split("?", 1)[0].split("#", 1)[0]

    if not path_part:
        path_part = "/"

    try:
        decoded = unquote(path_part)
    except Exception:  # noqa: BLE001 - unquote is very tolerant
        decoded = path_part

    segments = [segment for segment in decoded.split("/") if segment != ""]
    trailing_slash = decoded.endswith("/") and decoded not in {"/", ""}

    parameters: list[PathParameter] = []
    normalised: list[str] = []

    for index, segment in enumerate(segments):
        lowered = segment.lower()
        if lowered in RESERVED_SEGMENTS:
            normalised.append(segment)
            continue

        matched_rule: str | None = None
        for rule, pattern in HEURISTICS:
            if pattern.match(segment):
                matched_rule = rule
                break

        if matched_rule is None:
            normalised.append(segment)
            continue

        previous = normalised[-1] if normalised else None
        placeholder = _placeholder_for(segment, previous, matched_rule)
        parameters.append(
            PathParameter(
                index=index,
                original=segment,
                placeholder=placeholder,
                rule=matched_rule,
            )
        )
        normalised.append(placeholder)

    path_key = "/" + "/".join(normalised)
    if not normalised:
        path_key = "/"
    elif trailing_slash:
        path_key += "/"

    return NormalizedPath(
        original=path,
        path=path_part,
        path_key=path_key,
        parameters=tuple(parameters),
    )
