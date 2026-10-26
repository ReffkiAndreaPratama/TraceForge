"""HAR (HTTP Archive) 1.2 adapter.

A HAR file is *untrusted input*.  This adapter therefore:

* validates the outer structure before touching the entries,
* bounds the number of entries and the size of retained bodies,
* tolerates individual malformed entries (they become diagnostics, not
  failures),
* **redacts before returning**: secrets are removed here, so they never reach
  the database and can never leak through an export.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from traceforge.config import Limits
from traceforge.domain.enums import DiagnosticLevel
from traceforge.domain.models import Diagnostic
from traceforge.security.redaction import Redactor

HAR_VERSION = "1.2"


@dataclass(slots=True)
class HarHeader:
    name: str
    value: str
    redacted: bool = False


@dataclass(slots=True)
class HarParam:
    name: str
    value: str
    redacted: bool = False


@dataclass(slots=True)
class HarPostData:
    mime_type: str | None = None
    text: str | None = None
    params: list[HarParam] = field(default_factory=list)
    truncated: bool = False
    redacted: bool = False


@dataclass(slots=True)
class HarRequest:
    method: str
    url: str
    http_version: str | None = None
    headers: list[HarHeader] = field(default_factory=list)
    query_string: list[HarParam] = field(default_factory=list)
    post_data: HarPostData | None = None
    body_size: int | None = None
    cookie_count: int = 0


@dataclass(slots=True)
class HarContent:
    size: int | None = None
    mime_type: str | None = None
    text: str | None = None
    encoding: str | None = None
    truncated: bool = False
    redacted: bool = False


@dataclass(slots=True)
class HarResponse:
    status: int
    status_text: str | None = None
    headers: list[HarHeader] = field(default_factory=list)
    content: HarContent | None = None
    body_size: int | None = None
    redirect_url: str | None = None
    cookie_count: int = 0


@dataclass(slots=True)
class HarTimings:
    blocked: float | None = None
    dns: float | None = None
    connect: float | None = None
    send: float | None = None
    wait: float | None = None
    receive: float | None = None
    ssl: float | None = None

    def as_dict(self) -> dict[str, float]:
        return {
            f.name: getattr(self, f.name)
            for f in dataclasses.fields(self)
            if getattr(self, f.name) is not None
        }


@dataclass(slots=True)
class HarEntry:
    index: int
    started_date_time: str | None
    time_ms: float | None
    request: HarRequest
    response: HarResponse
    timings: HarTimings | None = None
    server_ip: str | None = None
    connection: str | None = None
    pageref: str | None = None


@dataclass(slots=True)
class HarCapture:
    """A parsed and redacted HAR capture."""

    version: str
    creator: dict[str, str]
    entries: list[HarEntry] = field(default_factory=list)
    page_count: int = 0
    comment: str | None = None
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(d.level == DiagnosticLevel.ERROR for d in self.diagnostics)


class HarParseError(Exception):
    """Raised when a file is not a usable HAR document at all."""


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return None


def _parse_headers(raw: Any, redactor: Redactor) -> list[HarHeader]:
    headers: list[HarHeader] = []
    if not isinstance(raw, list):
        return headers
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = _as_str(item.get("name"))
        if name is None:
            continue
        value = _as_str(item.get("value")) or ""
        result = redactor.redact_header(name, value)
        headers.append(HarHeader(name=name, value=result.value, redacted=result.redacted))
    return headers


def _parse_params(raw: Any, redactor: Redactor) -> list[HarParam]:
    params: list[HarParam] = []
    if not isinstance(raw, list):
        return params
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = _as_str(item.get("name"))
        if name is None:
            continue
        value = _as_str(item.get("value")) or ""
        result = redactor.redact_param(name, value)
        params.append(HarParam(name=name, value=result.value, redacted=result.redacted))
    return params


def _decode_content(
    content: Any, redactor: Redactor, limits: Limits
) -> tuple[HarContent | None, Diagnostic | None]:
    if not isinstance(content, dict):
        return None, None

    size = content.get("size")
    size = size if isinstance(size, int) else None
    mime_type = _as_str(content.get("mimeType"))
    encoding = _as_str(content.get("encoding"))
    text = _as_str(content.get("text"))

    truncated = False
    redacted = False
    diagnostic: Diagnostic | None = None

    if text is not None:
        if encoding and encoding.lower() == "base64":
            try:
                raw = base64.b64decode(text, validate=False)
            except (binascii.Error, ValueError):
                raw = None
            if raw is None:
                diagnostic = Diagnostic(
                    level=DiagnosticLevel.WARNING,
                    code="har.bad_base64",
                    message="Response body is marked base64 but could not be decoded",
                )
                text = None
            else:
                if len(raw) > limits.max_body_bytes:
                    raw = raw[: limits.max_body_bytes]
                    truncated = True
                text = raw.decode("utf-8", errors="replace")
        elif len(text.encode("utf-8", errors="replace")) > limits.max_body_bytes:
            encoded = text.encode("utf-8", errors="replace")[: limits.max_body_bytes]
            text = encoded.decode("utf-8", errors="replace")
            truncated = True

        if text is not None:
            if mime_type and "json" in mime_type.lower():
                text, was_redacted = _redact_json_text(text, redactor)
                redacted = redacted or was_redacted
            else:
                cleaned_text, was_redacted = redactor.redact_text_body(text)
                text = cleaned_text
                redacted = redacted or was_redacted

    return (
        HarContent(
            size=size,
            mime_type=mime_type,
            text=text,
            encoding=encoding,
            truncated=truncated,
            redacted=redacted,
        ),
        diagnostic,
    )


def _redact_json_text(text: str, redactor: Redactor) -> tuple[str, bool]:
    """Redact a JSON body while preserving the original text when possible.

    The body is only re-serialised when something actually had to be
    redacted; otherwise the captured bytes are kept verbatim so that the
    stored evidence matches what was observed.
    """
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return redactor.redact_text_body(text)

    cleaned = redactor.redact_json(payload)
    if cleaned == payload:
        return text, False
    try:
        return json.dumps(cleaned, sort_keys=True, separators=(",", ":")), True
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return redactor.redact_text_body(text)


def _parse_post_data(raw: Any, redactor: Redactor, limits: Limits) -> HarPostData | None:
    if not isinstance(raw, dict):
        return None
    mime_type = _as_str(raw.get("mimeType"))
    text = _as_str(raw.get("text"))
    params = _parse_params(raw.get("params"), redactor)

    truncated = False
    redacted = any(p.redacted for p in params)

    if text is not None:
        if len(text.encode("utf-8", errors="replace")) > limits.max_body_bytes:
            text = text.encode("utf-8", errors="replace")[: limits.max_body_bytes].decode(
                "utf-8", errors="replace"
            )
            truncated = True
        if mime_type and "json" in mime_type.lower():
            text, was_redacted = _redact_json_text(text, redactor)
            redacted = redacted or was_redacted
        else:
            cleaned_text, was_redacted = redactor.redact_text_body(text)
            text = cleaned_text
            redacted = redacted or was_redacted

    return HarPostData(
        mime_type=mime_type,
        text=text,
        params=params,
        truncated=truncated,
        redacted=redacted,
    )


def _parse_timings(raw: Any) -> HarTimings | None:
    if not isinstance(raw, dict):
        return None

    def _num(key: str) -> float | None:
        value = raw.get(key)
        return float(value) if isinstance(value, (int, float)) else None

    return HarTimings(
        blocked=_num("blocked"),
        dns=_num("dns"),
        connect=_num("connect"),
        send=_num("send"),
        wait=_num("wait"),
        receive=_num("receive"),
        ssl=_num("ssl"),
    )


def parse_har(
    data: bytes | str | dict,
    *,
    limits: Limits | None = None,
    redactor: Redactor | None = None,
) -> HarCapture:
    """Parse HAR bytes (or an already decoded object) into a redacted capture.

    Raises :class:`HarParseError` only when the document is not a HAR file at
    all.  Problems with individual entries are reported as diagnostics.
    """
    limits = limits or Limits()
    redactor = redactor or Redactor()

    if isinstance(data, dict):
        document: Any = data
    elif isinstance(data, str):
        try:
            document = json.loads(data)
        except (json.JSONDecodeError, ValueError) as exc:
            raise HarParseError(f"The file is not valid JSON: {exc}") from exc
    elif isinstance(data, (bytes, bytearray, memoryview)):
        try:
            document = json.loads(bytes(data).decode("utf-8"))
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
            raise HarParseError(f"The file is not valid UTF-8 JSON: {exc}") from exc
    else:
        raise HarParseError(
            "The HAR document must be a JSON object, JSON text or bytes"
        )

    if not isinstance(document, dict):
        raise HarParseError("The HAR document must be a JSON object")

    log = document.get("log")
    if not isinstance(log, dict):
        raise HarParseError("The HAR document has no 'log' object")

    diagnostics: list[Diagnostic] = []

    version = _as_str(log.get("version")) or HAR_VERSION
    if version.split(".")[0] != "1":
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.WARNING,
                code="har.unexpected_version",
                message=f"HAR version '{version}' was not expected; parsing as 1.2",
            )
        )

    creator_raw = log.get("creator")
    creator: dict[str, str] = {}
    if isinstance(creator_raw, dict):
        name = _as_str(creator_raw.get("name"))
        creator_version = _as_str(creator_raw.get("version"))
        if name:
            creator["name"] = name
        if creator_version:
            creator["version"] = creator_version

    raw_entries = log.get("entries")
    if not isinstance(raw_entries, list):
        raise HarParseError("The HAR document has no 'log.entries' array")

    pages = log.get("pages")
    page_count = len(pages) if isinstance(pages, list) else 0

    entries: list[HarEntry] = []
    truncated_entries = 0
    malformed_entries = 0

    for index, raw_entry in enumerate(raw_entries):
        if len(entries) >= limits.max_har_entries:
            truncated_entries += 1
            continue
        if not isinstance(raw_entry, dict):
            malformed_entries += 1
            continue

        request_raw = raw_entry.get("request")
        response_raw = raw_entry.get("response")
        if not isinstance(request_raw, dict) or not isinstance(response_raw, dict):
            malformed_entries += 1
            continue

        url = _as_str(request_raw.get("url"))
        method = _as_str(request_raw.get("method"))
        if not url or not method:
            malformed_entries += 1
            continue

        clean_url, _ = redactor.redact_url(url)

        request = HarRequest(
            method=method.upper(),
            url=clean_url,
            http_version=_as_str(request_raw.get("httpVersion")),
            headers=_parse_headers(request_raw.get("headers"), redactor),
            query_string=_parse_params(request_raw.get("queryString"), redactor),
            post_data=_parse_post_data(request_raw.get("postData"), redactor, limits),
            body_size=request_raw.get("bodySize")
            if isinstance(request_raw.get("bodySize"), int)
            else None,
            cookie_count=len(request_raw.get("cookies") or []),
        )

        content, content_diagnostic = _decode_content(
            response_raw.get("content"), redactor, limits
        )
        if content_diagnostic is not None:
            diagnostics.append(content_diagnostic)

        status = response_raw.get("status")
        response = HarResponse(
            status=status if isinstance(status, int) else 0,
            status_text=_as_str(response_raw.get("statusText")),
            headers=_parse_headers(response_raw.get("headers"), redactor),
            content=content,
            body_size=response_raw.get("bodySize")
            if isinstance(response_raw.get("bodySize"), int)
            else None,
            redirect_url=_as_str(response_raw.get("redirectURL")),
            cookie_count=len(response_raw.get("cookies") or []),
        )

        time_value = raw_entry.get("time")
        entries.append(
            HarEntry(
                index=index,
                started_date_time=_as_str(raw_entry.get("startedDateTime")),
                time_ms=float(time_value) if isinstance(time_value, (int, float)) else None,
                request=request,
                response=response,
                timings=_parse_timings(raw_entry.get("timings")),
                server_ip=_as_str(raw_entry.get("serverIPAddress")),
                connection=_as_str(raw_entry.get("connection")),
                pageref=_as_str(raw_entry.get("pageref")),
            )
        )

    if truncated_entries:
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.WARNING,
                code="har.entries_truncated",
                message=(
                    f"{truncated_entries} entries were skipped because the capture exceeds the "
                    f"configured maximum of {limits.max_har_entries} entries"
                ),
            )
        )
    if malformed_entries:
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.WARNING,
                code="har.malformed_entries",
                message=f"{malformed_entries} entries were malformed and were skipped",
            )
        )

    return HarCapture(
        version=version,
        creator=creator,
        entries=entries,
        page_count=page_count,
        comment=_as_str(log.get("comment")),
        diagnostics=diagnostics,
    )


def parse_har_file(
    path: Path, *, limits: Limits | None = None, redactor: Redactor | None = None
) -> HarCapture:
    """Read and parse a HAR file from disk."""
    limits = limits or Limits()
    size = path.stat().st_size
    if size > limits.max_file_bytes:
        from traceforge.errors import SecurityLimitExceeded

        raise SecurityLimitExceeded(
            "HAR file exceeds the maximum allowed size",
            detail=f"{size} bytes > {limits.max_file_bytes} bytes",
        )
    with path.open("rb") as handle:
        data = handle.read(limits.max_file_bytes + 1)
    return parse_har(data, limits=limits, redactor=redactor)
