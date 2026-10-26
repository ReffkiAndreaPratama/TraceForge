"""Unit tests for the HAR adapter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traceforge.adapters.http.har import HarParseError, parse_har, parse_har_file
from traceforge.config import Limits
from traceforge.domain.enums import DiagnosticLevel
from tests.fixtures.generators import build_har


class TestParseHar:
    def test_entries_are_parsed(self, har_document: dict) -> None:
        capture = parse_har(har_document)
        assert len(capture.entries) == 5
        assert capture.version == "1.2"
        assert capture.creator["name"] == "TraceForge fixtures"

    def test_request_and_response_are_available(self, har_document: dict) -> None:
        capture = parse_har(har_document)
        entry = capture.entries[0]
        assert entry.request.method == "GET"
        assert entry.request.url.startswith("https://api.example.test/")
        assert entry.response.status == 200
        assert entry.response.content is not None
        assert entry.response.content.text is not None

    def test_timings_are_parsed(self, har_document: dict) -> None:
        capture = parse_har(har_document)
        timings = capture.entries[0].timings
        assert timings is not None
        assert timings.wait == 10.0

    def test_query_parameters_are_parsed(self, har_document: dict) -> None:
        capture = parse_har(har_document)
        names = {param.name for param in capture.entries[2].request.query_string}
        assert "redirect" in names

    def test_json_body_is_available(self, har_document: dict) -> None:
        capture = parse_har(har_document)
        post_data = capture.entries[2].request.post_data
        assert post_data is not None
        assert post_data.text is not None
        assert json.loads(post_data.text)["username"] == "ada"

    def test_invalid_json_raises(self) -> None:
        with pytest.raises(HarParseError):
            parse_har("{not json")

    def test_missing_log_raises(self) -> None:
        with pytest.raises(HarParseError):
            parse_har({"entries": []})

    def test_missing_entries_raises(self) -> None:
        with pytest.raises(HarParseError):
            parse_har({"log": {"version": "1.2"}})

    def test_non_object_document_raises(self) -> None:
        with pytest.raises(HarParseError):
            parse_har([1, 2, 3])

    def test_malformed_entries_become_diagnostics(self) -> None:
        document = build_har()
        document["log"]["entries"].append({"request": {"url": "x"}})  # no response
        capture = parse_har(document)
        assert len(capture.entries) == 5
        codes = {d.code for d in capture.diagnostics}
        assert "har.malformed_entries" in codes

    def test_unexpected_version_is_a_diagnostic(self) -> None:
        document = build_har()
        document["log"]["version"] = "2.0"
        capture = parse_har(document)
        assert any(d.code == "har.unexpected_version" for d in capture.diagnostics)

    def test_entry_limit_is_enforced(self) -> None:
        limits = Limits(max_har_entries=2)
        capture = parse_har(build_har(), limits=limits)
        assert len(capture.entries) == 2
        assert any(d.code == "har.entries_truncated" for d in capture.diagnostics)

    def test_base64_content_is_decoded(self) -> None:
        import base64

        payload = base64.b64encode(b'{"a": 1}').decode("ascii")
        document = build_har()
        document["log"]["entries"][0]["response"]["content"] = {
            "size": 8,
            "mimeType": "application/json",
            "text": payload,
            "encoding": "base64",
        }
        capture = parse_har(document)
        content = capture.entries[0].response.content
        assert content is not None
        assert content.text == '{"a": 1}'

    def test_oversized_body_is_truncated(self) -> None:
        limits = Limits(max_body_bytes=32)
        document = build_har()
        document["log"]["entries"][0]["response"]["content"]["text"] = "x" * 500
        capture = parse_har(document, limits=limits)
        content = capture.entries[0].response.content
        assert content is not None
        assert len(content.text) <= 32
        assert content.truncated is True

    def test_invalid_base64_is_reported(self) -> None:
        document = build_har()
        document["log"]["entries"][0]["response"]["content"]["encoding"] = "base64"
        document["log"]["entries"][0]["response"]["content"]["text"] = "!!!not base64!!!"
        capture = parse_har(document)
        assert any(
            d.level == DiagnosticLevel.WARNING for d in capture.diagnostics
        )


class TestRedactionDuringParsing:
    def test_authorization_header_is_redacted(self, har_document: dict) -> None:
        capture = parse_har(har_document)
        header = next(
            h for h in capture.entries[0].request.headers if h.name.lower() == "authorization"
        )
        assert header.value == "[REDACTED]"
        assert header.redacted is True

    def test_cookie_is_redacted(self, har_document: dict) -> None:
        capture = parse_har(har_document)
        header = next(
            h for h in capture.entries[0].response.headers if h.name.lower() == "set-cookie"
        )
        assert header.value == "[REDACTED]"

    def test_body_secret_is_redacted(self, har_document: dict) -> None:
        capture = parse_har(har_document)
        post_data = capture.entries[2].request.post_data
        assert post_data is not None
        assert post_data.text is not None
        assert "hunter2" not in post_data.text
        assert "[REDACTED]" in post_data.text
        assert post_data.redacted is True

    def test_no_secret_reaches_the_capture(self, har_document: dict) -> None:
        capture = parse_har(har_document)
        blob = json.dumps(capture.entries[2].__dict__ if hasattr(capture.entries[2], "__dict__") else {})
        assert "supersecrettoken" not in blob


class TestParseHarFile:
    def test_file_is_read(self, har_file: Path) -> None:
        capture = parse_har_file(har_file)
        assert len(capture.entries) == 5

    def test_oversized_file_is_rejected(self, tmp_path: Path) -> None:
        from traceforge.errors import SecurityLimitExceeded

        path = tmp_path / "big.har"
        path.write_text("x" * 1000, encoding="utf-8")
        with pytest.raises(SecurityLimitExceeded):
            parse_har_file(path, limits=Limits(max_file_bytes=100))
