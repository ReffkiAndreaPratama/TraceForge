"""Security tests for the safety guards.

The properties exercised here are the ones the project promises: untrusted
input is bounded, secrets never reach the database, paths cannot escape the
workspace and imported binaries are never executed.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from traceforge.adapters.http.har import HarParseError, parse_har
from traceforge.config import Limits, RedactionSettings
from traceforge.errors import SecurityLimitExceeded, ValidationError
from traceforge.ingestion.loader import ingest_file
from traceforge.security.paths import resolve_existing_file, safe_join, sanitize_display_name
from traceforge.security.redaction import Redactor
from traceforge.security.validators import validate_input_file
from tests.fixtures.generators import build_har, build_pe

SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "traceforge"


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------
def test_safe_join_blocks_traversal(tmp_path: Path) -> None:
    base = tmp_path / "ws"
    base.mkdir()
    with pytest.raises(ValidationError):
        safe_join(base, "..", "..", "windows", "system32")


def test_safe_join_blocks_absolute_paths(tmp_path: Path) -> None:
    base = tmp_path / "ws"
    base.mkdir()
    with pytest.raises(ValidationError):
        safe_join(base, os.path.abspath(os.sep))


def test_safe_join_blocks_empty_components(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        safe_join(tmp_path, "")


def test_symlinked_input_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"MZ")
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks requires privileges on Windows")
    with pytest.raises(ValidationError):
        resolve_existing_file(link)


def test_display_names_are_sanitised() -> None:
    assert "/" not in sanitize_display_name("../../etc/passwd")
    assert "\\" not in sanitize_display_name("..\\..\\windows\\system32")
    assert sanitize_display_name("CON") != "CON"
    assert sanitize_display_name("") == "unnamed"


# ---------------------------------------------------------------------------
# size limits
# ---------------------------------------------------------------------------
def test_oversized_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "big.bin"
    path.write_bytes(b"x" * 4096)
    with pytest.raises(SecurityLimitExceeded):
        validate_input_file(path, Limits(max_file_bytes=100))


def test_ingest_enforces_the_size_limit(tmp_path: Path) -> None:
    path = tmp_path / "big.bin"
    path.write_bytes(b"x" * 4096)
    with pytest.raises(SecurityLimitExceeded):
        ingest_file(
            path,
            workspace_root=tmp_path / "ws",
            artifact_id="art_test",
            limits=Limits(max_file_bytes=100),
        )


def test_har_entry_limit_is_enforced() -> None:
    capture = parse_har(build_har(), limits=Limits(max_har_entries=1))
    assert len(capture.entries) == 1
    assert any(d.code == "har.entries_truncated" for d in capture.diagnostics)


def test_body_size_limit_is_enforced() -> None:
    document = build_har()
    document["log"]["entries"][0]["response"]["content"]["text"] = "x" * 4096
    capture = parse_har(document, limits=Limits(max_body_bytes=8))
    content = capture.entries[0].response.content
    assert content is not None
    assert content.truncated is True
    assert len(content.text or "") <= 8


# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------
def test_redaction_covers_sensitive_values() -> None:
    redactor = Redactor()
    text = (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.sig "
        "password=hunter2 api_key=abcd1234"
    )
    result = redactor.redact_text(text)
    assert "eyJhbGci" not in result.value
    assert "hunter2" not in result.value
    assert "abcd1234" not in result.value
    assert "[REDACTED]" in result.value


def test_sensitive_headers_are_replaced_entirely() -> None:
    redactor = Redactor()
    result = redactor.redact_header("Authorization", "Bearer abcdefghijklmnop")
    assert result.value == "[REDACTED]"
    assert result.redacted is True


def test_user_patterns_are_applied() -> None:
    settings = RedactionSettings(extra_patterns=(r"CUSTOM-\d+",))
    redactor = Redactor(settings)
    result = redactor.redact_text("value CUSTOM-1234 end")
    assert "CUSTOM-1234" not in result.value
    assert "[REDACTED]" in result.value


# ---------------------------------------------------------------------------
# malformed input
# ---------------------------------------------------------------------------
def test_malformed_har_is_rejected() -> None:
    with pytest.raises(HarParseError):
        parse_har([1, 2, 3])
    with pytest.raises(HarParseError):
        parse_har({"entries": []})
    with pytest.raises(HarParseError):
        parse_har("{not json")


# ---------------------------------------------------------------------------
# binaries are never executed
# ---------------------------------------------------------------------------
def test_analysis_code_contains_no_execution_primitives() -> None:
    """The analysis core must not contain a way to run an imported file."""
    forbidden = ("subprocess", "os.system", "os.exec", "os.popen", "eval(", "exec(")
    offenders: list[str] = []
    for path in SRC_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for needle in forbidden:
            if needle in text:
                offenders.append(f"{path.relative_to(SRC_ROOT)}: {needle}")
    assert offenders == []


def test_importing_a_binary_only_reads_bytes(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(build_pe())
    ingested = ingest_file(
        path,
        workspace_root=tmp_path / "ws",
        artifact_id="art_sample",
        kind=None,
    )
    assert ingested.sha256
    assert ingested.size_bytes > 0
    # The stored copy is byte identical; nothing was executed or transformed.
    assert ingested.stored_path is not None
    assert ingested.stored_path.read_bytes() == path.read_bytes()
