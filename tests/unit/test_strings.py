"""Unit tests for the bounded string extractor."""

from __future__ import annotations

from traceforge.adapters.binary.strings import (
    extract_strings,
    extract_strings_from_file,
    shannon_entropy,
)
from traceforge.config import Limits


class TestExtractStrings:
    def test_ascii_string_is_found(self) -> None:
        data = b"\x00\x00Hello from TraceForge\x00\x00"
        strings = extract_strings(data)
        assert [item.text for item in strings] == ["Hello from TraceForge"]
        assert strings[0].offset == 2
        assert strings[0].encoding == "ascii"

    def test_utf16le_string_is_found(self) -> None:
        data = b"\x00\x00" + "Wide string".encode("utf-16-le") + b"\x00\x00"
        strings = extract_strings(data)
        assert [item.text for item in strings] == ["Wide string"]
        assert strings[0].encoding == "utf-16le"

    def test_utf16be_string_is_found(self) -> None:
        data = b"\x00\x00" + "Wide string".encode("utf-16-be") + b"\x00\x00"
        strings = extract_strings(data)
        assert [item.text for item in strings] == ["Wide string"]
        assert strings[0].encoding == "utf-16be"

    def test_short_runs_are_ignored(self) -> None:
        strings = extract_strings(b"abc")
        assert strings == []

    def test_minimum_length_is_configurable(self) -> None:
        strings = extract_strings(b"abcd", min_length=10)
        assert strings == []

    def test_results_are_ordered_by_offset(self) -> None:
        data = b"first string\x00second string\x00third string\x00"
        offsets = [item.offset for item in extract_strings(data)]
        assert offsets == sorted(offsets)

    def test_extraction_is_deterministic(self) -> None:
        data = b"alpha string\x00beta string\x00" * 10
        assert extract_strings(data) == extract_strings(data)

    def test_maximum_number_of_strings_is_enforced(self) -> None:
        limits = Limits(max_strings=3)
        data = b"".join(f"string number {index:04d}\x00".encode() for index in range(20))
        strings = extract_strings(data, limits=limits)
        assert len(strings) == 3

    def test_maximum_string_length_is_enforced(self) -> None:
        limits = Limits(max_string_length=8)
        strings = extract_strings(b"a very long string indeed", limits=limits)
        assert all(len(item.text) <= 8 for item in strings)

    def test_scan_is_bounded(self) -> None:
        limits = Limits(max_string_scan_bytes=16)
        data = b"x" * 32 + b"tail string here"
        strings = extract_strings(data, limits=limits)
        assert all(item.offset < 16 for item in strings)


class TestExtractStringsFromFile:
    def test_reads_the_file(self, tmp_path) -> None:
        path = tmp_path / "sample.bin"
        path.write_bytes(b"\x00prefix string\x00")
        strings, truncated = extract_strings_from_file(path)
        assert [item.text for item in strings] == ["prefix string"]
        assert truncated is False

    def test_truncation_is_reported(self, tmp_path) -> None:
        path = tmp_path / "big.bin"
        path.write_bytes(b"a string here" * 1000)
        limits = Limits(max_string_scan_bytes=64)
        strings, truncated = extract_strings_from_file(path, limits=limits)
        assert truncated is True
        assert all(item.offset < 64 for item in strings)


class TestShannonEntropy:
    def test_empty_data(self) -> None:
        assert shannon_entropy(b"") == 0.0

    def test_uniform_data(self) -> None:
        assert shannon_entropy(b"aaaa") == 0.0

    def test_maximum_entropy(self) -> None:
        data = bytes(range(256))
        assert abs(shannon_entropy(data) - 8.0) < 1e-9

    def test_entropy_is_bounded(self) -> None:
        data = b"abcabcabcabcabcabcabcabcabc"
        assert 0.0 <= shannon_entropy(data) <= 8.0
