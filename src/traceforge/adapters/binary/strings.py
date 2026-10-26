"""Bounded string extraction.

TraceForge implements a *small*, deliberate string extractor instead of
depending on an external tool.  The reasons are control over encoding
detection, deterministic output and hard bounds on the work performed.

Two encodings are recognised:

* printable ASCII (7-bit), and
* UTF-16LE (ASCII code units with a NUL high byte), which is what Windows
  binaries use for wide strings.

The extractor never interprets the extracted text.  Any meaning is assigned
downstream by the analysis engine, which keeps the provenance chain intact.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from traceforge.config import Limits

#: Printable 7-bit ASCII characters that are considered part of a string.
_ASCII_CHARS = rb"[\x20-\x7e]"

#: UTF-16LE: printable ASCII followed by a NUL byte, repeated.
_UTF16LE_CHARS = rb"(?:[\x20-\x7e]\x00)"

#: UTF-16BE: NUL byte followed by printable ASCII, repeated.
_UTF16BE_CHARS = rb"(?:\x00[\x20-\x7e])"


def _compile_runs(min_length: int) -> tuple[re.Pattern[bytes], ...]:
    """Build the run matchers for a minimum string length.

    The patterns are compiled per call because the minimum length is a
    runtime setting rather than a constant.
    """
    length = max(1, min_length)
    return (
        re.compile(_ASCII_CHARS + b"{" + str(length).encode("ascii") + b",}"),
        re.compile(_UTF16LE_CHARS + b"{" + str(length).encode("ascii") + b",}"),
        re.compile(_UTF16BE_CHARS + b"{" + str(length).encode("ascii") + b",}"),
    )


@dataclass(frozen=True, slots=True)
class ExtractedString:
    """A single extracted string with its location."""

    offset: int
    text: str
    encoding: str


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy (bits per byte, 0.0 - 8.0) of ``data``."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def extract_strings(
    data: bytes,
    *,
    limits: Limits | None = None,
    min_length: int | None = None,
) -> list[ExtractedString]:
    """Extract printable ASCII and UTF-16 strings from ``data``.

    The scan is bounded by ``limits.max_string_scan_bytes``; the result is
    bounded by ``limits.max_strings``.  Output ordering is deterministic
    (by offset, then encoding) so that repeated runs produce identical output.

    A wide string stored at an odd offset is matched twice: once as UTF-16LE
    and once as UTF-16BE (the byte pairs shift).  Duplicated text that
    overlaps an already accepted match is dropped so that a single logical
    string is reported once.
    """
    limits = limits or Limits()
    min_len = min_length or limits.min_string_length
    scan_limit = limits.max_string_scan_bytes

    if len(data) > scan_limit:
        data = data[:scan_limit]

    ascii_run, utf16le_run, utf16be_run = _compile_runs(min_len)

    candidates: list[tuple[int, int, str, str]] = []
    for match in ascii_run.finditer(data):
        candidates.append(
            (match.start(), match.end(), "ascii", match.group(0).decode("ascii", errors="replace"))
        )
    for match in utf16le_run.finditer(data):
        candidates.append(
            (
                match.start(),
                match.end(),
                "utf-16le",
                match.group(0).decode("utf-16-le", errors="replace"),
            )
        )
    for match in utf16be_run.finditer(data):
        candidates.append(
            (
                match.start(),
                match.end(),
                "utf-16be",
                match.group(0).decode("utf-16-be", errors="replace"),
            )
        )

    candidates.sort(key=lambda item: (item[0], item[2]))

    accepted: list[ExtractedString] = []
    accepted_spans: list[tuple[int, int, str, str]] = []
    for start, end, encoding, text in candidates:
        text = text[: limits.max_string_length]
        candidate = (start, end, encoding, text)
        index = None
        for position, (other_start, other_end, other_encoding, other_text) in enumerate(
            accepted_spans
        ):
            if other_text == text and start < other_end and other_start < end:
                index = position
                break
        if index is None:
            accepted.append(ExtractedString(start, text, encoding))
            accepted_spans.append(candidate)
        elif _is_preferred(candidate, accepted_spans[index]):
            accepted[index] = ExtractedString(start, text, encoding)
            accepted_spans[index] = candidate

    accepted.sort(key=lambda item: (item.offset, item.encoding))
    if len(accepted) > limits.max_strings:
        accepted = accepted[: limits.max_strings]
    return accepted


def _is_preferred(
    candidate: tuple[int, int, str, str], other: tuple[int, int, str, str]
) -> bool:
    """Decide which of two overlapping readings of the same text to keep.

    A wide string can often be read both as UTF-16LE and as UTF-16BE; the
    decoded text is identical, only the reported encoding differs.  The
    reading whose start offset is 2-byte aligned is preferred, because wide
    strings are conventionally aligned inside their container.  Ties are
    broken by the earlier offset and then by the encoding name, so the result
    is deterministic.
    """
    if (candidate[0] % 2) != (other[0] % 2):
        return (candidate[0] % 2) == 0
    if candidate[0] != other[0]:
        return candidate[0] < other[0]
    return candidate[2] < other[2]


def extract_strings_from_file(
    path: Path, *, limits: Limits | None = None
) -> tuple[list[ExtractedString], bool]:
    """Extract strings from a file, returning ``(strings, scan_was_truncated)``."""
    limits = limits or Limits()
    size = path.stat().st_size
    to_read = min(size, limits.max_string_scan_bytes)
    with path.open("rb") as handle:
        data = handle.read(to_read)
    return extract_strings(data, limits=limits), size > to_read
