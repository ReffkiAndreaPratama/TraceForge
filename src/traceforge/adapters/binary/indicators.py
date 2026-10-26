"""Extraction of network indicators from free-form text.

These heuristics are deliberately *literal*: they report what a string looks
like, never what it means.  A domain found inside a binary is evidence that
the domain string is present - not evidence that the binary talks to it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

#: Matches http(s) URLs.
URL_RE = re.compile(
    r"""(?i)\b(?:https?|wss?|ftp)://[^\s"'<>`\\^\[\]{}|]+""",
)

#: Matches a hostname with at least one dot and a plausible TLD.
DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|edu|gov|mil|int|io|dev|app|ai|co|xyz|info|biz|me|tv|cc|"
    r"cloud|online|site|tech|store|shop|blog|api|local|localhost|test|internal|"
    r"example|invalid|uk|de|fr|nl|be|ch|at|es|it|pt|pl|se|no|fi|dk|cz|hu|ro|"
    r"ru|ua|tr|il|in|sg|hk|tw|jp|kr|cn|au|nz|br|mx|ar|cl|co|za|ng|ke|eg|"
    r"us|ca|uk|eu|asia)\b"
)

#: Hostname:port pairs.
HOSTPORT_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63})(?::\d{1,5})\b"
)

#: IP addresses (v4 and v6).
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"(?i)\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b")

#: Strings that look like file paths on Windows or POSIX.
PATH_RE = re.compile(r"(?:[A-Za-z]:\\[^\s\"']{3,}|(?:/[\w.\-]+){2,}/?)\b")

#: Trailing characters that are usually punctuation rather than URL content.
_URL_TRAILING = ".,;:)]}>\"'"


def _clean_url(url: str) -> str:
    return url.rstrip(_URL_TRAILING)


def extract_urls(texts: Iterable[str]) -> list[str]:
    """Return the sorted, de-duplicated URLs found in ``texts``."""
    found: set[str] = set()
    for text in texts:
        for match in URL_RE.finditer(text):
            url = _clean_url(match.group(0))
            if len(url) > len("http://"):
                found.add(url)
    return sorted(found)


def extract_domains(texts: Iterable[str]) -> list[str]:
    """Return the sorted, de-duplicated hostnames found in ``texts``.

    Hostnames that are part of a URL are included: they are still literal
    observations about the binary's content.
    """
    found: set[str] = set()
    for text in texts:
        for match in DOMAIN_RE.finditer(text):
            host = match.group(0).lower().rstrip(".")
            if len(host) > 4:
                found.add(host)
        for match in HOSTPORT_RE.finditer(text):
            host = match.group(0).split(":")[0].lower().rstrip(".")
            if len(host) > 4:
                found.add(host)
    return sorted(found)


def extract_ip_addresses(texts: Iterable[str]) -> list[str]:
    """Return the sorted, de-duplicated IP addresses found in ``texts``."""
    found: set[str] = set()
    for text in texts:
        for match in IPV4_RE.finditer(text):
            candidate = match.group(0)
            octets = candidate.split(".")
            if all(octet.isdigit() and int(octet) <= 255 for octet in octets):
                found.add(candidate)
    return sorted(found)


def extract_paths(texts: Iterable[str]) -> list[str]:
    """Return the sorted, de-duplicated filesystem paths found in ``texts``."""
    found: set[str] = set()
    for text in texts:
        for match in PATH_RE.finditer(text):
            path = match.group(0)
            if len(path) > 4:
                found.add(path)
    return sorted(found)
