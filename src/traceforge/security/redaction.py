"""Secret redaction.

Redaction happens **before** anything is written to the database, so a secret
can never leak through a later export.  The redactor is intentionally
conservative: when in doubt it replaces the value.

Design rules:

* Redaction is *value-preserving in shape* - the key names survive so that the
  inventory still shows which parameters existed.
* Redaction is applied to headers, query parameters, request/response bodies
  (for JSON and text), URLs and extracted binary strings.
* The redaction applied is recorded on the value (``redacted=True``) so that
  the UI can render it honestly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from traceforge.config import RedactionSettings

#: A JSON Web Token.
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b")
#: An ``Authorization: Bearer <token>`` style value.
BEARER_RE = re.compile(r"(?i)\b(bearer|basic|token)\s+([A-Za-z0-9\-._~+/]{8,}=*)")
#: ``key=value`` / ``key: value`` pairs for well-known secret names.
ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|pwd|token|access[_-]?token|refresh[_-]?token"
    r"|client[_-]?secret|private[_-]?key)\b(\s*[:=]\s*)(\"|')?([^\s\"',;]{4,})\3?"
)


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """Outcome of a redaction attempt."""

    value: str
    redacted: bool
    rules: tuple[str, ...] = ()

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.redacted


class Redactor:
    """Applies the configured redaction rules to strings and structures."""

    def __init__(self, settings: RedactionSettings | None = None) -> None:
        self.settings = settings or RedactionSettings()
        self._sensitive_headers = {h.lower() for h in self.settings.sensitive_headers}
        self._sensitive_params = {p.lower() for p in self.settings.sensitive_parameters}
        self._extra: list[tuple[str, re.Pattern[str]]] = []
        for raw in self.settings.extra_patterns:
            try:
                self._extra.append((raw, re.compile(raw)))
            except re.error:
                # An invalid user pattern is ignored rather than crashing the
                # whole run; the configured defaults still apply.
                continue

    # ------------------------------------------------------------------
    # primitives
    # ------------------------------------------------------------------
    def is_sensitive_header(self, name: str) -> bool:
        return name.strip().lower() in self._sensitive_headers

    def is_sensitive_param(self, name: str) -> bool:
        return name.strip().lower() in self._sensitive_params

    def redact_text(self, text: str) -> RedactionResult:
        """Apply pattern based redaction to a free-form string."""
        if not text:
            return RedactionResult(value=text, redacted=False)

        rules: list[str] = []
        result = text

        if self.settings.redact_jwt:
            new_result, count = JWT_RE.subn(self.settings.placeholder, result)
            if count:
                rules.append("jwt")
                result = new_result

        if self.settings.redact_bearer:
            new_result, count = BEARER_RE.subn(
                lambda m: f"{m.group(1)} {self.settings.placeholder}", result
            )
            if count:
                rules.append("bearer")
                result = new_result

        new_result, count = ASSIGNMENT_RE.subn(
            lambda m: f"{m.group(1)}{m.group(2)}{m.group(3) or ''}{self.settings.placeholder}",
            result,
        )
        if count:
            rules.append("assignment")
            result = new_result

        for _label, pattern in self._extra:
            result, count = pattern.subn(lambda _m: self.settings.placeholder, result)
            if count:
                rules.append("user_pattern")

        return RedactionResult(value=result, redacted=bool(rules), rules=tuple(dict.fromkeys(rules)))

    def redact_header(self, name: str, value: str) -> RedactionResult:
        """Redact a header value based on the header name and its content."""
        if self.is_sensitive_header(name):
            return RedactionResult(
                value=self.settings.placeholder, redacted=True, rules=("sensitive_header",)
            )
        return self.redact_text(value)

    def redact_param(self, name: str, value: str) -> RedactionResult:
        """Redact a query/body parameter value."""
        if self.is_sensitive_param(name):
            return RedactionResult(
                value=self.settings.placeholder, redacted=True, rules=("sensitive_parameter",)
            )
        return self.redact_text(value)

    # ------------------------------------------------------------------
    # structures
    # ------------------------------------------------------------------
    def redact_headers(self, headers: list[tuple[str, str]]) -> list[tuple[str, str, bool]]:
        """Redact a list of ``(name, value)`` header pairs.

        Returns ``(name, value, redacted)`` triples.
        """
        out: list[tuple[str, str, bool]] = []
        for name, value in headers:
            result = self.redact_header(name, value)
            out.append((name, result.value, result.redacted))
        return out

    def redact_query(self, query: str) -> tuple[str, bool]:
        """Redact a raw query string, preserving parameter names."""
        if not query:
            return "", False
        pairs = parse_qsl(query, keep_blank_values=True)
        if not pairs:
            # Unparseable query: fall back to whole-value redaction of the text.
            result = self.redact_text(query)
            return result.value, result.redacted
        out: list[tuple[str, str]] = []
        changed = False
        for name, value in pairs:
            res = self.redact_param(name, value)
            changed = changed or res.redacted
            out.append((name, res.value))
        return urlencode(out), changed

    def redact_url(self, url: str) -> tuple[str, bool]:
        """Redact a URL's query string and any embedded credentials."""
        if not url:
            return url, False
        try:
            parts = urlsplit(url)
        except ValueError:
            result = self.redact_text(url)
            return result.value, result.redacted

        changed = False
        netloc = parts.netloc
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[1]
            changed = True

        query, q_changed = self.redact_query(parts.query)
        changed = changed or q_changed

        path = parts.path
        path_result = self.redact_text(path)
        if path_result.redacted:
            path = path_result.value
            changed = True

        cleaned = urlunsplit((parts.scheme, netloc, path, query, parts.fragment))
        return cleaned, changed

    def redact_json(self, payload: Any, _depth: int = 0) -> Any:
        """Recursively redact a decoded JSON structure.

        Parameter *names* that are marked sensitive have their values replaced;
        string values are additionally scanned for token-like content.
        """
        if _depth > 32:
            return self.settings.placeholder
        if isinstance(payload, dict):
            out: dict[str, Any] = {}
            for key, value in payload.items():
                if self.is_sensitive_param(str(key)):
                    out[str(key)] = self.settings.placeholder
                else:
                    out[str(key)] = self.redact_json(value, _depth + 1)
            return out
        if isinstance(payload, list):
            return [self.redact_json(item, _depth + 1) for item in payload]
        if isinstance(payload, str):
            return self.redact_text(payload).value
        return payload

    def redact_text_body(self, body: str) -> tuple[str, bool]:
        """Redact a non-JSON text body (form encoded, XML, plain text...)."""
        result = self.redact_text(body)
        return result.value, result.redacted
