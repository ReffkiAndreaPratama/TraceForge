"""Unit tests for the redaction pipeline."""

from __future__ import annotations

import pytest

from traceforge.config import RedactionSettings
from traceforge.security.redaction import Redactor


@pytest.fixture
def redactor() -> Redactor:
    return Redactor(RedactionSettings())


class TestRedactText:
    def test_jwt_is_replaced(self, redactor: Redactor) -> None:
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl"
        result = redactor.redact_text(f"token is {token} here")
        assert token not in result.value
        assert result.redacted is True
        assert "jwt" in result.rules

    def test_bearer_token_is_replaced(self, redactor: Redactor) -> None:
        result = redactor.redact_text("Authorization: Bearer abcdef0123456789")
        assert "abcdef0123456789" not in result.value
        assert result.redacted is True
        assert "bearer" in result.rules

    def test_password_assignment_is_replaced(self, redactor: Redactor) -> None:
        result = redactor.redact_text("password=hunter2&user=ada")
        assert "hunter2" not in result.value
        assert result.redacted is True
        assert "assignment" in result.rules

    def test_ordinary_text_is_untouched(self, redactor: Redactor) -> None:
        result = redactor.redact_text("https://api.example.test/v1/users")
        assert result.value == "https://api.example.test/v1/users"
        assert result.redacted is False

    def test_empty_text(self, redactor: Redactor) -> None:
        assert redactor.redact_text("").redacted is False

    def test_user_pattern_is_applied(self) -> None:
        settings = RedactionSettings(extra_patterns=(r"CUSTOM-\d+",))
        redactor = Redactor(settings)
        result = redactor.redact_text("value CUSTOM-1234 end")
        assert "CUSTOM-1234" not in result.value
        assert "user_pattern" in result.rules

    def test_invalid_user_pattern_is_ignored(self) -> None:
        settings = RedactionSettings(extra_patterns=("[unclosed",))
        redactor = Redactor(settings)
        # The default rules still work.
        assert redactor.redact_text("password=hunter2").redacted is True


class TestRedactHeader:
    def test_sensitive_header_is_replaced_entirely(self, redactor: Redactor) -> None:
        result = redactor.redact_header("Authorization", "Bearer abcdef0123456789")
        assert result.value == "[REDACTED]"
        assert result.redacted is True
        assert "sensitive_header" in result.rules

    def test_header_name_matching_is_case_insensitive(self, redactor: Redactor) -> None:
        assert redactor.redact_header("AUTHORIZATION", "x").redacted is True
        assert redactor.redact_header("Set-Cookie", "x").redacted is True

    def test_non_sensitive_header_keeps_its_value(self, redactor: Redactor) -> None:
        result = redactor.redact_header("Content-Type", "application/json")
        assert result.value == "application/json"
        assert result.redacted is False


class TestRedactParam:
    def test_sensitive_parameter_is_replaced(self, redactor: Redactor) -> None:
        result = redactor.redact_param("password", "hunter2")
        assert result.value == "[REDACTED]"
        assert result.redacted is True

    def test_parameter_names_survive(self, redactor: Redactor) -> None:
        query, changed = redactor.redact_query("user=ada&password=hunter2")
        assert "password=" in query
        assert "hunter2" not in query
        assert changed is True


class TestRedactUrl:
    def test_query_values_are_redacted_but_names_survive(self, redactor: Redactor) -> None:
        url, changed = redactor.redact_url("https://api.example.test/v1/x?token=abc123&q=1")
        assert "abc123" not in url
        assert "token=" in url
        assert "q=1" in url
        assert changed is True

    def test_embedded_credentials_are_removed(self, redactor: Redactor) -> None:
        url, changed = redactor.redact_url("https://user:pass@api.example.test/v1")
        assert "pass" not in url
        assert "api.example.test" in url
        assert changed is True

    def test_plain_url_is_untouched(self, redactor: Redactor) -> None:
        url, changed = redactor.redact_url("https://api.example.test/v1/users")
        assert url == "https://api.example.test/v1/users"
        assert changed is False


class TestRedactJson:
    def test_sensitive_keys_are_replaced(self, redactor: Redactor) -> None:
        payload = {"username": "ada", "password": "hunter2", "nested": {"token": "abc123"}}
        cleaned = redactor.redact_json(payload)
        assert cleaned["username"] == "ada"
        assert cleaned["password"] == "[REDACTED]"
        assert cleaned["nested"]["token"] == "[REDACTED]"

    def test_lists_are_traversed(self, redactor: Redactor) -> None:
        cleaned = redactor.redact_json([{"password": "hunter2"}])
        assert cleaned[0]["password"] == "[REDACTED]"

    def test_non_string_values_are_preserved(self, redactor: Redactor) -> None:
        cleaned = redactor.redact_json({"count": 3, "ok": True, "none": None})
        assert cleaned == {"count": 3, "ok": True, "none": None}

    def test_depth_is_bounded(self, redactor: Redactor) -> None:
        payload: dict = {}
        node = payload
        for _ in range(50):
            node["child"] = {}
            node = node["child"]
        cleaned = redactor.redact_json(payload)
        # The traversal must terminate; the deep value is replaced.
        assert isinstance(cleaned, dict)
