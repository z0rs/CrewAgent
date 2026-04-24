"""
test_autorize_tools.py
──────────────────────
Unit tests for autorize_tools.py session-swap logic and bypass detection.
"""
import pytest

from pentest_crew.tools.autorize_tools import (
    AuthorizeCheckTool,
    AuthorizeMultiRoleTool,
    _swap_session_token,
    _remove_auth,
)


class TestSwapSessionToken:
    """Tests for _swap_session_token helper."""

    def test_cookie_token_replacement(self):
        raw = (
            "GET /api/profile HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "Cookie: session= victim_token_here\r\n"
            "\r\n"
        )
        result = _swap_session_token(raw, "cookie", "attacker_token", None)
        # The regex replaces everything after "Cookie:" including "session= " prefix
        assert "Cookie: attacker_token" in result
        assert "victim_token_here" not in result

    def test_bearer_token_replacement(self):
        raw = (
            "GET /api/admin HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "Authorization: Bearer victim_token_here\r\n"
            "\r\n"
        )
        result = _swap_session_token(raw, "bearer", "attacker_bearer", None)
        assert "Authorization: Bearer attacker_bearer" in result
        assert "victim_token_here" not in result

    def test_custom_header_token_replacement(self):
        raw = (
            "GET /api/data HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "X-API-Key: old_api_key\r\n"
            "\r\n"
        )
        result = _swap_session_token(raw, "header", "new_api_key", "X-API-Key")
        assert "X-API-Key: new_api_key" in result
        assert "old_api_key" not in result

    def test_cookie_case_insensitive(self):
        raw = (
            "GET /api/profile HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "cookie: old_value\r\n"
            "\r\n"
        )
        result = _swap_session_token(raw, "cookie", "new_value", None)
        assert "cookie: new_value" in result.lower()

    def test_no_matching_header_leaves_request_unchanged(self):
        raw = (
            "GET /api/profile HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "Accept: application/json\r\n"
            "\r\n"
        )
        result = _swap_session_token(raw, "bearer", "some_token", None)
        assert result == raw


class TestRemoveAuth:
    """Tests for _remove_auth helper."""

    def test_removes_cookie_header(self):
        raw = (
            "GET /api/profile HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "Cookie: session=secret123\r\n"
            "Accept: application/json\r\n"
            "\r\n"
        )
        result = _remove_auth(raw)
        assert "Cookie:" not in result
        assert "Accept:" in result
        assert "GET /api/profile" in result

    def test_removes_authorization_header(self):
        raw = (
            "POST /api/data HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "Authorization: Bearer eyJxxx\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
        )
        result = _remove_auth(raw)
        assert "Authorization:" not in result
        assert "Content-Type:" in result

    def test_removes_both_cookie_and_authorization(self):
        raw = (
            "GET /admin HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "Cookie: session=abc\r\n"
            "Authorization: Bearer tok\r\n"
            "\r\n"
        )
        result = _remove_auth(raw)
        assert "Cookie:" not in result
        assert "Authorization:" not in result

    def test_preserves_non_auth_headers(self):
        raw = (
            "GET /api HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "User-Agent: TestAgent/1.0\r\n"
            "Accept: */*\r\n"
            "\r\n"
        )
        result = _remove_auth(raw)
        assert "User-Agent:" in result
        assert "Accept:" in result

    def test_no_auth_headers_unchanged(self):
        raw = (
            "GET /public HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "\r\n"
        )
        result = _remove_auth(raw)
        assert result == raw


class TestNormalizedBodyMatch:
    """Tests for AuthorizeCheckTool._normalized_body_match static method."""

    def test_identical_bodies_match(self):
        body = '{"user_id": 42, "name": "Alice"}'
        assert AuthorizeCheckTool._normalized_body_match(body, body) is True

    def test_different_dynamic_ids_rejected(self):
        a = '{"id": 100, "name": "Alice"}'
        b = '{"id": 200, "name": "Bob"}'
        # Different IDs with different names → structural mismatch after normalization
        result = AuthorizeCheckTool._normalized_body_match(a, b)
        # Normalization replaces id values but NOT names, so normalized strings differ
        assert result is False

    def test_same_user_different_id_field_replaced(self):
        # Same structure, different id values → should match after normalization
        a = '{"user_id": 42, "name": "Alice"}'
        b = '{"user_id": 99, "name": "Alice"}'
        result = AuthorizeCheckTool._normalized_body_match(a, b)
        assert result is True

    def test_timestamps_stripped(self):
        a = '{"created_at": "2026-04-24T10:00:00Z", "name": "Alice"}'
        b = '{"created_at": "2026-05-01T15:30:00Z", "name": "Alice"}'
        assert AuthorizeCheckTool._normalized_body_match(a, b) is True

    def test_email_addresses_normalized(self):
        a = '{"contact": "alice@example.com"}'
        b = '{"contact": "bob@example.com"}'
        assert AuthorizeCheckTool._normalized_body_match(a, b) is True

    def test_whitespace_normalized(self):
        a = '{"name":  "Alice"}'  # extra space
        b = '{"name": "Alice"}'
        assert AuthorizeCheckTool._normalized_body_match(a, b) is True

    def test_completely_different_structures_rejected(self):
        a = '{"user": {"name": "Alice", "id": 42}}'
        b = '{"order": {"total": 100}}'
        assert AuthorizeCheckTool._normalized_body_match(a, b) is False