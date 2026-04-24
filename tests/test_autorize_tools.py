"""
test_autorize_tools.py
──────────────────────
Unit tests for autorize_tools.py session-swap logic and bypass detection.
"""
import json
from unittest.mock import MagicMock, patch

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
        # New value replaces old, old value is consumed (space and all)
        assert "attacker_token" in result
        assert "victim_token_here" not in result

    def test_cookie_preserves_named_prefix(self):
        """Named cookie prefix (PHPSESSID=, JSESSIONID=, etc.) must be preserved."""
        raw = (
            "GET /api/profile HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "Cookie: PHPSESSID=abc123; session=xyz789\r\n"
            "\r\n"
        )
        result = _swap_session_token(raw, "cookie", "hijacked", None)
        assert "PHPSESSID=" in result  # prefix preserved
        assert "hijacked" in result
        assert "abc123" not in result
        assert "session=xyz789" in result  # other cookie values preserved too

    def test_cookie_without_prefix(self):
        """When no named prefix exists, replacement still works cleanly."""
        raw = (
            "GET /api/profile HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "Cookie: bare_token_value\r\n"
            "\r\n"
        )
        result = _swap_session_token(raw, "cookie", "new_token", None)
        assert "Cookie: bare_token_value" not in result
        assert "new_token" in result

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

    def test_bearer_token_with_leading_space(self):
        """Bearer token with space (standard JWT format) must be fully replaced."""
        raw = (
            "GET /api/admin HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjo0Mn0.sig\r\n"
            "\r\n"
        )
        result = _swap_session_token(raw, "bearer", "attacker_jwt_here", None)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
        assert ".eyJ1c2VyX2lkIjo0Mn0.sig" not in result
        assert "attacker_jwt_here" in result
        # Ensure no duplicate/malformed token
        assert result.count("Bearer ") == 1

    def test_bearer_jwt_with_underscores(self):
        """JWT tokens contain underscores in all three segments — regex must handle them."""
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjo0Mn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        raw = (
            "GET /api/admin HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            f"Authorization: Bearer {jwt}\r\n"
            "\r\n"
        )
        result = _swap_session_token(raw, "bearer", "attacker_jwt", None)
        assert jwt not in result
        assert "attacker_jwt" in result

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
        # Cookie header present with new value, old value gone
        assert "new_value" in result
        assert "old_value" not in result

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


class TestAuthorizeMultiRoleTool:
    """Tests for AuthorizeMultiRoleTool error handling."""

    def test_error_response_not_crash(self):
        """MCP error dict must not cause KeyError or AttributeError."""
        tool = AuthorizeMultiRoleTool()
        raw = (
            "GET /api/admin HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "Authorization: Bearer admin_token\r\n"
            "\r\n"
        )

        mock_client = MagicMock()
        mock_client.call.return_value = {
            "error": "Cannot connect to Burp MCP server at 127.0.0.1:9876"
        }

        with patch("pentest_crew.tools.autorize_tools.get_client", return_value=mock_client):
            result = tool._run(
                host="target.example.com",
                port=443,
                use_https=True,
                raw_request=raw,
                role_tokens=[{"role": "admin", "token": "Bearer admin_token", "type": "bearer"}],
            )

        parsed = json.loads(result)
        assert parsed["access_matrix"][0]["error"] is not None
        assert parsed["access_matrix"][0]["access_granted"] is False
        assert parsed["access_matrix"][0]["status_code"] is None

    def test_multiple_roles_one_error_continues(self):
        """When one role fails, other roles are still tested."""
        tool = AuthorizeMultiRoleTool()
        raw = (
            "GET /api/admin HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "Authorization: Bearer token\r\n"
            "\r\n"
        )

        mock_client = MagicMock()
        # First call fails, second succeeds
        mock_client.call.side_effect = [
            {"error": "timeout"},
            {"statusCode": 200, "bodyLength": 512},
        ]

        with patch("pentest_crew.tools.autorize_tools.get_client", return_value=mock_client):
            result = tool._run(
                host="target.example.com",
                port=443,
                use_https=True,
                raw_request=raw,
                role_tokens=[
                    {"role": "admin", "token": "admin_token", "type": "cookie"},
                    {"role": "user", "token": "user_token", "type": "cookie"},
                ],
            )

        parsed = json.loads(result)
        matrix = parsed["access_matrix"]
        assert matrix[0]["role"] == "admin"
        assert matrix[0]["error"] is not None
        assert matrix[1]["role"] == "user"
        assert matrix[1]["status_code"] == 200
        assert matrix[1]["access_granted"] is True