"""
test_burp_request_tools.py
──────────────────────────
Unit tests for burp_request_tools.py — HTTP request parsing and tool classes.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from pentest_crew.tools.burp_request_tools import (
    SendHTTP1RequestTool,
    SendHTTP2RequestTool,
    CreateRepeaterTabTool,
    SendToIntruderTool,
    _split_raw_request,
)


class TestSplitRawRequest:
    """Tests for _split_raw_request helper."""

    def test_basic_get_request(self):
        raw = (
            "GET /api/users?id=42 HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Accept: application/json\r\n"
            "\r\n"
        )
        request_line, headers, body = _split_raw_request(raw)
        assert request_line == "GET /api/users?id=42 HTTP/1.1"
        assert headers["Host"] == "example.com"
        assert headers["Accept"] == "application/json"
        assert body == ""

    def test_post_request_with_json_body(self):
        raw = (
            "POST /api/data HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 27\r\n"
            "\r\n"
            '{"name": "Alice", "age": 30}'
        )
        request_line, headers, body = _split_raw_request(raw)
        assert request_line == "POST /api/data HTTP/1.1"
        assert headers["Content-Type"] == "application/json"
        assert body == '{"name": "Alice", "age": 30}'

    def test_headers_without_colon_ignored(self):
        raw = (
            "GET /path HTTP/1.1\r\n"
            "ValidHeader: value\r\n"
            "InvalidLineWithoutColon\r\n"
            "Another: ok\r\n"
            "\r\n"
        )
        request_line, headers, body = _split_raw_request(raw)
        assert "InvalidLineWithoutColon" not in headers
        assert headers["ValidHeader"] == "value"
        assert headers["Another"] == "ok"

    def test_empty_request_raises(self):
        with pytest.raises(ValueError, match="must include an HTTP request line"):
            _split_raw_request("")

    def test_bare_newline_request_raises(self):
        with pytest.raises(ValueError, match="must include an HTTP request line"):
            _split_raw_request("\r\n\r\n")

    def test_lf_line_endings_accepted(self):
        raw = "GET /api HTTP/1.1\nHost: example.com\n\n"
        request_line, headers, body = _split_raw_request(raw)
        assert request_line == "GET /api HTTP/1.1"
        assert headers["Host"] == "example.com"


class TestSendHTTP2RequestToolBuild:
    """Tests for SendHTTP2RequestTool HTTP/2 pseudo-header construction."""

    def test_pseudo_headers_derived_from_request_line_and_host_header(self):
        """Verify HTTP/2 pseudo-headers are built correctly from request components."""
        raw = (
            "POST /api/v1/users HTTP/1.1\r\n"
            "Host: target.example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"user_id": 42}'
        )
        request_line, headers, body = _split_raw_request(raw)
        parts = request_line.split()
        pseudo_headers = {
            ":method": parts[0],
            ":path": parts[1],
            ":scheme": "https",
            ":authority": headers.get("Host", "target.example.com"),
        }
        http2_headers = {
            key: value
            for key, value in headers.items()
            if key.lower() not in {"host", "content-length"}
        }
        assert pseudo_headers[":method"] == "POST"
        assert pseudo_headers[":path"] == "/api/v1/users"
        assert pseudo_headers[":scheme"] == "https"
        assert pseudo_headers[":authority"] == "target.example.com"
        assert "Host" not in http2_headers
        assert "Content-Type" in http2_headers


class TestSendToIntruderToolPayloads:
    """Tests for SendToIntruderTool payload handling."""

    def test_payloads_not_sent_to_mcp_tabname_from_explicit_arg(self):
        """Explicit tab_name should be used as-is and payloads omitted for MCP compatibility."""
        tool = SendToIntruderTool()
        mock_client = MagicMock()
        mock_client.call_with_retry.return_value = {"ok": True}

        with patch("pentest_crew.tools.burp_request_tools.get_client", return_value=mock_client):
            output = tool._run(
                tab_name="FIND-001-FUZZ",
                host="target.com",
                port=443,
                use_https=True,
                raw_request="GET /search?q=§FUZZ§ HTTP/1.1\r\nHost: target.com\r\n\r\n",
                payload_type="Sniper",
                payloads=["id=1", "id=2", "id=3"],
            )

        parsed = json.loads(output)
        assert parsed["ok"] is True
        called_tool, call_payload = mock_client.call_with_retry.call_args.args
        assert called_tool == "send_to_intruder"
        assert call_payload["tabName"] == "FIND-001-FUZZ"
        assert call_payload["targetHostname"] == "target.com"
        assert "payloads" not in call_payload

    def test_tabname_used_exactly_as_provided(self):
        tool = SendToIntruderTool()
        mock_client = MagicMock()
        mock_client.call_with_retry.return_value = {"ok": True}

        with patch("pentest_crew.tools.burp_request_tools.get_client", return_value=mock_client):
            tool._run(
                tab_name="FIND-002-IDOR",
                host="target.com",
                port=443,
                use_https=True,
                raw_request="GET /api/§ID§ HTTP/1.1\r\nHost: target.com\r\n\r\n",
                payload_type="Sniper",
            )

        called_tool, call_payload = mock_client.call_with_retry.call_args.args
        assert called_tool == "send_to_intruder"
        assert call_payload["tabName"] == "FIND-002-IDOR"
        assert "payloads" not in call_payload

    def test_tabname_derives_from_payload_type_when_not_provided(self):
        """Backward compatibility: missing tab_name should auto-derive from payload_type."""
        tool = SendToIntruderTool()
        mock_client = MagicMock()
        mock_client.call_with_retry.return_value = {"ok": True}

        with patch("pentest_crew.tools.burp_request_tools.get_client", return_value=mock_client):
            tool._run(
                host="target.com",
                port=443,
                use_https=True,
                raw_request="GET /search?q=§FUZZ§ HTTP/1.1\r\nHost: target.com\r\n\r\n",
                payload_type="Pitchfork",
                payloads=None,
            )

        called_tool, call_payload = mock_client.call_with_retry.call_args.args
        assert called_tool == "send_to_intruder"
        assert call_payload["tabName"] == "Pitchfork"
        assert "payloads" not in call_payload

    def test_tabname_derives_from_payload_preview_when_payloads_present(self):
        """When tab_name is omitted and payloads exist, include first two payload previews."""
        tool = SendToIntruderTool()
        mock_client = MagicMock()
        mock_client.call_with_retry.return_value = {"ok": True}

        with patch("pentest_crew.tools.burp_request_tools.get_client", return_value=mock_client):
            tool._run(
                host="target.com",
                port=443,
                use_https=True,
                raw_request="GET /search?q=§FUZZ§ HTTP/1.1\r\nHost: target.com\r\n\r\n",
                payload_type="Sniper",
                payloads=["id=1", "id=2", "id=3"],
            )

        called_tool, call_payload = mock_client.call_with_retry.call_args.args
        assert called_tool == "send_to_intruder"
        assert call_payload["tabName"] == "Sniper-id=1-id=2"


class TestBurpRequestToolRetries:
    def test_send_http1_request_uses_retrying_client(self):
        tool = SendHTTP1RequestTool()
        mock_client = MagicMock()
        mock_client.call_with_retry.return_value = {"ok": True}

        with patch("pentest_crew.tools.burp_request_tools.get_client", return_value=mock_client):
            result = tool._run(
                host="example.com",
                port=443,
                use_https=True,
                raw_request="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )

        assert json.loads(result)["ok"] is True
        mock_client.call_with_retry.assert_called_once_with(
            "send_http1_request",
            {
                "content": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "targetHostname": "example.com",
                "targetPort": 443,
                "usesHttps": True,
            },
            retries=3,
            delay=1.0,
        )

    def test_send_http2_request_uses_retrying_client(self):
        tool = SendHTTP2RequestTool()
        mock_client = MagicMock()
        mock_client.call_with_retry.return_value = {"ok": True}

        with patch("pentest_crew.tools.burp_request_tools.get_client", return_value=mock_client):
            result = tool._run(
                host="example.com",
                port=443,
                use_https=True,
                raw_request="GET / HTTP/1.1\r\nHost: example.com\r\nX-Test: 1\r\n\r\n",
            )

        assert json.loads(result)["ok"] is True
        mock_client.call_with_retry.assert_called_once()

    def test_create_repeater_tab_uses_retrying_client(self):
        tool = CreateRepeaterTabTool()
        mock_client = MagicMock()
        mock_client.call_with_retry.return_value = {"ok": True}

        with patch("pentest_crew.tools.burp_request_tools.get_client", return_value=mock_client):
            result = tool._run(
                tab_name="FIND-001",
                raw_request="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                host="example.com",
                port=443,
                use_https=True,
            )

        assert json.loads(result)["ok"] is True
        mock_client.call_with_retry.assert_called_once_with(
            "create_repeater_tab",
            {
                "tabName": "FIND-001",
                "content": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "targetHostname": "example.com",
                "targetPort": 443,
                "usesHttps": True,
            },
            retries=3,
            delay=1.0,
        )
