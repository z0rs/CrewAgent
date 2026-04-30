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

    def test_payloads_not_sent_to_mcp_but_tabname_keeps_preview(self):
        """Burp MCP currently rejects unknown payloads key; wrapper must omit it."""
        tool = SendToIntruderTool()
        mock_client = MagicMock()
        mock_client.call.return_value = {"ok": True}

        with patch("pentest_crew.tools.burp_request_tools.get_client", return_value=mock_client):
            output = tool._run(
                host="target.com",
                port=443,
                use_https=True,
                raw_request="GET /search?q=§FUZZ§ HTTP/1.1\r\nHost: target.com\r\n\r\n",
                payload_type="Sniper",
                payloads=["id=1", "id=2", "id=3"],
            )

        parsed = json.loads(output)
        assert parsed["ok"] is True
        called_tool, call_payload = mock_client.call.call_args.args
        assert called_tool == "send_to_intruder"
        assert call_payload["targetHostname"] == "target.com"
        assert call_payload["tabName"] == "Sniper-id=1-id=2"
        assert "payloads" not in call_payload

    def test_without_payloads_tabname_uses_payload_type(self):
        tool = SendToIntruderTool()
        mock_client = MagicMock()
        mock_client.call.return_value = {"ok": True}

        with patch("pentest_crew.tools.burp_request_tools.get_client", return_value=mock_client):
            tool._run(
                host="target.com",
                port=443,
                use_https=True,
                raw_request="GET /search?q=§FUZZ§ HTTP/1.1\r\nHost: target.com\r\n\r\n",
                payload_type="Pitchfork",
                payloads=None,
            )

        called_tool, call_payload = mock_client.call.call_args.args
        assert called_tool == "send_to_intruder"
        assert call_payload["tabName"] == "Pitchfork"
        assert "payloads" not in call_payload

    def test_tabname_with_payloads_includes_first_two_payloads(self):
        """When payloads are provided, tab name should include first two payload previews."""
        payloads = ["id=1", "id=2", "id=3"]
        tab_name = "Sniper" if not payloads else f"Sniper-{'-'.join(payloads[:2])}"
        assert tab_name == "Sniper-id=1-id=2"
