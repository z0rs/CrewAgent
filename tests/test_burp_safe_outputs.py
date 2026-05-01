"""
Regression tests for safe Burp output normalization and agent-tool hardening.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from pentest_crew.tools import ADMIN_TOOLS, ALL_TOOLS, ANALYST_TOOLS, EXECUTOR_TOOLS, REVIEWER_TOOLS
from pentest_crew.tools.burp_config_tools import OutputUserOptionsTool
from pentest_crew.tools.burp_proxy_tools import GetProjectOptionsTool, GetProxyHttpHistoryTool
from pentest_crew.tools.burp_request_tools import GetActiveEditorContentsTool, SendHTTP1RequestTool


def test_proxy_history_is_structured_redacted_and_binary_aware():
    tool = GetProxyHttpHistoryTool()
    mock_client = MagicMock()
    history_stream = "\n\n".join(
        [
            json.dumps(
                {
                    "request": (
                        "POST /api/users?id=42&search=alice HTTP/1.1\r\n"
                        "Host: api.example.com\r\n"
                        "Authorization: Bearer eyJ.real.jwt.token\r\n"
                        "Cookie: session=abcd1234; tracking=1\r\n"
                        "X-Client-Id: 12345\r\n"
                        "Content-Type: application/json\r\n"
                        "\r\n"
                        '{"token":"topsecret","profile":{"email":"alice@example.com"}}'
                    ),
                    "response": (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json\r\n"
                        "\r\n"
                        '{"email":"alice@example.com","status":"ok"}'
                    ),
                    "notes": "captured from login flow",
                }
            ),
            json.dumps(
                {
                    "request": (
                        "GET /static/logo.png HTTP/1.1\r\n"
                        "Host: cdn.example.com\r\n"
                        "\r\n"
                    ),
                    "response": (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: image/png\r\n"
                        "\r\n"
                        "\x89PNG\r\n\x1a\n\x00\x00binary"
                    ),
                    "notes": "",
                }
            ),
        ]
    )
    mock_client.call_with_retry.return_value = {"data": history_stream}

    with patch("pentest_crew.tools.burp_proxy_tools.get_client", return_value=mock_client):
        result = json.loads(tool._run(count=2, offset=7))

    assert result["count"] == 2
    assert result["offset"] == 7

    first = result["items"][0]
    assert first["id"] == 7
    assert first["request"]["method"] == "POST"
    assert first["request"]["host"] == "api.example.com"
    assert first["request"]["headers"]["Authorization"] == "Bearer <redacted>"
    assert first["request"]["headers"]["Cookie"] == "session=<redacted>; tracking=<redacted>"
    assert first["request"]["headers"]["X-Client-Id"] == "<redacted-id>"
    assert "alice@example.com" not in first["request"]["bodyPreview"]
    assert "<redacted-email>" in first["response"]["bodyPreview"]
    assert "idor_candidate" in first["request"]["riskHints"]
    assert "input_fuzz_candidate" in first["request"]["riskHints"]
    assert "secret_handling_candidate" in first["request"]["riskHints"]

    second = result["items"][1]
    assert second["id"] == 8
    assert second["response"]["bodyBinary"] is True
    assert "binary body omitted" in second["response"]["bodyPreview"]


def test_proxy_history_single_item_response_is_normalized_too():
    tool = GetProxyHttpHistoryTool()
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {
        "request": (
            "GET /profile?id=7 HTTP/1.1\r\n"
            "Host: app.example.com\r\n"
            "Authorization: Bearer eyJ.single.item.token\r\n"
            "\r\n"
        ),
        "response": (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"token":"abc123","email":"alice@example.com"}'
        ),
        "notes": "",
    }

    with patch("pentest_crew.tools.burp_proxy_tools.get_client", return_value=mock_client):
        result = json.loads(tool._run(count=1, offset=3))

    assert result["count"] == 1
    item = result["items"][0]
    assert item["id"] == 3
    assert item["request"]["headers"]["Authorization"] == "Bearer <redacted>"
    assert item["response"]["bodyPreview"].count("<redacted>") >= 1
    assert "<redacted-email>" in item["response"]["bodyPreview"]


def test_project_options_are_summarized_for_scope_confirmation_only():
    tool = GetProjectOptionsTool()
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {
        "data": json.dumps(
            {
                "target": {
                    "scope": {
                        "advanced_mode": True,
                        "include": [{"host": "^api\\.example\\.com$", "protocol": "https", "port": "^443$"}],
                        "exclude": [{"host": "^admin\\.example\\.com$", "protocol": "https", "port": "^443$"}],
                    }
                },
                "proxy": {
                    "intercept_client_requests": {"do_intercept": False},
                    "intercept_server_responses": {"do_intercept": True},
                    "request_listeners": [{"listener_port": 8080}],
                },
                "project_options": {
                    "http": {"http2": {"enable_http2": True}},
                    "misc": {"collaborator_server": {"type": "default", "use_user_config": True}},
                    "resource_pools": {"default_resource_pool": {"concurrent_request_limit": 10, "auto_backoff": True, "throttle_interval_enabled": False}},
                },
            }
        )
    }

    with patch("pentest_crew.tools.burp_proxy_tools.get_client", return_value=mock_client):
        result = json.loads(tool._run())

    assert result["summaryOnly"] is True
    assert result["redacted"] is True
    assert result["scope"]["advancedMode"] is True
    assert result["scope"]["include"][0]["host"] == "^api\\.example\\.com$"
    assert result["proxy"]["listenerPorts"] == [8080]
    assert result["http"]["http2Enabled"] is True


def test_user_options_hide_local_paths_and_hashed_keys():
    tool = OutputUserOptionsTool()
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {
        "data": json.dumps(
            {
                "user_options": {
                    "extender": {
                        "extensions": [
                            {
                                "name": "MCP Server",
                                "loaded": True,
                                "extension_type": "java",
                                "extension_file": "/tmp/secret/path.jar",
                            }
                        ]
                    },
                    "misc": {
                        "api": {
                            "enabled": True,
                            "listen_mode": "loopback_only",
                            "port": 1337,
                            "keys": [{"name": "crewai", "hashed_key": "do-not-leak"}],
                        },
                        "pause_tasks_at_startup_default": True,
                    },
                    "display": {"user_interface": {"look_and_feel": "Light"}},
                }
            }
        )
    }

    with patch("pentest_crew.tools.burp_config_tools.get_client", return_value=mock_client):
        result = json.loads(tool._run())

    serialized = json.dumps(result)
    assert result["summaryOnly"] is True
    assert result["api"]["keyCount"] == 1
    assert result["extender"]["loadedExtensions"][0]["name"] == "MCP Server"
    assert "extension_file" not in serialized
    assert "do-not-leak" not in serialized
    assert "/tmp/secret/path.jar" not in serialized


def test_active_editor_contents_are_summarized_and_redacted():
    tool = GetActiveEditorContentsTool()
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {
        "data": (
            "GET /profile?id=7 HTTP/1.1\r\n"
            "Host: app.example.com\r\n"
            "Authorization: Bearer eyJ.editor.token\r\n"
            "Cookie: session=abc123\r\n"
            "\r\n"
        )
    }

    with patch("pentest_crew.tools.burp_request_tools.get_client", return_value=mock_client):
        result = json.loads(tool._run())

    summary = result["summary"]
    assert result["redacted"] is True
    assert summary["method"] == "GET"
    assert summary["headers"]["Authorization"] == "Bearer <redacted>"
    assert summary["headers"]["Cookie"] == "session=<redacted>"
    assert "idor_candidate" in summary["riskHints"]


def test_request_execution_output_redacts_sensitive_headers_and_body_values():
    tool = SendHTTP1RequestTool()
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {
        "statusCode": 200,
        "headers": {"Set-Cookie": "session=abc123; HttpOnly", "Content-Type": "application/json"},
        "body": '{"token":"abc123","email":"alice@example.com","status":"ok"}',
    }

    with patch("pentest_crew.tools.burp_request_tools.get_client", return_value=mock_client):
        result = json.loads(
            tool._run(
                host="app.example.com",
                port=443,
                use_https=True,
                raw_request="GET /profile HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
            )
        )

    assert result["statusCode"] == 200
    assert result["headers"]["Set-Cookie"] == "session=<redacted>; HttpOnly"
    assert "<redacted>" in result["body"]
    assert "<redacted-email>" in result["body"]


def test_dangerous_burp_admin_tools_are_not_in_autonomous_groups():
    analyst_names = {tool.name for tool in ANALYST_TOOLS}
    executor_names = {tool.name for tool in EXECUTOR_TOOLS}
    reviewer_names = {tool.name for tool in REVIEWER_TOOLS}
    all_names = {tool.name for tool in ALL_TOOLS}
    admin_names = {tool.name for tool in ADMIN_TOOLS}

    for forbidden in {
        "output_user_options",
        "set_project_options",
        "set_user_options",
        "set_task_execution_engine_state",
    }:
        assert forbidden not in analyst_names
        assert forbidden not in executor_names
        assert forbidden not in reviewer_names
        assert forbidden not in all_names
        assert forbidden in admin_names
