"""
Regression tests for Burp wrapper tools.
"""
import json
from unittest.mock import MagicMock, patch

from pentest_crew.tools.burp_collaborator_tools import URLEncodeTool
from pentest_crew.tools.burp_config_tools import (
    SetProjectOptionsTool,
    SetUserOptionsTool,
    SetTaskExecutionEngineTool,
    SetProjectOptionsInput,
    SetUserOptionsInput,
)
from pentest_crew.tools.burp_proxy_tools import (
    GetProxyHttpHistoryTool,
    SetProxyInterceptStateTool,
)


def test_set_project_options_no_json_module_shadowing():
    tool = SetProjectOptionsTool()
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {"ok": True}

    with patch("pentest_crew.tools.burp_config_tools.get_client", return_value=mock_client):
        result = tool._run(options_json='{"project_options":{}}')

    parsed = json.loads(result)
    assert parsed["ok"] is True
    mock_client.call_with_retry.assert_called_once_with(
        "set_project_options",
        {"json": '{"project_options":{}}'},
        retries=3,
        delay=1.0,
    )


def test_set_user_options_no_json_module_shadowing():
    tool = SetUserOptionsTool()
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {"ok": True}

    with patch("pentest_crew.tools.burp_config_tools.get_client", return_value=mock_client):
        result = tool._run(options_json='{"user_options":{}}')

    parsed = json.loads(result)
    assert parsed["ok"] is True
    mock_client.call_with_retry.assert_called_once_with(
        "set_user_options",
        {"json": '{"user_options":{}}'},
        retries=3,
        delay=1.0,
    )


def test_set_options_inputs_keep_json_alias_compatibility():
    project = SetProjectOptionsInput.model_validate({"json": '{"project_options":{}}'})
    user = SetUserOptionsInput.model_validate({"json": '{"user_options":{}}'})

    assert project.options_json == '{"project_options":{}}'
    assert user.options_json == '{"user_options":{}}'


def test_url_encode_does_not_send_unsupported_fullencode_key():
    tool = URLEncodeTool()
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {"data": "burp+mcp"}

    with patch("pentest_crew.tools.burp_collaborator_tools.get_client", return_value=mock_client):
        result = tool._run(data="burp mcp", full_encode=False)

    parsed = json.loads(result)
    assert parsed["data"] == "burp+mcp"
    mock_client.call_with_retry.assert_called_once_with(
        "url_encode",
        {"content": "burp mcp"},
        retries=3,
        delay=1.0,
    )


def test_url_encode_ignores_full_encode_flag_for_mcp_compatibility():
    tool = URLEncodeTool()
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {"data": "a%2Fb"}

    with patch("pentest_crew.tools.burp_collaborator_tools.get_client", return_value=mock_client):
        result = tool._run(data="a/b", full_encode=True)

    parsed = json.loads(result)
    assert parsed["data"] == "a%2Fb"
    mock_client.call_with_retry.assert_called_once_with(
        "url_encode",
        {"content": "a/b"},
        retries=3,
        delay=1.0,
    )


def test_get_proxy_http_history_uses_retrying_client():
    tool = GetProxyHttpHistoryTool()
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {"items": []}

    with patch("pentest_crew.tools.burp_proxy_tools.get_client", return_value=mock_client):
        result = tool._run(count=10, offset=2)

    assert json.loads(result)["items"] == []
    mock_client.call_with_retry.assert_called_once_with(
        "get_proxy_http_history",
        {"count": 10, "offset": 2},
        retries=3,
        delay=1.0,
    )


def test_set_proxy_intercept_state_uses_retrying_client():
    tool = SetProxyInterceptStateTool()
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {"ok": True}

    with patch("pentest_crew.tools.burp_proxy_tools.get_client", return_value=mock_client):
        result = tool._run(enabled=False)

    assert json.loads(result)["ok"] is True
    mock_client.call_with_retry.assert_called_once_with(
        "set_proxy_intercept_state",
        {"intercepting": False},
        retries=3,
        delay=1.0,
    )


def test_set_task_execution_engine_state_uses_retrying_client():
    tool = SetTaskExecutionEngineTool()
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {"ok": True}

    with patch("pentest_crew.tools.burp_config_tools.get_client", return_value=mock_client):
        result = tool._run(running=True)

    assert json.loads(result)["ok"] is True
    mock_client.call_with_retry.assert_called_once_with(
        "set_task_execution_engine_state",
        {"running": True},
        retries=3,
        delay=1.0,
    )


# ── call_with_retry tests ──────────────────────────────────────────────────────

def test_call_with_retry_retries_on_transient_timeout():
    """Timeout errors must be retried with exponential backoff."""
    mock_client = MagicMock()
    # First two calls fail with timeout, third succeeds
    mock_client.call.side_effect = [
        {"error": "timeout"},
        {"error": "Connection timed out"},
        {"ok": True},
    ]

    with patch("pentest_crew.tools.burp_mcp_client.call", mock_client.call):
        from pentest_crew.tools.burp_mcp_client import call_with_retry
        result = call_with_retry("some_tool", {}, retries=3)

    assert result == {"ok": True}
    assert mock_client.call.call_count == 3


def test_call_with_retry_gives_up_on_permanent_error():
    """Permanent errors (bad tool name) must NOT be retried."""
    mock_client = MagicMock()
    mock_client.call.return_value = {"error": "Unknown tool 'bad_tool_name'"}

    with patch("pentest_crew.tools.burp_mcp_client.call", mock_client.call):
        from pentest_crew.tools.burp_mcp_client import call_with_retry
        result = call_with_retry("bad_tool_name", {}, retries=3)

    assert "error" in result
    assert mock_client.call.call_count == 1  # no retries


def test_call_with_retry_retries_on_connection_refused():
    """Connection refused is retryable."""
    mock_client = MagicMock()
    mock_client.call.side_effect = [
        {"error": "connection refused"},
        {"ok": True},
    ]

    with patch("pentest_crew.tools.burp_mcp_client.call", mock_client.call):
        from pentest_crew.tools.burp_mcp_client import call_with_retry
        result = call_with_retry("some_tool", {})

    assert result == {"ok": True}
    assert mock_client.call.call_count == 2


def test_call_with_retry_retries_on_taskgroup_transport_error():
    """TaskGroup transport wrappers should be retried as transient errors."""
    mock_client = MagicMock()
    mock_client.call.side_effect = [
        {"error": "unhandled errors in a TaskGroup (1 sub-exception)"},
        {"ok": True},
    ]

    with patch("pentest_crew.tools.burp_mcp_client.call", mock_client.call):
        from pentest_crew.tools.burp_mcp_client import call_with_retry
        result = call_with_retry("some_tool", {})

    assert result == {"ok": True}
    assert mock_client.call.call_count == 2


def test_call_with_retry_zero_retries_still_runs_once():
    """retries=0 should still execute one call and return safely."""
    mock_client = MagicMock()
    mock_client.call.return_value = {"error": "timeout"}

    with patch("pentest_crew.tools.burp_mcp_client.call", mock_client.call):
        from pentest_crew.tools.burp_mcp_client import call_with_retry
        result = call_with_retry("some_tool", {}, retries=0)

    assert "error" in result
    assert mock_client.call.call_count == 1


# ── text normalization tests ───────────────────────────────────────────────────

def test_normalize_text_marks_config_editing_disabled_as_error():
    from pentest_crew.tools.burp_mcp_client import _normalize_tool_text_response

    result = _normalize_tool_text_response(
        "User has disabled configuration editing. They can enable it in Burp."
    )
    assert result is not None
    assert "error" in result


def test_normalize_text_parses_collaborator_payload_block():
    from pentest_crew.tools.burp_mcp_client import _normalize_tool_text_response

    msg = (
        "Payload: abc123.oastify.com\n"
        "Payload ID: abc123\n"
        "Collaborator server: oastify.com"
    )
    result = _normalize_tool_text_response(msg)
    assert result == {
        "payload": "abc123.oastify.com",
        "payloadId": "abc123",
        "collaboratorServer": "oastify.com",
    }


def test_normalize_text_null_http_response_becomes_error():
    from pentest_crew.tools.burp_mcp_client import _normalize_tool_text_response

    result = _normalize_tool_text_response("HttpRequestResponse{httpRequest=..., httpResponse=null}")
    assert result is not None
    assert result["error"].startswith("No HTTP response returned")
