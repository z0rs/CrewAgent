"""
test_improvements.py
────────────────────
Unit tests for bug fixes and feature improvements.
"""
import json
import pytest
from pentest_crew.tools.autorize_tools import _swap_session_token, _remove_auth
from pentest_crew.tools.burp_request_tools import _split_raw_request, SendHTTP2RequestTool
from pentest_crew.tools.burp_collaborator_tools import (
    PollCollaboratorInteractionsTool,
    CollaboratorPollWithWaitTool,
    poll_collaborator_adaptive,
)
from pentest_crew.tools.fuzzing_tools import ParamFuzzerTool, FuzzingComboTool
from unittest.mock import MagicMock, patch

class TestAutorizeImprovements:
    def test_swap_specific_cookie(self):
        raw = "GET / HTTP/1.1\r\nCookie: session=old; tracking=123\r\n\r\n"
        # Swap 'session'
        swapped = _swap_session_token(raw, "cookie", "new", "session")
        assert "Cookie: session=new; tracking=123" in swapped
        
        # Swap 'tracking'
        swapped = _swap_session_token(raw, "cookie", "456", "tracking")
        assert "Cookie: session=old; tracking=456" in swapped

    def test_swap_cookie_missing_specific_raises(self):
        raw = "GET / HTTP/1.1\r\nCookie: session=old\r\n\r\n"
        with pytest.raises(ValueError, match="cookie 'missing' was not found"):
            _swap_session_token(raw, "cookie", "new", "missing")

    def test_remove_auth_preserves_body_exactly(self):
        body = '{"data": "line1\r\nline2"}'
        raw = f"POST / HTTP/1.1\r\nAuthorization: Bearer xyz\r\n\r\n{body}"
        removed = _remove_auth(raw)
        assert body in removed
        assert "Authorization" not in removed
        assert removed.endswith(body)
        # Check that \r\n in body is preserved
        _, _, final_body = removed.partition("\r\n\r\n")
        assert final_body == body

class TestRequestToolsImprovements:
    def test_split_raw_request_preserves_body_exactly(self):
        body = '{"data": "line1\r\nline2"}'
        raw = f"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n{body}"
        request_line, headers, final_body = _split_raw_request(raw)
        assert final_body == body
        assert headers["Host"] == "example.com"

    def test_http2_tool_lowercases_headers(self):
        tool = SendHTTP2RequestTool()
        mock_client = MagicMock()
        mock_client.call_with_retry.return_value = {"ok": True}
        
        raw_request = (
            "GET / HTTP/1.1\r\n"
            "User-Agent: my-agent\r\n"
            "X-Custom-Header: value\r\n"
            "\r\n"
        )
        
        with patch("pentest_crew.tools.burp_request_tools.get_client", return_value=mock_client):
            tool._run(host="example.com", port=443, use_https=True, raw_request=raw_request)
            
        call_args = mock_client.call_with_retry.call_args[0]
        sent_args = call_args[1]
        sent_headers = sent_args["headers"]
        
        assert "user-agent" in sent_headers
        assert "x-custom-header" in sent_headers
        assert "User-Agent" not in sent_headers
        assert "X-Custom-Header" not in sent_headers


class TestCollaboratorImprovements:
    def test_poll_collaborator_uses_retry_for_transient_transport_errors(self):
        tool = PollCollaboratorInteractionsTool()
        mock_client = MagicMock()
        mock_client.call_with_retry.return_value = {"count": 0, "interactions": [], "message": "No interactions detected"}

        with patch("pentest_crew.tools.burp_collaborator_tools.get_client", return_value=mock_client):
            result = tool._run(payload_id="payload-id")

        assert "\"count\": 0" in result
        mock_client.call_with_retry.assert_called_once_with(
            "get_collaborator_interactions",
            {"payloadId": "payload-id"},
            retries=3,
            delay=1.0,
        )

    def test_poll_collaborator_with_wait_uses_adaptive_polling(self):
        tool = CollaboratorPollWithWaitTool()
        mock_client = MagicMock()
        # Return interaction on first poll — should exit early
        mock_client.call_with_retry.return_value = {
            "interactions": [{"type": "DNS", "clientIp": "1.2.3.4"}],
        }

        with patch("pentest_crew.tools.burp_collaborator_tools.get_client", return_value=mock_client):
            result = tool._run(payload_id="payload-id", wait_seconds=60)

        assert "\"status\": \"found\"" in result
        assert "\"waited_seconds\"" in result

    def test_adaptive_polling_returns_early_on_first_success(self):
        mock_client = MagicMock()
        mock_client.call_with_retry.return_value = {
            "interactions": [{"type": "HTTP", "clientIp": "10.0.0.1"}],
        }

        with patch("pentest_crew.tools.burp_collaborator_tools.get_client", return_value=mock_client):
            result = poll_collaborator_adaptive("test-payload-id", max_wait=60)

        assert result["status"] == "found"
        assert len(result["interactions"]) == 1
        assert result["waited_seconds"] < 5  # Should return almost immediately

    def test_adaptive_polling_timeout_when_no_interactions(self):
        mock_client = MagicMock()
        mock_client.call_with_retry.return_value = {
            "interactions": [],
        }

        with patch("pentest_crew.tools.burp_collaborator_tools.get_client", return_value=mock_client), \
             patch("pentest_crew.tools.burp_collaborator_tools.time.sleep", return_value=None):
            result = poll_collaborator_adaptive("test-payload-id", max_wait=2)

        assert result["status"] == "timeout"
        assert result["interactions"] == []
        assert result["waited_seconds"] == 2

    def test_adaptive_polling_scopes_to_payload_id(self):
        mock_client = MagicMock()
        mock_client.call_with_retry.return_value = {
            "interactions": [{"type": "DNS"}],
        }

        with patch("pentest_crew.tools.burp_collaborator_tools.get_client", return_value=mock_client):
            poll_collaborator_adaptive("my-payload-id", max_wait=10)

        # Verify all polls used the correct payloadId
        for call_args in mock_client.call_with_retry.call_args_list:
            assert call_args[0][1] == {"payloadId": "my-payload-id"}


class TestFuzzTypesEnforcement:
    def test_param_fuzzer_rejects_empty_fuzz_types(self):
        tool = ParamFuzzerTool()
        result = json.loads(tool._run(
            host="example.com", port=443, use_https=True,
            raw_request="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            param_name="id", fuzz_types="",
        ))
        assert "error" in result
        assert "required" in result["error"].lower()

    def test_param_fuzzer_rejects_all_fuzz_types(self):
        tool = ParamFuzzerTool()
        result = json.loads(tool._run(
            host="example.com", port=443, use_https=True,
            raw_request="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            param_name="id", fuzz_types="all",
        ))
        assert "error" in result
        assert "required" in result["error"].lower()

    def test_param_fuzzer_rejects_invalid_categories(self):
        tool = ParamFuzzerTool()
        result = json.loads(tool._run(
            host="example.com", port=443, use_https=True,
            raw_request="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            param_name="id", fuzz_types="nonexistent_vuln,another_fake",
        ))
        assert "error" in result
        assert "No valid fuzz categories" in result["error"]

    def test_param_fuzzer_accepts_explicit_categories(self):
        tool = ParamFuzzerTool()
        mock_client = MagicMock()
        mock_client.call.return_value = {"statusCode": 200, "body": "ok"}
        with patch("pentest_crew.tools.fuzzing_tools.get_client", return_value=mock_client):
            result = json.loads(tool._run(
                host="example.com", port=443, use_https=True,
                raw_request="GET /?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                param_name="id", fuzz_types="sqli,fuzz_baseline",
            ))
        assert "error" not in result
        assert result["param"] == "id"

    def test_fuzzing_combo_rejects_empty_fuzz_types(self):
        tool = FuzzingComboTool()
        result = json.loads(tool._run(
            host="example.com", port=443, use_https=True,
            raw_request="GET /?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            fuzz_types="",
        ))
        assert "error" in result
        assert "required" in result["error"].lower()

    def test_fuzzing_combo_rejects_all_fuzz_types(self):
        tool = FuzzingComboTool()
        result = json.loads(tool._run(
            host="example.com", port=443, use_https=True,
            raw_request="GET /?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            fuzz_types="all",
        ))
        assert "error" in result
        assert "required" in result["error"].lower()

    def test_fuzzing_combo_accepts_explicit_categories(self):
        tool = FuzzingComboTool()
        mock_client = MagicMock()
        mock_client.call.return_value = {"statusCode": 200, "body": "ok"}
        with patch("pentest_crew.tools.fuzzing_tools.get_client", return_value=mock_client):
            result = json.loads(tool._run(
                host="example.com", port=443, use_https=True,
                raw_request="GET /?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                fuzz_types="sqli,fuzz_baseline",
            ))
        assert "error" not in result
        assert result["parameters_tested"] == ["id"]
