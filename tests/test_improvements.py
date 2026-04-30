"""
test_improvements.py
────────────────────
Unit tests for bug fixes and feature improvements.
"""
import pytest
from pentest_crew.tools.autorize_tools import _swap_session_token, _remove_auth
from pentest_crew.tools.burp_request_tools import _split_raw_request, SendHTTP2RequestTool
from pentest_crew.tools.burp_collaborator_tools import PollCollaboratorInteractionsTool, CollaboratorPollWithWaitTool
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
        mock_client.call.return_value = {"ok": True}
        
        raw_request = (
            "GET / HTTP/1.1\r\n"
            "User-Agent: my-agent\r\n"
            "X-Custom-Header: value\r\n"
            "\r\n"
        )
        
        with patch("pentest_crew.tools.burp_request_tools.get_client", return_value=mock_client):
            tool._run(host="example.com", port=443, use_https=True, raw_request=raw_request)
            
        call_args = mock_client.call.call_args[0]
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

    def test_poll_collaborator_with_wait_uses_retry_for_transient_transport_errors(self):
        tool = CollaboratorPollWithWaitTool()
        mock_client = MagicMock()
        mock_client.call_with_retry.return_value = {"count": 0, "interactions": [], "message": "No interactions detected"}

        with patch("pentest_crew.tools.burp_collaborator_tools.time.sleep", return_value=None), \
             patch("pentest_crew.tools.burp_collaborator_tools.get_client", return_value=mock_client):
            result = tool._run(payload_id="payload-id", wait_seconds=0)

        assert "\"count\": 0" in result
        mock_client.call_with_retry.assert_called_once_with(
            "get_collaborator_interactions",
            {"payloadId": "payload-id"},
            retries=3,
            delay=1.0,
        )
