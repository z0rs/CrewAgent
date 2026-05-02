"""
Regression tests for advanced bug-hunting helper tools.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from pentest_crew.tools import EXECUTOR_TOOLS
from pentest_crew.tools.business_logic_tools import (
    CouponBypassToolWrapper,
    _inject_json_field,
    _pollute_param,
)
from pentest_crew.tools.graphql_security_tools import (
    GraphQLBatchBypassTool,
    GraphQLIDORTool,
)
from pentest_crew.tools.jwt_security_tools import JWTManipulateTool, _create_jwt, _replace_jwt_in_request
from pentest_crew.tools.redirect_and_cors_tools import (
    HostHeaderInjectionTool,
    OpenRedirectTestTool,
    URLPollutionWrapperTool,
)
from pentest_crew.tools.request_smuggling_tools import _build_smuggled_request
from pentest_crew.tools.ssrf_tools import SSRFBlindTestTool


def test_graphql_idor_uses_victim_baseline_then_attacker_id():
    tool = GraphQLIDORTool()
    mock_client = MagicMock()
    mock_client.call.side_effect = [
        {"statusCode": 200, "body": '{"data":{"user":{"id":"victim-1"}}}'},
        {"statusCode": 200, "body": '{"data":{"user":{"id":"attacker-2"}}}'},
    ]

    with patch("pentest_crew.tools.graphql_security_tools.get_client", return_value=mock_client):
        result = json.loads(
            tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                path="/graphql",
                headers=None,
                query='query { user(id: "victim-1") { id email } }',
                id_param="id",
                victim_id="victim-1",
                attacker_id="attacker-2",
            )
        )

    first_request = mock_client.call.call_args_list[0].args[1]["content"]
    second_request = mock_client.call.call_args_list[1].args[1]["content"]
    assert "victim-1" in first_request
    assert "attacker-2" not in first_request
    assert "attacker-2" in second_request
    assert result["victim_test"]["query"] != result["attacker_test"]["query"]
    assert result["idor_confirmed"] is True


def test_graphql_idor_does_not_default_missing_status_to_success():
    tool = GraphQLIDORTool()
    mock_client = MagicMock()
    mock_client.call.side_effect = [
        {"body": '{"data":{"user":{"id":"victim-1"}}}'},
        {"statusCode": 200, "body": '{"data":{"user":{"id":"attacker-2"}}}'},
    ]

    with patch("pentest_crew.tools.graphql_security_tools.get_client", return_value=mock_client):
        result = json.loads(
            tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                query='query { user(id: "victim-1") { id } }',
                id_param="id",
                victim_id="victim-1",
                attacker_id="attacker-2",
            )
        )

    assert result["victim_test"]["status"] == 0
    assert result["idor_confirmed"] is False


def test_graphql_batch_tool_sends_top_level_json_array():
    tool = GraphQLBatchBypassTool()
    mock_client = MagicMock()
    mock_client.call.return_value = {"statusCode": 200, "body": '[{"data":{"ok":true}}]'}

    with patch("pentest_crew.tools.graphql_security_tools.get_client", return_value=mock_client):
        result = json.loads(
            tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                queries=["query { me { id } }", "query { viewer { id } }"],
            )
        )

    sent_request = mock_client.call.call_args.args[1]["content"]
    body = sent_request.split("\r\n\r\n", 1)[1]
    assert body.startswith("[")
    assert json.loads(body) == [
        {"query": "query { me { id } }"},
        {"query": "query { viewer { id } }"},
    ]
    assert result["batch_support"] is True


def test_ssrf_blind_test_polls_generated_collaborator_payload_id():
    tool = SSRFBlindTestTool()
    mock_client = MagicMock()
    mock_client.call.side_effect = [
        {"payload": "abc.oast.test", "payloadId": "payload-123"},
        {"statusCode": 200, "body": "ok"},
    ]
    # Adaptive polling uses call_with_retry for the poll
    mock_client.call_with_retry.return_value = {
        "interactions": [{"type": "DNS", "timestamp": "now", "clientIp": "127.0.0.1"}],
    }

    with patch("pentest_crew.tools.ssrf_tools.get_client", return_value=mock_client), \
         patch("pentest_crew.tools.burp_collaborator_tools.get_client", return_value=mock_client):
        result = json.loads(
            tool._run(
                host="target.example.com",
                port=443,
                use_https=True,
                raw_request="GET /fetch?url=https://example.com HTTP/1.1\r\nHost: target.example.com\r\n\r\n",
                vulnerable_param="url",
                wait_seconds=10,
            )
        )

    # Verify poll was scoped to the generated payload ID
    poll_call = mock_client.call_with_retry.call_args
    assert poll_call[0][0] == "get_collaborator_interactions"
    assert poll_call[0][1] == {"payloadId": "payload-123"}
    assert result["poll_scoped_to_payload"] is True
    assert result["interactions_found"] is True


def test_jwt_manipulate_replays_none_algorithm_token():
    token = _create_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "123"}, secret="secret", algorithm="HS256")
    raw_request = f"GET /me HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer {token}\r\n\r\n"
    tool = JWTManipulateTool()
    mock_client = MagicMock()
    mock_client.call.return_value = {
        "statusCode": 200,
        "body": '{"user_id": 123, "email": "test@example.com", "role": "admin"}',
    }

    with patch("pentest_crew.tools.jwt_security_tools.get_client", return_value=mock_client):
        result = json.loads(
            tool._run(
                host="api.example.com",
                port=443,
                use_https=True,
                raw_request=raw_request,
                jwt_token=token,
                new_claims={"role": "admin"},
                algorithm="none",
            )
        )

    sent_request = mock_client.call.call_args.args[1]["content"]
    # None algorithm token must appear in tokens_tested
    assert any(
        t.get("algorithm") == "none" for t in result["tokens_tested"]
    ), f"tokens_tested: {result['tokens_tested']}"
    # With authenticated-content response (user_id, email, role in body), tool confirms the bypass.
    assert result["successful_modifications"], f"successful_modifications was: {result['successful_modifications']}"
    assert "Bearer " in sent_request
    assert sent_request != raw_request


def test_replace_jwt_fails_closed_without_bearer_header():
    with pytest.raises(ValueError, match="Authorization: Bearer"):
        _replace_jwt_in_request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "new.jwt.token")


def test_smuggled_request_keeps_header_payload_out_of_body():
    raw = (
        "POST /submit HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: 7\r\n"
        "\r\n"
        "a=1&b=2"
    )

    smuggled = _build_smuggled_request(raw, prefix_payload="Content-Length: 0")
    head, body = smuggled.split("\r\n\r\n", 1)

    assert "Content-Length: 0" in head
    assert body == "a=1&b=2"
    assert "Content-Length: 0" not in body


def test_business_logic_mutators_preserve_http_message_shape():
    raw_get = "GET /search?q=one HTTP/1.1\r\nHost: example.com\r\n\r\n"
    polluted = _pollute_param(raw_get, "q", ["admin", "user"])
    request_line = polluted.split("\r\n", 1)[0]

    assert request_line == "GET /search?q=one&q=admin&q=user HTTP/1.1"
    assert not polluted.endswith("&q=admin&q=user")

    raw_json = (
        "POST /profile HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        '{"name":"alice"}'
    )
    injected = _inject_json_field(raw_json, "is_admin", True)
    head, body = injected.split("\r\n\r\n", 1)

    assert json.loads(body)["is_admin"] is True
    assert f"Content-Length: {len(body.encode())}" in head


def test_business_logic_tools_are_registered_for_executor():
    tool_names = {tool.name for tool in EXECUTOR_TOOLS}
    assert "race_condition_test" in tool_names
    assert "parameter_pollution_test" in tool_names
    assert "mass_assignment_test" in tool_names
    assert "otp_bypass_test" in tool_names
    assert "coupon_bypass_test" in tool_names
    assert CouponBypassToolWrapper().args_schema.__name__ == "CouponBypassInput"


def test_open_redirect_does_not_flag_benign_redirect_location():
    tool = OpenRedirectTestTool()
    mock_client = MagicMock()
    mock_client.call.return_value = {"statusCode": 302, "headers": {"Location": "/dashboard"}}

    with patch("pentest_crew.tools.redirect_and_cors_tools.get_client", return_value=mock_client):
        result = json.loads(
            tool._run(
                host="app.example.com",
                port=443,
                use_https=True,
                raw_request="GET /login?next=/home HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
                redirect_param="next",
            )
        )

    assert result["vulnerabilities"] == []
    assert all(test["redirect_to_evil"] is False for test in result["tests"])


def test_host_header_injection_requires_reflection_not_any_non_400():
    tool = HostHeaderInjectionTool()
    mock_client = MagicMock()
    mock_client.call.return_value = {"statusCode": 200, "body": "normal page"}

    with patch("pentest_crew.tools.redirect_and_cors_tools.get_client", return_value=mock_client):
        result = json.loads(
            tool._run(
                host="app.example.com",
                port=443,
                use_https=True,
                raw_request="GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
            )
        )

    assert all(test.get("vulnerable") is False for test in result["tests"] if "vulnerable" in test)


def test_url_pollution_tool_builds_duplicate_params_in_request_target():
    tool = URLPollutionWrapperTool()
    mock_client = MagicMock()
    mock_client.call.return_value = {"statusCode": 200, "body": "approved"}

    with patch("pentest_crew.tools.redirect_and_cors_tools.get_client", return_value=mock_client):
        result = json.loads(
            tool._run(
                host="app.example.com",
                port=443,
                use_https=True,
                raw_request="GET /transfer?role=user HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
                param_to_pollute="role",
            )
        )

    sent_request = mock_client.call.call_args_list[0].args[1]["content"]
    request_line = sent_request.split("\r\n", 1)[0]
    assert request_line == "GET /transfer?role=0&role=1 HTTP/1.1"
    assert not sent_request.endswith("&role=1")
    assert result["tests"]


def test_redirect_and_cors_tools_are_registered_for_executor():
    tool_names = {tool.name for tool in EXECUTOR_TOOLS}
    assert "open_redirect_test" in tool_names
    assert "host_header_injection" in tool_names
    assert "cors_misconfig_test" in tool_names
    assert "url_param_pollution" in tool_names
    assert URLPollutionWrapperTool().args_schema.__name__ == "URLParameterPollutionInput"
