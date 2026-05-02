"""
test_pipeline_gates.py
──────────────────────
Tests for pre-flight pipeline gate checks.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from pentest_crew.pipeline_gates import (
    check_auth_endpoints_exist,
    check_confirmed_findings_exist,
    check_parameters_exist,
    check_scope_non_empty,
)


def test_scope_gate_skips_when_scope_has_rules():
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {
        "data": json.dumps({
            "target": {
                "scope": {
                    "include": [{"host": "^api\\.example\\.com$"}],
                }
            }
        })
    }
    with patch("pentest_crew.pipeline_gates.get_client", return_value=mock_client):
        should_run, reason = check_scope_non_empty()
    assert should_run is False
    assert "include rules" in reason


def test_scope_gate_runs_when_scope_empty():
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {
        "data": json.dumps({
            "target": {"scope": {"include": []}},
        })
    }
    # Also mock history check — no traffic
    history_mock = MagicMock()
    history_mock.call_with_retry.return_value = {"items": []}
    with patch("pentest_crew.pipeline_gates.get_client", return_value=mock_client):
        # First call returns scope, second call returns empty history
        mock_client.call_with_retry.side_effect = [
            {"data": json.dumps({"target": {"scope": {"include": []}}})},
            {"items": []},
        ]
        should_run, reason = check_scope_non_empty()
    assert should_run is True
    assert "empty" in reason.lower()


def test_scope_gate_skips_when_traffic_exists():
    mock_client = MagicMock()
    mock_client.call_with_retry.side_effect = [
        {"data": json.dumps({"target": {"scope": {"include": []}}})},
        {"items": [{"request": "GET / HTTP/1.1"}]},
    ]
    with patch("pentest_crew.pipeline_gates.get_client", return_value=mock_client):
        should_run, reason = check_scope_non_empty()
    assert should_run is False
    assert "traffic" in reason.lower()


def test_auth_gate_skips_when_no_auth_traffic():
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {"items": []}
    with patch("pentest_crew.pipeline_gates.get_client", return_value=mock_client):
        should_run, reason = check_auth_endpoints_exist()
    assert should_run is False
    assert "No auth" in reason


def test_auth_gate_runs_when_auth_traffic_found():
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {
        "items": [{"request": "POST /api/login HTTP/1.1"}]
    }
    with patch("pentest_crew.pipeline_gates.get_client", return_value=mock_client):
        should_run, reason = check_auth_endpoints_exist()
    assert should_run is True
    assert "auth-related" in reason


def test_fuzzing_gate_skips_when_no_params():
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {"items": []}
    with patch("pentest_crew.pipeline_gates.get_client", return_value=mock_client):
        should_run, reason = check_parameters_exist()
    assert should_run is False
    assert "No parameters" in reason


def test_fuzzing_gate_runs_when_params_found():
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {
        "items": [{"request": "GET /api/users?id=1 HTTP/1.1"}]
    }
    with patch("pentest_crew.pipeline_gates.get_client", return_value=mock_client):
        should_run, reason = check_parameters_exist()
    assert should_run is True
    assert "parameterized" in reason


def test_exploitation_gate_skips_when_no_scanner_issues():
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {"data": json.dumps({"issues": []})}
    with patch("pentest_crew.pipeline_gates.get_client", return_value=mock_client):
        should_run, reason = check_confirmed_findings_exist()
    assert should_run is False
    assert "No scanner issues" in reason


def test_exploitation_gate_runs_when_issues_found():
    mock_client = MagicMock()
    mock_client.call_with_retry.return_value = {
        "data": json.dumps({"issues": [{"name": "SQL injection"}]})
    }
    with patch("pentest_crew.pipeline_gates.get_client", return_value=mock_client):
        should_run, reason = check_confirmed_findings_exist()
    assert should_run is True
    assert "scanner issues" in reason


def test_gate_handles_client_failure_gracefully():
    mock_client = MagicMock()
    mock_client.call_with_retry.side_effect = ConnectionError("MCP unavailable")
    with patch("pentest_crew.pipeline_gates.get_client", return_value=mock_client):
        should_run, reason = check_scope_non_empty()
    # Should proceed when gate check fails
    assert should_run is True
