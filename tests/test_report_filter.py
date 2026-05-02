"""
test_report_filter.py
─────────────────────
Tests for the report input filtering and sanitization logic.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from pentest_crew.tools.report_filter_tools import (
    classify_finding,
    extract_findings,
    filter_report_input,
    strip_agent_traces,
)


def test_classify_finding_confirmed():
    block = "FIND-001: SQL Injection\nStatus: CONFIRMED\nEndpoint: /api/user?id=1"
    assert classify_finding(block) == "confirmed"


def test_classify_finding_rejected():
    block = "FIND-002: XSS\nVerdict: NOT CONFIRMED\nReason: reflected but not executable"
    assert classify_finding(block) == "rejected"


def test_classify_finding_inconclusive():
    block = "FIND-003: SSRF\nStatus: INCONCLUSIVE\nNote: timeout on collaborator poll"
    assert classify_finding(block) == "inconclusive"


def test_classify_finding_unknown():
    block = "FIND-004: Some random text without status"
    assert classify_finding(block) == "unknown"


def test_classify_finding_validated():
    block = "FIND-005: IDOR\nAction: VALIDATED via autorize"
    assert classify_finding(block) == "confirmed"


def test_classify_finding_bypassed():
    block = "FIND-006: Auth Bypass\nStatus: BYPASSED"
    assert classify_finding(block) == "confirmed"


def test_classify_finding_skipped():
    block = "FIND-007: Info leak\nAction: SKIP"
    assert classify_finding(block) == "rejected"


def test_extract_findings_multiple():
    text = """
Some preamble text.

FIND-001: SQL Injection
Status: CONFIRMED
Endpoint: /api/user?id=1
Parameter: id

FIND-002: XSS
Verdict: NOT CONFIRMED
Reason: payload was encoded

FIND-003: SSRF
Status: INCONCLUSIVE

Some trailing text.
"""
    findings = extract_findings(text)
    assert len(findings) == 3
    assert findings[0]["status"] == "confirmed"
    assert findings[1]["status"] == "rejected"
    assert findings[2]["status"] == "inconclusive"


def test_extract_findings_empty():
    assert extract_findings("No findings here") == []


def test_strip_agent_traces_removes_thought_action():
    text = """Thought: I need to check the proxy history
Action: get_proxy_http_history
Action Input: {"count": 100}
Observation: Found 50 entries

FIND-001: SQL Injection
Status: CONFIRMED"""
    cleaned = strip_agent_traces(text)
    assert "Thought:" not in cleaned
    assert "Action:" not in cleaned
    assert "Observation:" not in cleaned
    assert "FIND-001" in cleaned


def test_strip_agent_traces_removes_json_blocks():
    text = """```json
{"tool": "send_http1_request", "params": {"host": "example.com"}}
```

FIND-001: XSS
Status: CONFIRMED"""
    cleaned = strip_agent_traces(text)
    assert '"tool"' not in cleaned
    assert "FIND-001" in cleaned


def test_filter_report_input_confirmed_only():
    raw = """
FIND-001: SQL Injection
Status: CONFIRMED
Endpoint: /api/user?id=1
Parameter: id
CVSS: 8.5

FIND-002: False Positive
Status: REJECTED
Reason: payload was encoded by WAF

FIND-003: SSRF
Status: INCONCLUSIVE
Note: collaborator timed out
"""
    filtered = filter_report_input(raw, include_inconclusive=False)
    assert "CONFIRMED FINDINGS" in filtered
    assert "FIND-001" in filtered
    assert "REJECTED" in filtered  # In the rejected summary section
    assert "FIND-003" not in filtered  # Inconclusive excluded


def test_filter_report_input_with_inconclusive():
    raw = """
FIND-001: SQL Injection
Status: CONFIRMED
Endpoint: /api/user?id=1

FIND-003: SSRF
Status: INCONCLUSIVE
"""
    filtered = filter_report_input(raw, include_inconclusive=True)
    assert "FIND-001" in filtered
    assert "INCONCLUSIVE" in filtered
    assert "FIND-003" in filtered


def test_filter_report_input_no_findings_returns_stripped():
    raw = """Thought: I should check the history
Action: get_proxy_http_history
Observation: No interesting entries found.
The scope was empty so nothing to test.
"""
    filtered = filter_report_input(raw)
    assert "Thought:" not in filtered
    assert "Action:" not in filtered


def test_filter_report_input_strips_traces_from_context():
    raw = """Thought: Analyzing the traffic now.
Action: get_scanner_issues
Action Input: {}
Observation: No scanner issues.

## Scope
Target: api.example.com

FIND-001: XSS
Status: CONFIRMED
Endpoint: /search?q=test

Thought: Now I should validate.
Action: send_http1_request
Observation: HTTP 200 with reflected payload.
"""
    filtered = filter_report_input(raw)
    assert "Thought:" not in filtered
    assert "Action:" not in filtered
    assert "Observation:" not in filtered
    assert "FIND-001" in filtered
    assert "Target: api.example.com" in filtered


def test_filter_report_input_rejected_summary():
    raw = """
FIND-001: SQLi
Status: CONFIRMED

FIND-002: XSS
Verdict: NOT CONFIRMED
Reason: WAF blocked payload

FIND-003: Open Redirect
Status: REJECTED
Reason: URL was sanitized
"""
    filtered = filter_report_input(raw)
    # Rejected findings should appear as one-line summaries
    assert "REJECTED" in filtered
    assert "FIND-002" in filtered
    assert "FIND-003" in filtered
    # But full blocks should not be in the main output
    assert "WAF blocked payload" not in filtered


def test_report_filter_tool_run():
    from pentest_crew.tools.report_filter_tools import ReportFilterTool
    tool = ReportFilterTool()
    raw = """
FIND-001: SQL Injection
Status: CONFIRMED
Endpoint: /api/user?id=1

FIND-002: XSS
Status: REJECTED
"""
    result = tool._run(raw_context=raw, include_inconclusive=False)
    assert "FIND-001" in result
    assert "CONFIRMED" in result
