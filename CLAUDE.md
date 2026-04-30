# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Pentest Crew is a multi-agent web application penetration testing pipeline built with CrewAI and Burp Suite MCP. It runs directly on top of Burp — the crew reads scope/history/scanner state from Burp via MCP tools and executes request validation through Burp without needing manual target input.

**Single-agent mode** (1 API key): one LLM runs all 4 stages sequentially.
**Multi-agent mode** (2+ API keys): 4 specialized agents run in a strict sequential pipeline.

## Dev Commands

```bash
# Run the crew (recommended entry point)
python src/pentest_crew/main.py

# With env overrides
ENGAGEMENT_ID=ENG-001 CLIENT_NAME=Acme python src/pentest_crew/main.py

# Run tests
.venv/bin/python -m pytest tests/ -v

# Install dependencies
python -m venv .venv && .venv/bin/pip install -e .
```

## Architecture

```
Burp MCP (scope + HTTP history + scanner)
    │
    ▼
http_analyst          → get/scan scope, triage history, build finding candidates
    │
    ▼
validation_executor   → replay, collaborator, autorize session-swap
    │
    ▼
lead_pentester        → QA gate, CVSS scoring, evidence review
    │
    ▼
report_generator      → final Markdown pentest report
```

**Pipeline is always sequential** (`Process.sequential`). No task parallelism.

### Tool Groups

- `ANALYST_TOOLS` — http_analyst: scope, history, scanner, WS, regex search
- `EXECUTOR_TOOLS` — validation_executor: replay (HTTP/1, HTTP/2), collaborator, autorize, encoding
- `REVIEWER_TOOLS` — lead_pentester: scanner, history search, collaborator, project options
- `REPORTER_TOOLS` — report_generator: no Burp tools (consumes structured output from previous agents)

### LLM Mode Detection

`llm_mode.py` detects mode from environment. Provider order:
- 1 key → single-agent (all 4 stages, one LLM)
- 2+ keys → multi-agent (each role gets preferred provider with fallback chain)

Model override format: `MODEL_<ROLE> = "provider/model"` or just `"model-name"` (provider inferred from fallback chain).

### Key Files

- `src/pentest_crew/main.py` — entry point, env validation, input building, CrewAI panel patches
- `src/pentest_crew/crew.py` — crew/agent/task definitions, LLM selection with fallback
- `src/pentest_crew/llm_mode.py` — LLM provider detection, model override resolution
- `src/pentest_crew/tools/` — CrewAI BaseTool wrappers for all Burp MCP tools
  - `burp_mcp_client.py` — singleton MCP client, SSE transport, 60s timeout per call
  - `autorize_tools.py` — session-swap bypass detection (cookie/bearer/header token swap)
  - `burp_collaborator_tools.py` — OOB testing, encoding, random string. `COLLABORATOR_WAIT_SECS` env var controls default wait.
  - `burp_request_tools.py` — HTTP/1, HTTP/2, Repeater, Intruder, editor tools
  - `burp_proxy_tools.py` — history, WS, scanner, scope, intercept control
  - `burp_config_tools.py` — project/user options, scanner engine control

## Important Conventions

- All tools are **singleton instances** defined in `tools/__init__.py` — never create new instances inline
- The `BurpMCPClient` singleton in `burp_mcp_client.py` is thread-safe (locks around creation)
- `_blocking_call` uses a fresh event loop per call with a **60s timeout** — do not call from the main thread in a blocking way without awareness
- `REPORTER_TOOLS` is intentionally empty — the report generator must not call Burp tools
- `poll_collaborator_with_wait` default wait is driven by `COLLABORATOR_WAIT_SECS` env var (default: 30s)
- CrewAI telemetry is disabled via `CREWAI_DISABLE_TELEMETRY=true` and `CREWAI_DISABLE_TRACKING=true` in `crew.py`

## Bypass Detection Logic (autorize_tools.py)

The `autorize_check` tool has two bypass signals:

1. **Soft bypass** (`bypassed`): attacker gets HTTP 200 AND body is structurally equivalent to victim's (size delta < 2% or normalized content match). Catches IDOR where both users get the same response structure.
2. **Hard bypass** (`hard_bypass`): victim gets non-200 (e.g. 403) but attacker gets HTTP 200 with non-empty body. The attacker succeeded despite the victim's request being denied — always a confirmed bypass.

Use `_get_status(response)` (not bare `.get()`) to extract status codes — handles both `statusCode` and `status` keys.

## Testing Notes

- Tests mock `get_client()` via `patch("...get_client", return_value=mock_client)` — real MCP never called
- `_split_raw_request` helper handles both `\r\n` and `\n` line endings
- `call_with_retry` retries only transient errors (timeout, connection refused/reset, network). Permanent errors (bad tool name, auth failures) return immediately without retry
- Test file naming: `test_*.py`, function naming: `test_*`
