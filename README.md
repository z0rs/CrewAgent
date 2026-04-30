# Pentest Crew

Multi-agent web pentest pipeline built with CrewAI, Burp Suite MCP, and the Autorize extension.

This project runs directly on top of Burp MCP. The crew reads scope/history/scanner
state from Burp and executes request validation through Burp tools without needing
manual target input as a prerequisite.

## What It Does

The pipeline is sequential:

1. `http_analyst`
   Reads Burp HTTP/WebSocket history, runs regex searches, reviews scanner issues, maps candidates to WSTG-aligned categories, and routes them to an executable validation action.
2. `validation_executor`
   Replays requests with Burp MCP tools, performs targeted request mutation, Collaborator checks, and Autorize-style session swap checks.
3. `lead_pentester`
   Reviews the evidence, rejects weak claims, assigns CVSS, and writes technical impact and remediation content.
4. `report_generator`
   Produces the final Markdown pentest report.

## Burp MCP Tool Coverage

This repository covers all tools exposed by the Burp MCP server:

| Tool | Wrapper | Purpose |
|------|---------|---------|
| `get_proxy_http_history` | `GetProxyHttpHistoryTool` | Read proxy HTTP history |
| `get_proxy_http_history_regex` | `SearchProxyHttpHistoryTool` | Regex-filtered history search |
| `get_proxy_websocket_history` | `GetProxyWebSocketHistoryTool` | Read WebSocket frames |
| `get_proxy_websocket_history_regex` | `SearchProxyWebSocketHistoryTool` | Regex-filtered WS search |
| `get_scanner_issues` | `GetScannerIssuesTool` | Automated scanner findings |
| `output_project_options` | `GetProjectOptionsTool` | Read project scope/config |
| `output_user_options` | `OutputUserOptionsTool` | Read user preferences |
| `set_proxy_intercept_state` | `SetProxyInterceptStateTool` | Enable/disable proxy intercept |
| `send_http1_request` | `SendHTTP1RequestTool` | HTTP/1 replay with mutations |
| `send_http2_request` | `SendHTTP2RequestTool` | HTTP/2 replay |
| `create_repeater_tab` | `CreateRepeaterTabTool` | Create Repeater tab by finding ID |
| `send_to_intruder` | `SendToIntruderTool` | Send request to Intruder |
| `get_active_editor_contents` | `GetActiveEditorContentsTool` | Read active editor tab |
| `set_active_editor_contents` | `SetActiveEditorContentsTool` | Write to active editor tab |
| `generate_collaborator_payload` | `GenerateCollaboratorPayloadTool` | Generate OOB payload |
| `get_collaborator_interactions` | `PollCollaboratorInteractionsTool` | Poll for OOB interactions |
| `poll_collaborator_with_wait` | `CollaboratorPollWithWaitTool` | Sleep then poll (wait configurable) |
| `generate_random_string` | `GenerateRandomStringTool` | Random nonce for fuzzing |
| `base64_encode` | `Base64EncodeTool` | Base64 encode |
| `base64_decode` | `Base64DecodeTool` | Base64 decode |
| `url_encode` | `URLEncodeTool` | URL encode (form-encoded, space→+) |
| `url_decode` | `URLDecodeTool` | URL decode |
| `set_project_options` | `SetProjectOptionsTool` | Write project options |
| `set_user_options` | `SetUserOptionsTool` | Write user options |
| `set_task_execution_engine_state` | `SetTaskExecutionEngineTool` | Pause/resume Burp Scanner |
| `autorize_check` | `AuthorizeCheckTool` | Session-swap bypass detection |
| `autorize_multi_role_check` | `AuthorizeMultiRoleTool` | Multi-role vertical escalation check |

**Autorize wrapper behavior** (`autorize_tools.py`): These tools do not require the Autorize plugin to be installed. They replicate Autorize's session-swap logic by calling `send_http1_request` directly — replaying victim requests with attacker tokens, comparing responses by status code and body equivalence.

**`send_to_intruder` tab naming**: `tab_name` is an explicit parameter. When omitted, the tool auto-derives a name from `payload_type` (e.g. `"Pitchfork"`) or `payload_type + first-two-payloads` (e.g. `"Sniper-id=1-id=2"`). Pass an explicit `tab_name` (e.g. `"FIND-001-IDOR"`) for traceability.

**`url_encode` encoding**: Burp's `url_encode` uses `application/x-www-form-urlencoded` (space → `+`). Use `%20` manually if RFC 3986 encoding is required.

**Empty scope/history**: If Burp scope or proxy history is empty, the analyst reports that cleanly instead of inventing findings.

## Architecture

```
[Burp HTTP History + Scanner + Scope]
               |
               v
  [Agent 1: http_analyst]
      - scope confirmation
      - history triage
      - regex search
      - scanner cross-reference
      - action routing
               |
               v
  [Agent 2: validation_executor]
      - HTTP/1.1 replay
      - HTTP/2 replay
      - repeater setup
      - intruder handoff
      - collaborator checks
      - autorize session-swap checks
               |
               v
  [Agent 3: lead_pentester]
      - QA gate
      - evidence review
      - CVSS scoring
      - remediation writing
               |
               v
  [Agent 4: report_generator]
      - final Markdown report
```

## Project Structure

```
pentest_crew/
├── .env.example
├── .gitignore
├── Guideline.md
├── README.md
├── pyproject.toml
├── uv.lock / uv.toml
├── logs/
├── reports/
├── src/
│   └── pentest_crew/
│       ├── main.py          # Entry point, env validation, input building
│       ├── crew.py          # Crew/agent/task definitions, LLM selection
│       ├── llm_mode.py      # Single vs multi-agent detection, model overrides
│       ├── config/
│       │   ├── agents.yaml  # Agent backstories + tool routing instructions
│       │   └── tasks.yaml   # Task definitions for all 4 pipeline stages
│       └── tools/
│           ├── __init__.py          # Tool singletons + agent tool groups
│           ├── burp_mcp_client.py   # MCP SSE client, response normalization, retry
│           ├── burp_proxy_tools.py  # Proxy/history/scanner/scope tools
│           ├── burp_request_tools.py # HTTP replay, Repeater, Intruder, editor
│           ├── burp_collaborator_tools.py # OOB testing, encoding, random
│           ├── burp_config_tools.py # Project/user options, scanner engine
│           └── autorize_tools.py    # Session-swap bypass detection
└── tests/
    ├── test_autorize_tools.py         # Session swap, bypass detection, verdicts
    ├── test_burp_request_tools.py    # HTTP parsing, Intruder, HTTP/2 headers
    ├── test_burp_wrapper_regressions.py # MCP retry, response normalization, config
    ├── test_crew_smoke.py             # CrewAI initialization, LLM selection
    └── test_main.py                   # Env validation, input building, LLM mode
```

## Requirements

### 1. Python

- Python `>=3.10,<3.14`

Install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate    # Windows
pip install -e .
```

### 2. Burp Suite

Recommended setup:

- Burp Suite Professional or Community
- Burp MCP extension loaded
- Autorize extension loaded (optional — autorize_tools.py works without it)
- Proxy listener running
- Project scope configured before analysis

### 3. Environment Variables

```bash
cp .env.example .env
# then edit .env with your real API keys and engagement settings
```

```env
# LLM API Keys
# Set at least one key. One key runs single-agent mode.
# Two or more keys run multi-agent mode with fallback for missing role-preferred providers.
GOOGLE_API_KEY=your_gemini_key_here
OPENAI_API_KEY=your_openai_key_here
ANTHROPIC_API_KEY=your_anthropic_key_here
OPENROUTER_API_KEY=your_openrouter_key_here

# Burp MCP
BURP_MCP_HOST=127.0.0.1
BURP_MCP_PORT=9876

# Engagement (metadata)
ENGAGEMENT_ID=ENG-2026-001
TARGET_URL=burp://active-scope
CLIENT_NAME=Example Corp
TEST_TYPE=greybox
TESTER_NAME=Security Team
REPORT_OUTPUT_DIR=./reports

# Optional tuning
COLLABORATOR_WAIT_SECS=30

# Model overrides (optional, format: "provider/model" or just "model-name")
MODEL_PENTESTER=openai/gpt-4o
MODEL_HTTP_ANALYST=google/gemini-2.0-flash
```

### 4. Running the Crew

```bash
# Via main.py (recommended — handles report path dynamically)
python src/pentest_crew/main.py

# With inline overrides
ENGAGEMENT_ID=ENG-001 CLIENT_NAME=Acme python src/pentest_crew/main.py

# Via uv
uv run pentest_crew
```

## Expected Outputs

- `reports/pentest_report_<engagement_id>.md` — final client-ready report
- `logs/pentest_crew_log.txt` — crew execution audit log

Convert to PDF or DOCX if needed:

```bash
pandoc reports/pentest_report_ENG-001.md -o reports/pentest_report_ENG-001.pdf
pandoc reports/pentest_report_ENG-001.md -o reports/pentest_report_ENG-001.docx
```

## Agent-to-Tool Mapping

### `http_analyst`

- `output_project_options` — confirm scope
- `get_proxy_http_history` — ingest traffic
- `get_proxy_http_history_regex` — pattern search
- `get_proxy_websocket_history` / `get_proxy_websocket_history_regex` — WS traffic
- `get_scanner_issues` — scanner cross-reference
- `base64_decode` / `url_decode` — decode encoded params/tokens for analysis

### `validation_executor`

- `send_http1_request` / `send_http2_request` — replay with mutations
- `create_repeater_tab` — organize tests by finding ID
- `send_to_intruder` — handoff to Intruder
- `get_active_editor_contents` / `set_active_editor_contents` — editor manipulation
- `generate_collaborator_payload` / `get_collaborator_interactions` / `poll_collaborator_with_wait` — OOB testing
- `generate_random_string` / `base64_encode` / `base64_decode` / `url_encode` / `url_decode` — encoding
- `autorize_check` / `autorize_multi_role_check` — session-swap authorization testing
- `set_proxy_intercept_state` — disable intercept during automated testing
- `get_proxy_http_history` / `search_proxy_http_history` — re-check history during validation
- `get_scanner_issues` — cross-reference scanner state
- `get_project_options` — re-verify scope
- `set_task_execution_engine_state` — pause Burp Scanner during manual testing

### `lead_pentester`

- `get_scanner_issues` — cross-reference automated findings
- `get_proxy_http_history_regex` — independent re-examination
- `get_collaborator_interactions` — re-verify OOB callbacks
- `get_active_editor_contents` — spot-check specific requests
- `output_project_options` — verify scope compliance
- `output_user_options` — check user settings
- `base64_decode` / `url_decode` — decode evidence tokens

### `report_generator`

No Burp tools — consumes structured JSON from previous agents only.

## Recommended Workflow

1. Configure Burp scope for the engagement.
2. Ensure Burp MCP connection is active and proxy history is accessible.
3. Optionally run Burp Scanner on approved scope.
4. If you want access control testing, prepare Autorize with at least two sessions (victim + attacker account).
5. Ensure Burp intercept is disabled before running the crew.
6. Run the crew (the agents will enumerate scope and test endpoints through MCP tools).
7. Review the generated report and confirm remediation priorities before delivery.

## Testing

```bash
uv run pytest tests/ -v
```

## Prompt and Task Design Notes

The configuration is intentionally conservative:

- no forced minimum finding count
- explicit handling for empty Burp scope or empty history
- findings require observable evidence — no theoretical flagging
- Intruder is treated as review/handoff, not automated fuzzing
- unsupported cases route to `NEEDS_ESCALATION`
- Autorize bypass detection uses relative body delta (< 2%) + structural content matching to minimize false negatives
- hard bypass: attacker succeeds (HTTP 200, non-empty body) while victim is denied (non-200) = confirmed broken access control

## References

- [OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty)

## Legal Notice

Use this project only for systems you are explicitly authorized to test. Unauthorized testing is illegal and unethical.