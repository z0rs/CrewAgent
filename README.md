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

## Current Burp Tooling Model

This repository is aligned to the Burp MCP capabilities available in the connected Burp environment:

- **Proxy and review:**
  - `get_proxy_http_history`
  - `get_proxy_http_history_regex`
  - `get_proxy_websocket_history`
  - `get_proxy_websocket_history_regex`
  - `get_scanner_issues`
  - `output_project_options`
  - `output_user_options`
  - `set_proxy_intercept_state`
- **Request execution:**
  - `send_http1_request`
  - `send_http2_request`
  - `create_repeater_tab`
  - `send_to_intruder` (payload previews are kept in tab name; MCP schema currently ignores explicit payload lists)
  - `get_active_editor_contents`
  - `set_active_editor_contents`
- **Collaborator and helpers:**
  - `generate_collaborator_payload`
  - `get_collaborator_interactions`
  - `poll_collaborator_with_wait` (wait duration configurable via `COLLABORATOR_WAIT_SECS` env var)
  - `generate_random_string`
  - `base64_encode` / `base64_decode`
  - `url_encode` / `url_decode`
- **Autorize-style wrappers:**
  - `autorize_check`
  - `autorize_multi_role_check`

**Important limitations:**

- `send_to_intruder` is best treated as a setup/handoff action. Automated result harvesting from Intruder is still limited.
- Findings are only as good as the Burp history and scope you prepared beforehand.
- If Burp scope is empty or history is empty, the analyst reports that cleanly instead of inventing findings.
- The Autorize wrapper tools perform session-swap testing via `send_http1_request`; they require you to capture and supply the relevant session tokens yourself.

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
├── src/
│   └── pentest_crew/
│       ├── main.py
│       ├── crew.py
│       ├── config/
│       │   ├── agents.yaml
│       │   └── tasks.yaml
│       └── tools/
│           ├── __init__.py
│           ├── autorize_tools.py
│           ├── burp_collaborator_tools.py
│           ├── burp_mcp_client.py
│           ├── burp_proxy_tools.py
│           └── burp_request_tools.py
└── tests/
    ├── __init__.py
    ├── test_autorize_tools.py
    ├── test_burp_request_tools.py
    └── test_main.py
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
- Autorize extension loaded
- Proxy listener running
- Project scope configured before analysis

The connected Burp instance used during development had:

- MCP Server extension loaded
- Autorize extension loaded
- Proxy listener on `127.0.0.1:8080`
- HTTP/2 enabled

### 3. Environment Variables

```bash
cp .env.example .env
# then edit .env with your real API keys and engagement settings
```

```env
# LLM API Keys
# Set at least one key. One key runs single-agent mode.
# Two or three keys run multi-agent mode with fallback for missing role-preferred providers.
GOOGLE_API_KEY=your_gemini_key_here
OPENAI_API_KEY=your_openai_key_here
ANTHROPIC_API_KEY=your_anthropic_key_here

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
```

### 4. Running the Crew

```bash
# Via main.py (recommended — handles report path dynamically)
python src/pentest_crew/main.py

# With inline overrides (TARGET_URL optional metadata)
ENGAGEMENT_ID=ENG-001 python src/pentest_crew/main.py

# Via CrewAI CLI
crewai run
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
- `send_to_intruder` — handoff/setup to Intruder (payload previews are encoded in tab name)
- `get_active_editor_contents` / `set_active_editor_contents` — editor manipulation
- `generate_collaborator_payload` / `get_collaborator_interactions` / `poll_collaborator_with_wait` — OOB testing
- `generate_random_string` / `base64_encode` / `base64_decode` / `url_encode` / `url_decode` — encoding
- `autorize_check` / `autorize_multi_role_check` — session-swap authorization testing
- `set_proxy_intercept_state` — disable intercept during automated testing

### `lead_pentester`

- `get_scanner_issues` — cross-reference automated findings
- `get_proxy_http_history_regex` — independent re-examination
- `get_collaborator_interactions` — re-verify OOB callbacks
- `get_active_editor_contents` — spot-check specific requests
- `output_project_options` — verify scope compliance
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

Run the test suite:

```bash
.venv/bin/python -m pytest tests/ -v
```

Current coverage:

- Session token swap logic (cookie / bearer / custom header)
- Auth header stripping and CRLF preservation
- Autorize body normalization (dynamic ID/timestamp stripping)
- HTTP request parsing (`_split_raw_request`)
- HTTP/2 pseudo-header construction
- Intruder payload routing
- Environment variable validation and input building

## Prompt and Task Design Notes

The configuration is intentionally conservative:

- no forced minimum finding count
- explicit handling for empty Burp scope or empty history
- findings require observable evidence — no theoretical flagging
- Intruder is treated as review/handoff, not automated fuzzing
- unsupported cases route to `NEEDS_ESCALATION`
- Autorize bypass detection uses relative body delta (< 2%) + structural content matching to minimize false negatives

## References

- [OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty)

## Legal Notice

Use this project only for systems you are explicitly authorized to test. Unauthorized testing is illegal and unethical.
