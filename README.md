# Pentest Crew

Multi-agent web pentest pipeline built with CrewAI, Burp Suite MCP, and the Autorize extension.

This project is designed for post-browsing analysis. You test the target manually first, let Burp capture HTTP history, then run this crew to triage requests, validate selected candidates, review evidence, and generate a report.

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

This repository is now aligned to the Burp MCP capabilities that are actually available in the connected Burp environment:

- Proxy and review:
  - `get_proxy_http_history`
  - `get_proxy_http_history_regex`
  - `get_proxy_websocket_history`
  - `get_proxy_websocket_history_regex`
  - `get_scanner_issues`
  - `output_project_options`
  - `output_user_options`
  - `set_proxy_intercept_state`
- Request execution:
  - `send_http1_request`
  - `send_http2_request`
  - `create_repeater_tab`
  - `send_to_intruder`
  - `get_active_editor_contents`
  - `set_active_editor_contents`
- Collaborator and helpers:
  - `generate_collaborator_payload`
  - `get_collaborator_interactions`
  - `generate_random_string`
  - `base64_encode`
  - `base64_decode`
  - `url_encode`
  - `url_decode`
- Project wrappers:
  - `autorize_check`
  - `autorize_multi_role_check`
  - `poll_collaborator_with_wait`

Important limitations:

- `send_to_intruder` should be treated as a handoff/setup action for manual Intruder review, not as a full automated fuzzing engine with result harvesting.
- Findings are only as good as the Burp history and scope you prepared beforehand.
- If Burp scope is empty or history is empty, the analyst should report that cleanly instead of inventing findings.

## Architecture

```text
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
      - autorize checks
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

```text
pentest_crew/
├── .env
├── Guideline.md
├── README.md
├── pyproject.toml
└── src/
    └── pentest_crew/
        ├── main.py
        ├── crew.py
        ├── config/
        │   ├── agents.yaml
        │   └── tasks.yaml
        └── tools/
            ├── __init__.py
            ├── autorize_tools.py
            ├── burp_collaborator_tools.py
            ├── burp_mcp_client.py
            ├── burp_proxy_tools.py
            └── burp_request_tools.py
```

## Requirements

### 1. Python

- Python `>=3.10,<3.14`

Install dependencies:

```bash
uv pip install -e .
```

### 2. Burp Suite

Recommended setup:

- Burp Suite Professional or Community
- Burp MCP extension loaded
- Autorize extension loaded
- Proxy listener running
- Project scope configured before analysis

The connected Burp instance used during review had:

- MCP Server extension loaded
- Autorize extension loaded
- Proxy listener on `127.0.0.1:8080`
- HTTP/2 enabled

### 3. Environment Variables

Copy and edit:

```bash
cp .env.example .env
```

Example:

```env
GOOGLE_API_KEY=your_gemini_key
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key

BURP_MCP_HOST=127.0.0.1
BURP_MCP_PORT=9876

ENGAGEMENT_ID=ENG-2026-001
TARGET_URL=https://target.example.com
CLIENT_NAME=Example Corp
TEST_TYPE=greybox
TESTER_NAME=Security Team
```

## Recommended Workflow

1. Configure Burp scope for the engagement.
2. Browse the target manually through Burp and populate HTTP history.
3. Optionally run Burp Scanner on approved scope.
4. If you want access control testing, prepare Autorize with at least two sessions.
5. Make sure Burp intercept is not blocking the run.
6. Run the crew.

## Running

Using CrewAI CLI:

```bash
crewai run
```

Using Python directly:

```bash
python src/pentest_crew/main.py
```

With inline overrides:

```bash
ENGAGEMENT_ID=ENG-001 TARGET_URL=https://app.target.com crewai run
```

## Expected Outputs

- `reports/pentest_report_<engagement_id>.md`
- `logs/pentest_crew_log.txt`

Convert the Markdown report if needed:

```bash
pandoc reports/pentest_report_ENG-001.md -o reports/pentest_report_ENG-001.pdf
pandoc reports/pentest_report_ENG-001.md -o reports/pentest_report_ENG-001.docx
```

## Agent-to-Tool Mapping

### `http_analyst`

Tools:

- `output_project_options`
- `get_proxy_http_history`
- `get_proxy_http_history_regex`
- `get_proxy_websocket_history`
- `get_proxy_websocket_history_regex`
- `get_scanner_issues`
- `base64_decode`
- `url_decode`

Purpose:

- confirm scope
- assess captured traffic
- search for candidate patterns
- assign WSTG-oriented action routing

### `validation_executor`

Tools:

- `set_proxy_intercept_state`
- `send_http1_request`
- `send_http2_request`
- `create_repeater_tab`
- `send_to_intruder`
- `get_active_editor_contents`
- `set_active_editor_contents`
- `generate_collaborator_payload`
- `get_collaborator_interactions`
- `poll_collaborator_with_wait`
- `generate_random_string`
- `base64_encode`
- `base64_decode`
- `url_encode`
- `url_decode`
- `autorize_check`
- `autorize_multi_role_check`

Purpose:

- replay baseline requests
- run low-noise validation
- prepare Intruder cases for manual follow-up
- confirm OOB callbacks
- test authorization boundaries

### `lead_pentester`

Tools:

- `get_scanner_issues`
- `get_proxy_http_history_regex`
- `get_collaborator_interactions`
- `get_active_editor_contents`
- `output_project_options`
- `base64_decode`
- `url_decode`

Purpose:

- cross-check evidence
- enforce QA
- downgrade or reject weak findings
- produce scoring and remediation content

### `report_generator`

Tools:

- none

Purpose:

- convert approved findings into a client-ready report

## Prompt and Task Design Notes

The current configuration in `src/pentest_crew/config/` is intentionally conservative:

- no forced minimum finding count
- explicit handling for empty Burp scope or empty history
- action names now match realistic execution paths
- Intruder is treated as review/handoff, not fake automation
- unsupported cases are routed to `MANUAL_REVIEW` or `NEEDS_ESCALATION`

## References

- OWASP WSTG v4.2: https://owasp.org/www-project-web-security-testing-guide/v42/
- AllAboutBugBounty: https://github.com/daffainfo/AllAboutBugBounty

## Legal Notice

Use this project only for systems you are explicitly authorized to test. Unauthorized testing is illegal and unethical.
