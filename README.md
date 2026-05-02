# Pentest Crew

Multi-agent web pentest pipeline built with CrewAI, Burp Suite MCP, and the Autorize extension.

This project runs directly on top of Burp MCP. The crew reads scope/history/scanner
state from Burp and executes request validation through Burp tools without needing
manual target input as a prerequisite.

## Modes

This project supports **two modes** controlled by how many LLM API keys are configured:

### Single-Agent Mode (1 API key)

Uses one LLM to run all 4 stages sequentially in a single agent (`pentester`).

| Aspect | Detail |
|--------|--------|
| **Active Agent** | `pentester` (1 agent) |
| **Active Task** | `pentest_task` (1 unified task) |
| **Tools** | ALL_TOOLS — all 118 tools available |
| **Scope** | HTTP triage → Validation → QA Review → Report Generation |
| **Pipeline** | All 4 stages in 1 agent, 1 context window |

**Pentester's tool access**: All 118 tools from every tool group. Pentester has full access to scope discovery, HTTP analysis, auth testing, fuzzing, validation, QA review, exploitation, and evidence capture.

### Multi-Agent Mode (2+ API keys)

Uses 2–8 specialist agents in a sequential pipeline, each expert in its domain.

| Aspect | Detail |
|--------|--------|
| **Active Agents** | 8 specialist agents |
| **Active Tasks** | 8 stage-separated tasks |
| **LLM Providers** | Each agent uses a different preferred provider (with fallback) |
| **Tool Scope** | Tool groups are scoped per role — no unnecessary tools exposed |

**Pipeline (8 stages):**

```
scope_discovery_agent → http_analyst → auth_agent → fuzzing_agent
    → validation_executor → lead_pentester → exploitation_agent → report_generator
```

---

## Agent Reference

| # | Agent | Mode | Task | Tools | Role |
|---|-------|------|------|-------|------|
| 1 | `pentester` | Single | `pentest_task` | ALL (118) | All 4 stages in one agent |
| 2 | `scope_discovery_agent` | Multi | `scope_discovery_task` | 11 | Target discovery without existing traffic |
| 3 | `http_analyst` | Multi | `http_triage_task` | 17 | HTTP history triage, finding candidates |
| 4 | `auth_agent` | Multi | `auth_task` | 8 | Auth endpoint discovery, session extraction |
| 5 | `fuzzing_agent` | Multi | `fuzzing_task` | 9 | Parameter auto-fuzzing, anomaly detection |
| 6 | `validation_executor` | Multi | `validation_task` | 105 | Vulnerability validation, Repeater/Collaborator/Autorize |
| 7 | `lead_pentester` | Multi | `qa_review_task` | 14 | QA review, CVSS scoring, coverage analysis |
| 8 | `exploitation_agent` | Multi | `exploitation_task` | 16 | Post-confirmation data extraction |
| 9 | `report_generator` | Multi | `report_generation_task` | 5 | Final client-ready report |

---

## Tool Groups Per Agent

| Agent | Tool Group | Count | Key Tools |
|-------|-----------|-------|-----------|
| `scope_discovery_agent` | SCOPE_DISCOVERY_TOOLS | 11 | `robots_sitemap_tool`, `favicon_fingerprint_tool`, `path_enumeration_tool`, `js_file_analyzer`, `github_dorking_tool`, `dns_enumeration_tool` |
| `http_analyst` | ANALYST_TOOLS | 17 | `get_proxy_http_history`, `search_proxy_http_history`, `get_scanner_issues`, `auth_endpoint_discovery`, `credential_extraction`, `session_token_extraction` |
| `auth_agent` | AUTH_TOOLS | 8 | `auth_endpoint_discovery`, `credential_extraction`, `session_token_extraction`, `auto_login_test`, `send_http1_request` |
| `fuzzing_agent` | FUZZING_TOOLS | 9 | `param_discovery`, `param_fuzzer`, `param_typer`, `fuzzing_combo`, `send_to_intruder` |
| `validation_executor` | EXECUTOR_TOOLS | 105 | SSRF, GraphQL, XSS, JWT, SQLi, XXE, Command Injection, WebSocket, DOM XSS, Request Smuggling, Business Logic, CRLF Injection, Prototype Pollution, Cache Poisoning, postMessage Security, LDAP Injection, S3 Bucket Enum, Redirect/CORS, Stateful Testing, Fuzzing, Data Extraction |
| `lead_pentester` | REVIEWER_TOOLS | 14 | `coverage_gap_analyzer`, `session_fixation_test`, `multi_step_flow_test`, `oauth_flow_test`, `cookie_persistence_test`, `false_positive_tracker`, `differential_reporting` |
| `exploitation_agent` | EXPLOITATION_TOOLS | 16 | `sql_data_extraction`, `idor_data_extraction`, `ssrf_data_extraction`, `jwt_data_extraction`, `generic_data_extract`, `autorize_check`, `exploit_chain_correlator` |
| `report_generator` | REPORTER_TOOLS | 5 | `poc_script_generator`, `request_response_dumper`, `evidence_bundler`, `filter_report_input`, `differential_reporting` |

---

## Vulnerability Categories (TOOL_CATEGORIES)

The validation executor uses `TOOL_CATEGORIES` for dynamic tool composition based on analyst finding types. Each category maps to one or more specialized tools.

| Category | Tools |
|----------|-------|
| `sqli` | SQL injection error, blind, union, boolean blind, stacked queries, full test, data extraction |
| `xss` | Context test, WAF bypass, comprehensive, DOM XSS variants |
| `ssrf` | Basic, metadata enum, protocol test, blind, data extraction |
| `xxe` | Test, blind, billion laughs, XInclude, full test |
| `cmd_injection` | Test, blind, output extraction, encoded, full test |
| `graphql` | Introspection, enum brute, alias abuse, batch bypass, IDOR, depth attack |
| `jwt` | Analysis, none bypass, manipulate, alg confusion, data extraction |
| `smuggling` | Request smuggling, CL.0, TE/TE, HTTP/2 |
| `redirect` | Open redirect, host header injection, CORS misconfig, URL pollution |
| `business_logic` | Race condition, parameter pollution, mass assignment, OTP bypass, coupon bypass |
| `idor` | IDOR data extraction |
| `websocket` | Handshake, injection, frame injection, CSWSH, fuzzer, full test |
| `auth` | Session fixation, multi-step flow, OAuth flow, cookie persistence |
| `fuzzing` | Param discovery, fuzzer, typer, combo |
| `crlf` | HTTP response splitting test, header injection test |
| `prototype_pollution` | Basic and deep prototype pollution |
| `cache_poisoning` | Cache poisoning test, WebCache deception test |
| `postmessage` | postMessage listener security test |
| `ldap` | LDAP injection, blind LDAP injection |
| `s3` | S3 bucket enumeration, S3 SSRF test |
| `extraction` | Generic data extraction |

---

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

**Autorize wrapper behavior** (`autorize_tools.py`): These tools do not require the Autorize plugin to be installed. They replicate Autorize's session-swap logic by calling `send_http1_request` directly — replaying victim requests with attacker tokens, comparing responses by status code and structural body equivalence.

**`send_to_intruder` tab naming**: `tab_name` is an explicit parameter. When omitted, the tool auto-derives a name from `payload_type` (e.g. `"Pitchfork"`) or `payload_type + first-two-payloads` (e.g. `"Sniper-id=1-id=2"`). Pass an explicit `tab_name` (e.g. `"FIND-001-IDOR"`) for traceability.

**`url_encode` encoding**: Burp's `url_encode` uses `application/x-www-form-urlencoded` (space → `+`). Use `%20` manually if RFC 3986 encoding is required.

**Credential redaction and binary suppression**: Burp history/editor/request outputs are normalized before they reach the agents. Authorization headers, cookies, API keys, and similar secrets are redacted by default, and binary bodies are replaced with short placeholders. The wrappers also extract method/path/parameter metadata and risk hints so the crew can still triage attack surface effectively.

**Admin tools**: `set_project_options`, `set_user_options`, `output_user_options`, and `set_task_execution_engine_state` remain available as wrappers but are not exposed to autonomous agent tool groups by default. This avoids accidental scope or Burp configuration drift during unattended runs.

**Empty scope/history**: If Burp scope or proxy history is empty, the analyst reports that cleanly instead of inventing findings.

---

## Architecture

### Single-Agent Mode (1 API key)

```
[Burp HTTP History + Scanner + Scope]
               |
               v
      [pentester — ALL stages, 1 agent]
         - HTTP triage
         - Validation
         - QA Review
         - Report Generation
         - All 118 tools
```

### Multi-Agent Mode (2+ API keys)

```
[Burp HTTP History + Scanner + Scope]
               |
               v
    [scope_discovery_agent] ← no existing traffic needed
         robots.txt, favicon fingerprint, path enum,
         JS analysis, GitHub dorking, DNS enumeration
               |
               v
         [http_analyst]
         HTTP history triage, finding candidates, scanner cross-ref
               |
               v
          [auth_agent]
          Auth endpoint discovery, session extraction, auto login
               |
               v
        [fuzzing_agent]
        Parameter auto-fuzzing, anomaly detection
               |
               v
      [validation_executor] ← specialist, 105 tools
         HTTP replay, Collaborator, Autorize, SSRF, XSS,
         SQLi, XXE, JWT, Command Injection, WebSocket,
         Request Smuggling, Business Logic, CRLF Injection,
         Prototype Pollution, Cache Poisoning, postMessage Security,
         LDAP Injection, S3 Bucket Enum, Stateful Testing
               |
               v
       [lead_pentester]
       QA gate, CVSS scoring, coverage analysis, FP tracking
               |
               v
      [exploitation_agent] ← post-confirmation only
         SQL/IDOR/SSRF/JWT data extraction, exploit chain correlation
               |
               v
      [report_generator]
      Final Markdown report + PoC scripts + evidence bundle
```

### Pipeline Gates

`pipeline_gates.py` provides optional pre-flight gates that skip agent stages when their preconditions are not met:

| Gate | Condition |
|------|-----------|
| `scope_non_empty` | Burp scope contains at least one URL |
| `auth_endpoints_exist` | Auth-related tokens/cookies present in history |
| `parameters_exist` | At least one parameter discovered in history |
| `confirmed_findings_exist` | Prior run has at least one confirmed finding |

Gates run before their respective agent in multi-agent mode. When a gate fails, the pipeline skips to the next stage rather than running the agent speculatively.

---

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
├── fp_store/           # False positive tracker data
├── evidence_store/     # Evidence bundles per finding
├── src/
│   └── pentest_crew/
│       ├── main.py          # Entry point, env validation, input building
│       ├── crew.py          # Crew/agent/task definitions, LLM selection
│       ├── llm_mode.py      # Single vs multi-agent detection, model overrides
│       ├── pipeline_gates.py # Pre-flight gates for pipeline stage skipping
│       ├── config/
│       │   ├── agents.yaml  # Agent backstories + tool routing instructions
│       │   └── tasks.yaml   # Task definitions for all pipeline stages
│       └── tools/
│           ├── __init__.py              # Tool singletons + agent tool groups
│           ├── burp_mcp_client.py       # MCP SSE client, stealth mode, retry
│           ├── burp_proxy_tools.py      # Proxy/history/scanner/scope tools
│           ├── burp_request_tools.py    # HTTP replay, Repeater, Intruder, editor
│           ├── burp_collaborator_tools.py # OOB testing, encoding, random
│           ├── burp_config_tools.py    # Project/user options, scanner engine
│           ├── autorize_tools.py        # Session-swap bypass detection
│           ├── ssrf_tools.py            # SSRF testing (basic/metadata/protocol/blind)
│           ├── graphql_security_tools.py # GraphQL introspection, alias abuse, batch bypass, IDOR, depth attack
│           ├── xss_bypass_tools.py      # XSS context test, WAF bypass, comprehensive
│           ├── jwt_security_tools.py    # JWT analysis, none bypass, manipulate, alg confusion
│           ├── request_smuggling_tools.py # CL.0, TE/TE, HTTP/2 smuggling
│           ├── business_logic_tools.py   # Race condition, parameter pollution, mass assignment, OTP bypass, coupon bypass
│           ├── redirect_and_cors_tools.py # Open redirect, host header injection, CORS misconfig, URL pollution
│           ├── sql_injection_tools.py    # SQLi error, blind, union, boolean blind, stacked queries, full test
│           ├── xxe_tools.py              # XXE test, blind, billion laughs, XInclude, full test
│           ├── websocket_security_tools.py # WS handshake, injection, frame injection, CSWSH, fuzzer, full test
│           ├── command_injection_tools.py # Cmd injection test, blind, output extraction, encoded, full test
│           ├── dom_xss_tools.py          # DOM XSS test, taint track, fragment test, full test
│           ├── exploitation_tools.py    # SQL/IDOR/SSRF/JWT/generic data extraction
│           ├── auth_tools.py             # Auth endpoint discovery, credential extraction, session token, auto login
│           ├── fuzzing_tools.py          # Param discovery, fuzzer, typer, fuzzing combo
│           ├── scope_discovery_tools.py  # Robots/sitemap, favicon fingerprint, path enum, JS analyzer, GitHub dorking, DNS enum
│           ├── coverage_gap_tools.py     # OWASP Top 10 coverage matrix, WSTG mapping, gap report
│           ├── stateful_testing_tools.py  # Session fixation, multi-step flow, OAuth flow, cookie persistence
│           ├── fp_tracker_tools.py       # False positive tracker, differential reporting
│           ├── evidence_capture_tools.py  # PoC script generator, req/resp dumper, evidence bundler
│           ├── report_filter_tools.py     # Pre-report filtering, finding deduplication
│           ├── exploit_chain_tools.py    # Exploit chain correlation and chaining
│           ├── crlf_injection_tools.py   # HTTP response splitting, header injection
│           ├── prototype_pollution_tools.py # JavaScript prototype pollution testing
│           ├── cache_poisoning_tools.py   # Web cache poisoning and WebCache deception
│           ├── postmessage_security_tools.py # Unsafe postMessage listener detection
│           ├── ldap_injection_tools.py   # LDAP injection and blind LDAP injection
│           └── s3_bucket_tools.py         # S3 bucket enumeration and S3 SSRF testing
└── tests/
    ├── test_autorize_tools.py              # Session swap, bypass detection, verdicts
    ├── test_burp_request_tools.py          # HTTP parsing, Intruder, HTTP/2 headers
    ├── test_advanced_security_tool_regressions.py # Security tool regression tests
    ├── test_burp_safe_outputs.py            # Safe output verification
    ├── test_crew_smoke.py                  # CrewAI initialization, LLM selection, single/multi mode
    ├── test_main.py                        # Env validation, input building, LLM mode
    ├── test_exploit_chains.py              # Exploit chain correlation
    ├── test_pipeline_gates.py              # Pipeline gate skipping logic
    └── test_report_filter.py               # Report filtering and deduplication
```

---

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
# Set 1 key → Single-Agent Mode (pentester, all 4 stages)
# Set 2+ keys → Multi-Agent Mode (8 specialist agents)
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

# Stealth / Anti-Evasion (optional)
# Enable random delay + User-Agent rotation before each request
STEALTH_MODE=false
STEALTH_MIN_DELAY_SECS=0.5
STEALTH_MAX_DELAY_SECS=3.0

# Model overrides (optional, format: "provider/model" or just "model-name")
MODEL_PENTESTER=openai/gpt-4o
MODEL_HTTP_ANALYST=google/gemini-2.0-flash
```

### 4. Running the Crew

```bash
# Via main.py (recommended)
python src/pentest_crew/main.py

# With inline overrides
ENGAGEMENT_ID=ENG-001 CLIENT_NAME=Acme python src/pentest_crew/main.py

# Via uv
uv run pentest_crew
```

## Expected Outputs

- `reports/pentest_report_<engagement_id>.md` — final client-ready report
- `logs/pentest_crew_log.txt` — crew execution audit log
- `fp_store/<engagement_id>_fp.json` — false positive tracker data
- `evidence_store/<engagement_id>_<finding_id>.json` — evidence bundles per finding

Convert to PDF or DOCX if needed:

```bash
pandoc reports/pentest_report_ENG-001.md -o reports/pentest_report_ENG-001.pdf
pandoc reports/pentest_report_ENG-001.md -o reports/pentest_report_ENG-001.docx
```

---

## Mode Comparison Table

| Aspect | Single-Agent (1 key) | Multi-Agent (2+ keys) |
|--------|----------------------|------------------------|
| **API Key** | 1 | 2–8 |
| **Active Agents** | `pentester` (1) | 8 specialist agents |
| **Tasks** | `pentest_task` (1) | 8 tasks |
| **Pipeline** | All 4 stages in 1 agent | Sequential 8-stage pipeline |
| **LLM Providers** | 1 | Each agent uses preferred provider (with fallback) |
| **Tool Access** | ALL_TOOLS (118 tools) | Tool groups scoped per role |
| **Specialist Expertise** | ❌ 1 model for all roles | ✅ 8 expert models, each in domain |
| **Context Overflow Risk** | ⚠️ High (4 stages in 1 context) | ✅ Low (each agent has small context) |
| **Parallel LLM** | ❌ Sequential | ✅ Each agent runs with its own model |
| **Speed** | Depends on 1 model | Faster (specialists work in parallel) |
| **Accuracy** | ⚠️ Depends on single model capability | ✅ Higher (expert per domain) |

---

## Advanced Features

### Stealth / Anti-Evasion Mode

Enabled via `STEALTH_MODE=true` in `.env`. Before each Burp MCP tool call:

- **Random delay**: `STEALTH_MIN_DELAY_SECS` – `STEALTH_MAX_DELAY_SECS` seconds
- **User-Agent rotation**: Random UA injected into Burp project options every 60s
- UA pool includes Chrome, Firefox, Safari, Googlebot, Bingbot

### Coverage Gap Analyzer

`coverage_gap_analyzer` (REVIEWER_TOOLS) — tracks OWASP Top 10 / WSTG coverage matrix per engagement. Reports tested vs untested categories with WSTG-ID mapping.

### Stateful Testing Tools

`validation_executor` and `lead_pentester` have access to:
- `session_fixation_test` — checks if session IDs regenerate after auth
- `multi_step_flow_test` — tests step skipping/replay in checkout/registration flows
- `oauth_flow_test` — tests OAuth2 state parameter, redirect URI, PKCE
- `cookie_persistence_test` — analyzes HttpOnly, Secure, SameSite, domain/path scope

### False Positive Tracker

`false_positive_tracker` (REVIEWER_TOOLS) — records findings per engagement, tracks CONFIRMED/REJECTED/DOWNGRADED verdicts, generates accuracy reports per category. Data stored in `fp_store/<engagement_id>_fp.json`.

### Differential Reporting

`differential_reporting` (REVIEWER_TOOLS, REPORTER_TOOLS) — compares consecutive runs: new findings, resolved findings, recurring findings, accuracy trend. Auto-detects previous engagement from `fp_store`.

### Evidence Auto-Capture

`validation_executor` and `report_generator` have access to:
- `poc_script_generator` — generates PoC in Python/curl/JavaScript/Burp/wget
- `request_response_dumper` — captures raw HTTP req/resp pairs via Repeater
- `evidence_bundler` — packages finding evidence into structured JSON bundle

Evidence bundles stored in `evidence_store/<engagement_id>_<finding_id>.json`.

### Exploit Chain Correlation

`exploit_chain_correlator` (EXPLOITATION_TOOLS) — identifies multi-step exploit chains across findings. Correlates SSRF → IAM credential access → internal service enumeration → data exfiltration. Generates combined CVSS and attack path narrative.

### Pipeline Gates

`pipeline_gates.py` pre-flight checks enable the multi-agent pipeline to skip stages when preconditions aren't met (empty scope, no auth tokens, no parameters). Reduces unnecessary LLM calls and token spend on early stages with no actionable work.

---

## Recommended Workflow

1. Configure Burp scope for the engagement.
2. Ensure Burp MCP connection is active and proxy history is accessible.
3. Optionally run Burp Scanner on approved scope.
4. If you want access control testing, prepare Autorize with at least two sessions (victim + attacker account).
5. Ensure Burp intercept is disabled before running the crew.
6. Run the crew (the agents will enumerate scope and test endpoints through MCP tools).
7. Review the generated report and confirm remediation priorities before delivery.
8. (Multi-agent) Use `false_positive_tracker` in 'report' mode to review accuracy metrics.

---

## Testing

```bash
uv run pytest tests/ -v
```

---

## Prompt and Task Design Notes

The configuration is intentionally conservative:

- no forced minimum finding count
- explicit handling for empty Burp scope or empty history
- findings require observable evidence — no theoretical flagging
- Intruder is treated as review/handoff, not automated fuzzing
- unsupported cases route to `NEEDS_ESCALATION`
- Autorize bypass detection uses normalized body match + JSON field count equivalence to minimize false positives; hard bypass: attacker succeeds (HTTP 200, non-empty body) while victim is denied (non-200) = confirmed broken access control
- XSS detection uses structural unencoded reflection checks (exact match, not case-insensitive) to avoid false positives from safely HTML-encoded inputs
- SQL UNION detection requires DB fingerprint alongside response changes (not generic numeric patterns that match all API responses)

---

## References

- [OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty)

## Legal Notice

Use this project only for systems you are explicitly authorized to test. Unauthorized testing is illegal and unethical.