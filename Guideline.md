# Pentest and Bug Bounty Guideline

This document is a practical testing guideline for using this repository during web pentest or bug bounty work. It is aligned to OWASP WSTG v4.2 and supplemented by the vulnerability categories and bug bounty notes collected in `daffainfo/AllAboutBugBounty`.

References:

- [OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [OWASP Web Application Security Testing index](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/)
- [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty)

## Purpose

Use this guideline when:

- preparing Burp history before running the crew
- deciding which bug classes to prioritize
- mapping findings to WSTG-style test areas
- keeping bug bounty testing focused, reproducible, and non-destructive

## Core Operating Model

This project can run directly with Burp MCP access (scope + history + request
execution). Manual browsing is optional for deeper coverage, not a hard
prerequisite.

Recommended flow:

1. Confirm authorization, scope, and target rules.
2. Configure Burp scope and logging.
3. Ensure Burp scope is correct and proxy history is accessible via MCP.
4. Run this crew to triage, validate, review, and document findings.
5. Optionally add manual browsing or targeted manual tests to enrich coverage.

## Testing Principles

- Prefer evidence over guesswork.
- Keep testing low-noise and reproducible.
- Do not use destructive payloads.
- Do not force findings when history is weak.
- Track identity, role, and object ownership carefully.
- Write PoC steps so another tester can replay them.
- Separate candidate findings from confirmed findings.

## Prepare Burp Before Running the Crew

**Minimum preparation:**

- define target scope
- ensure Burp MCP is connected and readable
- ensure in-scope hosts are configured
- ensure proxy history/scanner data are available (or allow the crew to do
  in-scope smoke testing)

**Recommended additional preparation:**

- browse as multiple roles if allowed
- prepare two or more session tokens for the Autorize session-swap checks (victim account + attacker/lower-privilege account)
- run safe scanner coverage on allowed targets
- keep notes on account IDs, object IDs, email addresses, and role differences

## WSTG-Aligned Test Areas

The WSTG web application testing areas most relevant to this project are:

- Information Gathering
- Configuration and Deployment Management Testing
- Identity Management Testing
- Authentication Testing
- Authorization Testing
- Session Management Testing
- Input Validation Testing
- Error Handling Testing
- Weak Cryptography Testing
- Business Logic Testing
- Client-side Testing

Use the crew directly against Burp MCP data. Additional traffic coverage will
improve depth, but it is not mandatory to start.

## High-Value Bug Bounty Categories

Based on the categories visible in `AllAboutBugBounty`, the most useful categories for this project are:

- IDOR
- SQL Injection
- XSS
- SSRF
- Open Redirect
- File Upload
- LFI and RFI
- Mass Assignment
- OAuth Misconfiguration
- Host Header Injection
- Web Cache Deception
- Web Cache Poisoning
- CSRF
- Business Logic Errors
- JWT Vulnerabilities
- Default Credentials

These categories fit well with Burp history review, request replay, Collaborator checks, and authorization testing.

## What to Capture in Burp

Capture requests that help downstream analysis:

- login and registration
- password reset and MFA
- profile and account management
- object lookup by ID
- admin and privileged endpoints
- file upload and download
- import and export flows
- search and filter endpoints
- API requests with JSON bodies
- webhook, callback, or URL-fetch features
- redirects and return parameters
- any request carrying JWTs, API keys, or role-bearing tokens

## Practical Checklist by Area

### 1. Information Gathering

**Look for:**
- hostnames, subdomains, alternate environments
- API versions
- framework clues
- admin paths
- debug, staging, and internal routes
- exposed configuration and backup files

**Burp signals:**
- unusual paths in history
- comments in JavaScript responses
- alternate hostnames in redirects
- metadata files such as `.git`, `.env`, `.bak`, `.yaml`, `.json`

### 2. Authentication

**Test for:**
- weak login flows
- password reset abuse
- alternate authentication paths
- remember-me misuse
- missing brute force protection
- weak MFA enforcement

**Useful captured requests:**
- login request
- reset token submission
- MFA challenge request
- session refresh requests

### 3. Authorization

This is one of the highest-value areas for this project.

**Test for:**
- horizontal privilege escalation
- vertical privilege escalation
- missing object ownership checks
- direct access to admin endpoints
- role confusion across APIs and UI

**Best practice:**
- capture the same workflow under multiple accounts
- preserve object IDs and tenant IDs
- supply at least two session tokens to the `autorize_check` tool (victim + attacker)
- note when a request succeeds with a different user token

**Bypass detection approach:** The autorize wrapper uses relative body size delta (< 2%) combined with structural content comparison (after stripping dynamic values like user IDs, timestamps, and emails) to detect bypasses. This catches cases where responses are similar in length but contain another user's data.

### 4. Session Management

**Test for:**
- session fixation
- predictable tokens
- overly long-lived tokens
- missing logout invalidation
- cookie scope and security flag issues

**Useful evidence:**
- `Set-Cookie` headers
- token refresh endpoints
- requests that continue working after logout or role change

### 5. Input Validation

**Test for:**
- SQLi
- NoSQLi
- XSS
- CRLF injection
- path traversal
- file inclusion
- command injection indicators

**Best practice:**
- start with low-noise payloads
- compare baseline and mutated responses
- note status changes, reflected data, error fragments, and content-length deltas

### 6. SSRF and OOB Testing

**Look for:**
- webhook URLs
- import-by-URL features
- avatar fetchers
- PDF generators
- URL preview endpoints
- XML processors

**Best practice:**
- use `generate_collaborator_payload` + `poll_collaborator_with_wait`
- the wait duration is configurable via the `COLLABORATOR_WAIT_SECS` environment variable (default: 30s)
- record parameter name and original value
- repeat cautiously
- treat DNS or HTTP callbacks as stronger evidence than timing only

### 7. File Upload

**Test for:**
- dangerous extensions
- MIME confusion
- content-type trust
- SVG or HTML upload abuse
- parser abuse
- overwrite behavior

**Capture:**
- multipart requests
- storage URLs
- preview endpoints
- download behavior

### 8. Business Logic

**Look for:**
- missing workflow sequencing
- coupon abuse
- price tampering
- quantity manipulation
- privilege changes through hidden parameters
- duplicate action replay
- race-friendly flows

These often do not match simple regex patterns, so richer traffic coverage
improves analysis quality.

## Priority Heuristics

Prioritize requests with:

- object IDs tied to users, invoices, orders, tenants, or files
- role-dependent responses
- admin-like route names
- callback or URL parameters
- multipart upload bodies
- encoded tokens
- rich JSON mutation surfaces
- payment, checkout, payout, invitation, and sharing flows

## Good Evidence Standard

A finding is stronger when you can show:

- original request
- exact modified request
- changed response or changed authorization outcome
- stable reproduction
- affected role or object boundary
- impact that is plausible and specific

Weak evidence includes:

- one noisy error page
- generic 500 without context
- speculative impact with no PoC
- unverified scanner noise

## Reporting Style

When writing findings:

- describe the endpoint and parameter exactly
- describe what changed between baseline and test case
- describe impact in business terms
- avoid exaggerated claims
- map to the closest WSTG area or identifier when practical

## Bug Bounty Safety Notes

- follow program policy and scope strictly
- avoid denial-of-service behavior
- avoid credential stuffing or mass automation unless explicitly allowed
- avoid touching third-party assets unless the program permits it
- avoid data exfiltration beyond minimal proof
- prefer redacted screenshots and minimal PoC data

## How This Repo Fits the Workflow

Use this repository directly against active Burp scope/history. Existing rich
history helps, but the workflow does not require manual pre-browsing.

**Strong fit:**
- triaging large Burp histories
- routing requests to validation actions
- reviewing authorization and OOB candidates
- turning notes and evidence into a structured report

**Weak fit:**
- blind recon with no history
- high-volume fuzzing campaigns
- exploitation paths that require custom automation not exposed through Burp MCP

## Suggested Personal Workflow

1. Read program scope and policy.
2. Set Burp scope.
3. Ensure Burp MCP connection is healthy.
4. Create at least two accounts if allowed (for authorization checks).
5. Run this project.
6. Review candidate findings and keep only evidence-backed issues.
7. Optionally add manual follow-up for complex business-logic edge cases.

## Reference Categories from AllAboutBugBounty

The referenced repository is especially useful as an idea bank for:

- recon categories
- bypass ideas such as 2FA, 403, 429, and captcha bypass
- vulnerability-specific notes for IDOR, XSS, SQLi, SSRF, file upload, and cache issues
- checklist-style inspiration for account flows such as forgot password

Use it as a testing idea source, not as a reason to claim a finding without proof.
