---
type: blue-team
id: BLUE-20260518-JUICE-SHOP-STORED-XS
title: Blue Team — Stored XSS via Product Review
date: 2026-05-18
subtype: detection
status: draft
severity: medium
tags:
  - blue-team
  - detection
  - xss
  - stored-xss
  - owasp-a03
  - mitre-t1059
  - output-encoding
  - mitre-t1059.007
related_findings: []
related_concepts: []
related_attack_chains: []
data_sources:
  - application-logs
  - waf-logs
  - http-access-logs
challenge_id: juice_shop_stored_xss_01
source_lab: juice_shop
---

# Blue Team — Stored XSS via Product Review

## Purpose

> Detection and mitigation analysis for the **Stored XSS via Product Review** challenge (xss).
> This note is derived from the AI_Cyber_Lab challenge blueprint and documents
> the defensive perspective for the techniques practised in this lab.

## Threat Context

**Technique:** Command and Scripting Interpreter - JavaScript
**ID:** T1059.007
**Tactic:** Xss
**Adversary Objective:** Inject a JavaScript payload via the product review feature

## Detection Logic

### Log Sources Required

| Source | Field | Notes |
|---|---|---|
| HTTP Access Logs | request_uri, request_body | All web application traffic |
| WAF Logs | blocked_requests, rule_triggered | ModSecurity / OWASP CRS |
| Application Logs | error_messages, exceptions | Application-level error output |

### Detection Signals

- HTML tags and JavaScript keywords appearing in user-generated content fields
- Script elements or event handler attributes in stored review data
- Content-Security-Policy violation reports if CSP is configured
- Output encoding failures identified through security scanning

### Detection Rule

```yaml
title: Detect Stored XSS via Product Review
status: experimental
description: >
  Detects xss exploitation patterns from juice_shop challenge context.
logsource:
  category: webserver
  product: nginx
detection:
  selection:
    # Add specific field patterns derived from detection signals above
    cs-uri-query|contains:
      - "'"           # SQL injection probe
      - "<script"     # XSS probe
      - "|"           # Command injection
  condition: selection
falsepositives:
  - "Legitimate penetration testing activity"
  - "Security scanning tools"
level: medium
tags:
  - attack.xss
  - attack.t1059.007
```

## Investigation Playbook

### Triage Steps

1. Identify the source IP and user agent from the request logs
2. Correlate with WAF logs for matching rule triggers
3. Check for successful responses (2xx/3xx) following suspicious input
4. Review application error logs for stack traces or SQL errors
5. Determine if any data was returned that indicates exploitation success

### Key Indicators of Compromise

| Type | Indicator | Notes |
|---|---|---|
| HTTP Parameter | Special characters in input fields | `'`, `<script>`, `|`, `..` |
| HTTP Response | 500 errors / stack traces in response | Indicates unhandled injection |
| Auth Log | Login success after repeated failures | Indicates bypass |

## False Positive Analysis

- Security scanning tools (OWASP ZAP, Burp Suite) — distinguish by user-agent
- Penetration testing during scheduled windows — correlate with change tickets
- Developer testing in non-production environments — scope by network segment

## Containment Actions

1. Block source IP at perimeter firewall / WAF
2. Rotate any credentials that may have been exposed
3. Patch or disable the vulnerable endpoint temporarily

## Mitigation Guidance

- Apply context-aware output encoding before rendering user-supplied content
- Implement a strict Content Security Policy that blocks inline script execution
- Validate and sanitize input on the server side before storage
- Use a trusted HTML sanitization library rather than custom filtering
- Store user content as plain text and encode at render time

## OWASP References

- A03:2021 — Injection

## Related

- Challenge: juice_shop_stored_xss_01
- Concept: [[concept-xss]] [[concept-stored-xss]] [[concept-owasp-a03]]
