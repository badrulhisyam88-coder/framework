---
type: blue-team
id: BLUE-20260518-JUICE-SHOP-BROKEN-AU
title: Blue Team — Broken Authentication — Password Reset Abuse
date: 2026-05-18
subtype: detection
status: draft
severity: medium
tags:
  - blue-team
  - detection
  - broken-auth
  - account-takeover
  - owasp-a07
  - mitre-t1078
  - security-questions
  - osint
related_findings: []
related_concepts: []
related_attack_chains: []
data_sources:
  - application-logs
  - waf-logs
  - http-access-logs
challenge_id: juice_shop_broken_auth_01
source_lab: juice_shop
---

# Blue Team — Broken Authentication — Password Reset Abuse

## Purpose

> Detection and mitigation analysis for the **Broken Authentication — Password Reset Abuse** challenge (authentication).
> This note is derived from the AI_Cyber_Lab challenge blueprint and documents
> the defensive perspective for the techniques practised in this lab.

## Threat Context

**Technique:** Valid Accounts
**ID:** T1078
**Tactic:** Authentication
**Adversary Objective:** Reset the admin account password using the Forgot Password feature

## Detection Logic

### Log Sources Required

| Source | Field | Notes |
|---|---|---|
| HTTP Access Logs | request_uri, request_body | All web application traffic |
| WAF Logs | blocked_requests, rule_triggered | ModSecurity / OWASP CRS |
| Application Logs | error_messages, exceptions | Application-level error output |

### Detection Signals

- Enumeration of the Forgot Password endpoint with multiple email addresses
- Correct security question answers submitted on the first attempt
- Password reset followed immediately by login from a different IP
- Unusual patterns in password reset request frequency

### Detection Rule

```yaml
title: Detect Broken Authentication — Password Reset Abuse
status: experimental
description: >
  Detects authentication exploitation patterns from juice_shop challenge context.
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
  - attack.authentication
  - attack.t1078
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

- Replace knowledge-based security questions with time-based OTP or email link recovery
- Rate-limit and CAPTCHA-protect the Forgot Password endpoint
- Invalidate all active sessions on password reset
- Alert on password reset followed by login from a new IP or device
- Never use predictable information (pet names, birth city) as security questions

## OWASP References

- A07:2021 — Identification and Authentication Failures

## Related

- Challenge: juice_shop_broken_auth_01
- Concept: [[concept-broken-auth]] [[concept-account-takeover]] [[concept-owasp-a07]]
