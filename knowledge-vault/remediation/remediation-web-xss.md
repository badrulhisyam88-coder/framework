---
type: remediation
id: REM-WEB-20260518-001
title: "Remediation: Cross-Site Scripting (XSS)"
date: "2026-05-18"
category: web
severity: medium
status: draft
tags:
  - remediation
  - xss
  - owasp-a03
  - web
related_findings:
  - FIND-WEB-20260518-002
related_concepts: []
---

# Remediation: Cross-Site Scripting (XSS)

## Summary

> Cross-Site Scripting (XSS) occurs when user-supplied data is rendered in HTML responses without proper output encoding.

## Root Cause

The application reflects or stores user input in HTML output without encoding HTML special characters, allowing script injection.

## Affected Components

- Any template rendering user input
- API responses embedded in HTML

## Short-Term Fix

> Apply immediately to reduce exploitability.

Apply a Content Security Policy (CSP) header to restrict script execution sources.

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
```

## Long-Term Fix

> Permanent remediation via code or architecture change.

### Developer Guidance

Encode all output: use context-aware encoding (HTML entity encoding for HTML contexts, JS escaping for script contexts). Use modern frameworks that auto-escape by default.

### Recommended Libraries / Functions

| Language | Recommended Approach |
|---|---|
| Python / Jinja2 | Use `{{ var }}` — Jinja2 auto-escapes in HTML mode |
| JavaScript/React | Use JSX — React auto-escapes, never use `dangerouslySetInnerHTML` |
| Java | Use OWASP Java Encoder library |
| PHP | Use `htmlspecialchars($input, ENT_QUOTES, 'UTF-8')` |

## Verification Steps

1. Retest with `<script>alert(1)</script>` — it should appear as literal text, not execute
2. Verify CSP header present in HTTP response
3. Scan with OWASP ZAP passive scan — expect no XSS findings

```bash
curl -sI https://target/page | grep -i content-security-policy
```

## References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
- [PortSwigger — XSS](https://portswigger.net/web-security/cross-site-scripting)

## Related

- Concept: [[concept-xss]]
- Findings:
- [[internal-xss-001]]
