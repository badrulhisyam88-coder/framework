---
type: remediation
id: REM-<CATEGORY>-<YYYYMMDD>-<NNN>
title: "Remediation: <Vulnerability Class>"
date: YYYY-MM-DD
category: web | api | network | cloud
severity: critical | high | medium | low
status: draft | reviewed | published
tags:
  - remediation
  - <vuln-class>
  - <owasp-ref>
  - <category>
related_findings: []
related_concepts: []
---

# Remediation: <Vulnerability Class>

## Summary

> What vulnerability class this playbook addresses and the primary fix approach.

## Root Cause

<!-- Why does this vulnerability class exist? Developer assumption, missing validation, framework gap, etc. -->

## Affected Components

- <!-- Framework / language / component type -->
- <!-- Specific files or patterns where this typically appears -->

## Short-Term Fix

> Apply immediately to reduce exploitability.

<!-- Step-by-step mitigation that can be applied without a code release, e.g., WAF rule, config change. -->

```
<!-- Config snippet, WAF rule, or patch example -->
```

## Long-Term Fix

> Permanent remediation via code or architecture change.

### Developer Guidance

```
<!-- Secure code pattern or library recommendation -->
```

### Recommended Libraries / Functions

| Language | Recommended Approach |
|---|---|
| Python | |
| JavaScript/Node | |
| Java | |
| PHP | |

## Verification Steps

1. <!-- How to confirm the fix is in place -->
2. <!-- Re-test payload that originally confirmed the vulnerability -->
3. <!-- Expected outcome after remediation -->

```bash
# Verification command or test payload
```

## References

- [OWASP Prevention Cheat Sheet]()
- [CWE-<NNN>]()
- [PortSwigger — <Topic>]()

## Related

- Concept: [[concept-<slug>]]
- Findings: [[FIND-<CATEGORY>-<YYYYMMDD>-<NNN>]]
