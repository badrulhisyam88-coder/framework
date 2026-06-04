---
type: finding
id: FIND-<CATEGORY>-<YYYYMMDD>-<NNN>
title: "<Short descriptive title>"
date: YYYY-MM-DD
severity: critical | high | medium | low | info
category: web | api | network | cloud
source: lab | ctf | bugbounty | assessment | ai-assist
platform: htb | thm | pg | ctf | real-world
target: "<Target name or URL (anonymize if real-world)>"
status: draft | confirmed | remediated
tags:
  - <vuln-class>       # e.g. sqli, xss, idor
  - <owasp-ref>        # e.g. owasp-a03
  - <mitre-ref>        # e.g. mitre-t1190
  - <severity>
  - <platform>
related_labs: []
related_concepts: []
related_findings: []
remediation_ref: ""
---

# <Title>

## Summary

> One or two sentences. What is vulnerable, what can an attacker do, and what is the business impact.

## Environment

| Field | Value |
|---|---|
| Target | |
| URL / Endpoint | |
| Parameter / Input | |
| Date Tested | |
| Tester | |

## Vulnerability Details

**Type:** <!-- e.g. SQL Injection (Error-Based) -->
**CWE:** <!-- e.g. CWE-89 -->
**CVSS Score:** <!-- e.g. 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) -->

### Description

<!-- Explain the root cause. What is the vulnerable code/configuration doing wrong? -->

## Proof of Concept

### Steps to Reproduce

1. <!-- Step 1 -->
2. <!-- Step 2 -->
3. <!-- Step 3 -->

### Payload / Request

```http
<!-- Paste the raw HTTP request or payload -->
```

### Response / Evidence

```
<!-- Paste the relevant portion of the response -->
```

### Screenshot Reference

<!-- If screenshots exist: ./screenshots/FIND-<ID>-01.png -->

## Impact

<!-- What can be achieved by exploiting this? Data exfiltration, authentication bypass, RCE, etc. -->

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| | | |

## References

- [OWASP - <Category>]()
- [CWE-<NNN>]()
- [PortSwigger - <Topic>]()

## Related

- Concept: [[concept-<slug>]]
- Lab: [[<lab-file-slug>]]
- Remediation: [[remediation-<category>-<slug>]]
- Related Finding: [[FIND-<CATEGORY>-<YYYYMMDD>-<NNN>]]
