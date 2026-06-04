---
type: attack-chain
id: CHAIN-20260518-001
title: Web SQLi to SSH Root Access
date: "2026-05-18"
status: draft
target_environment: real-world
initial_access: sqli
outcome: Root SSH access via credential reuse from SQLi data extraction
tags:
  - attack-chain
  - sqli
  - ssh-cred
related_findings:
  - FIND-WEB-20260518-001
  - FIND-WEB-20260518-002
  - FIND-NET-20260518-001
related_labs: []
related_concepts: []
mitre_techniques:
  - T1190
  - T1078
---

# Web SQLi to SSH Root Access

## Overview

> SQL injection on the login endpoint extracted admin credentials from the database. Credentials were reused via SSH for direct root-equivalent access on the same host.

## Environment

| Field | Value |
|---|---|
| Target | internal-web-01 (10.0.1.55) |
| Scope | Internal segment A — 10.0.1.0/24 |
| Date | 2026-05-18 |
| Source | real-world |

## Kill Chain

```
[Initial Access] → [Execution] → [Persistence] → [Privilege Escalation] → [Impact]
```

---

## Phase 1: Sqli — 10.0.1.55

**Technique:** Exploit Public-Facing Application
**MITRE ID:** T1190

### Description

Finding ID: internal-sqli-001
Type: sqli | Severity: high | Status: validated_exploitable

```bash
' OR 1=1--
```

---

## Phase 2: Ssh Cred — 10.0.1.55

**Technique:** Valid Accounts
**MITRE ID:** T1078

### Description

Finding ID: internal-ssh-001
Type: ssh_cred | Severity: critical | Status: validated_exploitable

```bash
ssh admin@10.0.1.55 (password: admin123)
```

---


## MITRE ATT&CK Summary

| Phase | Tactic | Technique | ID |
|---|---|---|---|
| Phase 1 | Initial Access | Exploit Public-Facing Application | T1190 |
| Phase 2 | Credential Access | Valid Accounts | T1078 |

## Detection Opportunities

| Phase | Detection Point | Log Source |
|---|---|---|
| Phase 1: sqli | SQL error patterns in HTTP responses | WAF / Application logs |
| Phase 2: ssh_cred | Successful SSH auth from unexpected source | Auth logs / SIEM |

## Related

- Findings:
- [[internal-sqli-001]]
- [[internal-ssh-001]]
- Lab: —
- Blue Team: —
