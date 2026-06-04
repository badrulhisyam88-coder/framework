---
type: attack-chain
id: CHAIN-<YYYYMMDD>-<NNN>
title: "<Attack Chain Name>"
date: YYYY-MM-DD
status: draft | complete
target_environment: lab | ctf | simulated | anonymized
initial_access: "<initial vector summary>"
outcome: "<end state: e.g. domain admin, data exfil, persistence>"
tags:
  - attack-chain
  - <primary-technique>
  - <mitre-tactic>      # e.g. initial-access, lateral-movement, privilege-escalation
related_findings: []
related_labs: []
related_concepts: []
mitre_techniques: []    # e.g. [T1190, T1078, T1059]
---

# <Attack Chain Title>

## Overview

> Narrative summary. What entry point was used, how the attacker moved through the environment, and what the final objective was.

## Environment

| Field | Value |
|---|---|
| Target | |
| Scope | |
| Date | |
| Source | lab / ctf / simulated |

## Kill Chain

```
[Initial Access] → [Execution] → [Persistence] → [Privilege Escalation] → [Lateral Movement] → [Impact]
```

---

## Phase 1: Initial Access

**Technique:** <!-- MITRE name -->
**MITRE ID:** <!-- T1190 etc. -->

### Description

<!-- What was exploited to gain initial access? -->

### Finding Reference

[[FIND-<CATEGORY>-<YYYYMMDD>-<NNN>]]

```bash
# Key command or payload
```

---

## Phase 2: <Phase Name>

**Technique:**
**MITRE ID:**

### Description

### Commands

```bash
```

---

## Phase 3: <Phase Name>

**Technique:**
**MITRE ID:**

### Description

### Commands

```bash
```

---

## Phase N: Impact / Objective

**Outcome:**

<!-- What was achieved at the end of the chain? -->

---

## MITRE ATT&CK Summary

| Phase | Tactic | Technique | ID |
|---|---|---|---|
| Initial Access | | | |
| Execution | | | |
| Persistence | | | |
| Privilege Escalation | | | |
| Lateral Movement | | | |
| Impact | | | |

## Detection Opportunities

| Phase | Detection Point | Log Source |
|---|---|---|
| | | |

## References

- [MITRE ATT&CK Navigator]()

## Related

- Findings: [[FIND-<CATEGORY>-<YYYYMMDD>-<NNN>]]
- Lab: [[<lab-file-slug>]]
- Blue Team: [[<blue-team-file-slug>]]
- Concept: [[concept-<slug>]]
