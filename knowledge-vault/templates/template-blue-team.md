---
type: blue-team
id: BLUE-<YYYYMMDD>-<NNN>
title: "<Detection or Analysis Title>"
date: YYYY-MM-DD
subtype: detection | dfir | threat-hunting | threat-intel | soc-triage
status: draft | active | archived
severity: critical | high | medium | low | info
tags:
  - blue-team
  - <subtype>
  - <vuln-or-technique>   # e.g. sqli, lateral-movement, kerberoasting
  - <mitre-ref>           # e.g. mitre-t1059
related_findings: []
related_concepts: []
related_attack_chains: []
data_sources: []           # e.g. windows-event-log, zeek, suricata, cloudtrail
---

# <Title>

## Purpose

> What threat or behavior this note is designed to detect, investigate, or understand.

## Threat Context

**Technique:** <!-- MITRE ATT&CK technique name -->
**ID:** <!-- e.g. T1059.001 -->
**Tactic:** <!-- e.g. Execution -->
**Adversary Objective:** <!-- What the attacker is trying to achieve -->

## Detection Logic

### Log Sources Required

| Source | Field | Notes |
|---|---|---|
| | | |

### Detection Rule

```yaml
# Sigma rule example
title: <Detection Title>
status: experimental
description: ""
logsource:
  category: ""
  product: ""
detection:
  selection:
    # key: value
  condition: selection
falsepositives:
  - ""
level: high
tags:
  - attack.<tactic>
  - attack.t<ID>
```

### KQL / SPL / YARA (if applicable)

```
<!-- KQL for Sentinel, SPL for Splunk, or YARA rule -->
```

## Investigation Playbook

### Triage Steps

1. <!-- First action when alert fires -->
2.
3.

### Key Indicators of Compromise

| Type | Indicator | Notes |
|---|---|---|
| File Hash | | |
| IP | | |
| Domain | | |
| Registry Key | | |
| Process Name | | |

### Timeline Reconstruction

```
YYYY-MM-DDTHH:MM:SSZ  [EVENT]  <description>
YYYY-MM-DDTHH:MM:SSZ  [EVENT]  <description>
```

## False Positive Analysis

<!-- Common benign scenarios that may trigger this detection and how to differentiate. -->

## Containment Actions

1. <!-- Immediate containment step -->
2.

## References

- [MITRE ATT&CK — T<ID>]()
- [Sigma Rules Repository]()

## Related

- Attack Chain: [[<chain-file-slug>]]
- Concept: [[concept-<slug>]]
- Finding: [[FIND-<CATEGORY>-<YYYYMMDD>-<NNN>]]
