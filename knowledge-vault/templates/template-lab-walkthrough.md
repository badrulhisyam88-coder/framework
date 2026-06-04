---
type: lab-walkthrough
id: LAB-<PLATFORM>-<CHALLENGE-SLUG>
title: "<Platform> — <Challenge Name>"
date: YYYY-MM-DD
platform: htb | thm | pg | ctf | local
difficulty: easy | medium | hard | insane
os: linux | windows | other
status: in-progress | completed | incomplete
completion_time: ""   # e.g. "2h 30m"
tags:
  - <platform>
  - <os>
  - <difficulty>
  - <primary-technique>  # e.g. sqli, privesc-suid, kerberoasting
related_findings: []
related_concepts: []
flags:
  user: ""
  root: ""
---

# <Platform> — <Challenge Name>

## Overview

| Field | Value |
|---|---|
| Platform | |
| Challenge | |
| Difficulty | |
| OS | |
| IP / URL | |
| Date | |

## Objectives

<!-- What is the goal? Get user flag, root flag, specific data, etc. -->

## Enumeration

### Host Discovery

```bash
# nmap or other initial scan
```

### Port Scan

```bash
nmap -sC -sV -oN nmap/<challenge>.txt <IP>
```

```
<!-- Paste relevant nmap output -->
```

### Service Enumeration

<!-- Enumerate interesting services: HTTP, SMB, LDAP, FTP, etc. -->

#### Web Enumeration

```bash
# gobuster / feroxbuster / ffuf
```

## Exploitation

### Initial Foothold

<!-- Describe the initial access vector. Link to finding if it's a discrete vulnerability. -->

**Finding reference:** [[FIND-<CATEGORY>-<YYYYMMDD>-<NNN>_<slug>]]

```
<!-- Key payload or command -->
```

### Privilege Escalation

<!-- Describe the privesc path. -->

```bash
# Key commands
```

## Flags

| Flag | Value |
|---|---|
| User | `<hash>` |
| Root | `<hash>` |

## Lessons Learned

<!-- What new techniques, tools, or concepts did this lab reinforce or introduce? -->

## Related

- Concept: [[concept-<slug>]]
- Finding: [[FIND-<CATEGORY>-<YYYYMMDD>-<NNN>]]
- Remediation: [[remediation-<category>-<slug>]]
