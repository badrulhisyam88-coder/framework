---
type: remediation
id: REM-NET-20260518-001
title: "Remediation: SSH Default / Weak Credential"
date: "2026-05-18"
category: network
severity: critical
status: draft
tags:
  - remediation
  - ssh-cred
  - owasp-a07
  - network
related_findings:
  - FIND-NET-20260518-001
related_concepts: []
---

# Remediation: SSH Default / Weak Credential

## Summary

> SSH service accessible with default or weak credentials allows unauthorised remote login.

## Root Cause

Default credentials were not changed post-deployment, or a weak password policy allows brute-force access.

## Affected Components

- SSH daemon (sshd)
- System accounts

## Short-Term Fix

> Apply immediately to reduce exploitability.

Immediately change the exposed credentials and restrict SSH access by IP.

```
# /etc/ssh/sshd_config
AllowUsers deploy@10.0.0.0/8
PasswordAuthentication no
PermitRootLogin no
```

## Long-Term Fix

> Permanent remediation via code or architecture change.

### Developer Guidance

Enforce key-based authentication, disable password login, use a bastion host, and implement a secrets rotation policy.

### Recommended Libraries / Functions

| Language | Recommended Approach |
|---|---|
| Linux | Disable PasswordAuthentication in sshd_config; use ssh-keygen + authorized_keys |
| Ansible/Terraform | Provision SSH keys at build time; never bake credentials into images |
| Kubernetes | Use SSH secrets manager (Vault, AWS Secrets Manager) with rotation |

## Verification Steps

1. Attempt login with the original credential — it should fail
2. Confirm PasswordAuthentication is disabled in sshd_config
3. Run nmap -sV -p22 --script ssh-auth-methods <target> — expect publickey only

```bash
ssh -o PasswordAuthentication=yes user@target 2>&1 | grep 'Permission denied'
```

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

## Related

- Concept: [[concept-ssh-cred]]
- Findings:
- [[internal-ssh-001]]
