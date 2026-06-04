# Export Standards

Deterministic naming conventions, ID formats, and export rules for the knowledge vault.

---

## ID Formats

### Finding ID

```
FIND-<CATEGORY>-<YYYYMMDD>-<NNN>
```

| Segment | Description |
|---|---|
| `FIND` | Constant prefix |
| `<CATEGORY>` | `WEB`, `API`, `NET`, `CLOUD` |
| `<YYYYMMDD>` | Date the finding was documented |
| `<NNN>` | Three-digit sequence number, reset per day per category |

Examples:
- `FIND-WEB-20260518-001`
- `FIND-API-20260518-002`
- `FIND-NET-20260601-001`

---

### Challenge / Lab ID

```
LAB-<PLATFORM>-<CHALLENGE-SLUG>
```

| Segment | Description |
|---|---|
| `LAB` | Constant prefix |
| `<PLATFORM>` | `HTB`, `THM`, `PG`, `CTF`, `LOCAL` |
| `<CHALLENGE-SLUG>` | Kebab-case challenge name |

Examples:
- `LAB-HTB-LAME`
- `LAB-THM-ADVENT-OF-CYBER-2024`
- `LAB-CTF-PICOCTF-2025-BINARY-01`

---

### Remediation ID

```
REM-<CATEGORY>-<YYYYMMDD>-<NNN>
```

Examples:
- `REM-WEB-20260518-001`

---

### Report ID

```
RPT-<SCOPE-SLUG>-<YYYYMMDD>
```

Examples:
- `RPT-INTERNAL-PENTEST-20260518`

---

## File Naming Conventions

### Findings

```
FIND-<CATEGORY>-<YYYYMMDD>-<NNN>_<short-title>.md
```

Examples:
- `FIND-WEB-20260518-001_sqli-login-bypass.md`
- `FIND-API-20260518-001_broken-object-level-auth.md`
- `FIND-NET-20260518-001_smb-relay-internal.md`

---

### Lab Walkthroughs

```
YYYYMMDD_<platform>_<challenge-slug>.md
```

Examples:
- `20260518_htb_lame.md`
- `20260518_thm_advent-of-cyber-2024.md`
- `20260518_ctf_picoctf-2025-binary-01.md`

---

### Concepts

```
concept-<slug>.md
```

Examples:
- `concept-sqli.md`
- `concept-kerberoasting.md`
- `concept-jwt-attacks.md`

---

### Remediation Playbooks

```
remediation-<category>-<slug>.md
```

Examples:
- `remediation-web-sqli.md`
- `remediation-cloud-s3-public-exposure.md`

---

### Journals

```
YYYYMMDD_journal.md
```

Example:
- `20260518_journal.md`

---

### Reports

```
YYYYMMDD_report_<scope-slug>.md
```

Example:
- `20260518_report_internal-pentest.md`

---

### Attack Chains

```
YYYYMMDD_chain_<slug>.md
```

Example:
- `20260518_chain_web-to-domain-admin.md`

---

### Blue Team Notes

```
YYYYMMDD_blue_<slug>.md
```

Example:
- `20260518_blue_sqli-detection-sigma.md`

---

## Timestamp Format

All timestamps follow **ISO 8601**:

- Date only: `YYYY-MM-DD` in frontmatter `date` fields
- Date in filenames: `YYYYMMDD` (no hyphens)
- Datetime: `YYYY-MM-DDTHH:MM:SSZ` when full precision is needed (e.g., incident timelines)

---

## Tag Taxonomy

Tags must be lowercase, hyphenated, and drawn from recognized namespaces:

### Vulnerability Class
`sqli`, `xss`, `ssrf`, `xxe`, `idor`, `csrf`, `rce`, `lfi`, `rfi`, `ssti`, `open-redirect`, `jwt-attack`, `path-traversal`

### OWASP Top 10 (2021)
`owasp-a01` through `owasp-a10`

| Code | Category |
|---|---|
| `owasp-a01` | Broken Access Control |
| `owasp-a02` | Cryptographic Failures |
| `owasp-a03` | Injection |
| `owasp-a04` | Insecure Design |
| `owasp-a05` | Security Misconfiguration |
| `owasp-a06` | Vulnerable and Outdated Components |
| `owasp-a07` | Identification and Authentication Failures |
| `owasp-a08` | Software and Data Integrity Failures |
| `owasp-a09` | Security Logging and Monitoring Failures |
| `owasp-a10` | Server-Side Request Forgery |

### MITRE ATT&CK
`mitre-t<TECHNIQUE-ID>` — use the full numeric ID

Examples: `mitre-t1190`, `mitre-t1059`, `mitre-t1078`

### Severity
`critical`, `high`, `medium`, `low`, `info`

### Platform
`htb`, `thm`, `pg`, `ctf`, `bugbounty`, `lab`, `real-world`

### Technology
`linux`, `windows`, `active-directory`, `aws`, `azure`, `gcp`, `docker`, `kubernetes`

---

## Export Bundles

When exporting a set of files for sharing (e.g., NotebookLM upload, AI Assist context):

### Naming

```
export_<scope>_<YYYYMMDD>.zip
```

Example:
- `export_web-findings_20260518.zip`
- `export_full-vault_20260518.zip`

### Contents

Export bundles are flat copies — no symlinks, no directories inside unless required.

Include a `MANIFEST.md` at the bundle root listing:
- Date of export
- Files included
- Finding IDs or lab IDs covered

### Export Process (Manual)

```bash
# Example: export all web findings
zip -j exports/export_web-findings_$(date +%Y%m%d).zip findings/web/*.md

# Example: full vault export
zip -r exports/export_full-vault_$(date +%Y%m%d).zip . \
  --exclude "exports/*" \
  --exclude ".obsidian/*" \
  --exclude ".git/*"
```

---

## Cross-Linking Conventions

Use **relative paths** for links between files (portable across tools):

```markdown
- Related concept: [SQL Injection](../concepts/concept-sqli.md)
- Related lab: [HTB Lame Walkthrough](../labs/20260518_htb_lame.md)
- Remediation: [SQLi Remediation](../remediation/remediation-web-sqli.md)
- Related finding: [Login Bypass](../findings/web/FIND-WEB-20260518-001_sqli-login-bypass.md)
```

Obsidian wikilink format is also acceptable for Obsidian-first workflows:

```markdown
[[concept-sqli]]
[[20260518_htb_lame]]
[[remediation-web-sqli]]
```

Both formats may coexist — relative paths are canonical for portability.
