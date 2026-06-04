# Vault Structure

Conventions governing where files live and how folders are organized.

---

## Folder Definitions

### `findings/`
Discrete vulnerability findings from CTFs, labs, bug bounty, or assessments.

Subfolders map to OWASP/attack surface categories:

| Folder | Scope |
|---|---|
| `findings/web/` | XSS, SQLi, CSRF, SSRF, auth bypass, file upload, path traversal |
| `findings/api/` | REST/GraphQL issues, broken object-level auth, mass assignment, JWT flaws |
| `findings/network/` | SMB relay, LLMNR poisoning, port scan findings, firewall misconfig |
| `findings/cloud/` | IAM misconfig, S3 exposure, metadata SSRF, privilege escalation in AWS/GCP/Azure |

A finding file represents a **single exploitable condition** in a specific target context.

---

### `labs/`
Step-by-step walkthroughs of lab environments.

File naming: `YYYYMMDD_<platform>_<challenge-slug>.md`

Platforms: `htb` (HackTheBox), `thm` (TryHackMe), `pg` (Proving Grounds), `ctf`, `local`

---

### `learning-paths/`
Curated roadmaps tracking progress through a skill domain.

Each file describes a learning objective, required resources, and completion status.

---

### `blue-team/`
Defensive analysis notes: detection rules, SOC triage notes, DFIR timelines, threat hunting queries.

Subfolders (ad hoc, create as needed):
- `blue-team/detection/`
- `blue-team/dfir/`
- `blue-team/threat-intel/`

---

### `remediation/`
Remediation playbooks and fix references, keyed to finding categories.

Each file addresses a class of vulnerability (e.g., `remediation-sqli.md`) with:
- Root cause
- Short-term fix
- Long-term fix
- Verification steps
- CVSS/OWASP references

---

### `attack-chains/`
Multi-stage attack narratives combining multiple findings into an end-to-end scenario.

These link to individual findings files and describe lateral movement, privilege escalation, or full kill-chain coverage.

---

### `concepts/`
Atomic reference notes for security concepts, protocols, tools, and techniques.

One concept per file. Not tied to any specific lab or target.

Examples: `concept-jwt-attacks.md`, `concept-kerberoasting.md`, `concept-xxe.md`

---

### `journals/`
Time-stamped practice and study logs.

File naming: `YYYYMMDD_journal.md`

Use for: what was studied, what worked, what was confusing, next steps.

---

### `reports/`
Formatted deliverables: pentest reports, assessment summaries, lab completion certificates.

File naming: `YYYYMMDD_report_<scope-slug>.md`

---

### `templates/`
Canonical templates. **Do not modify templates directly when writing content — copy first.**

| Template | Purpose |
|---|---|
| `template-finding.md` | Vulnerability finding |
| `template-lab-walkthrough.md` | Lab/CTF walkthrough |
| `template-remediation.md` | Remediation playbook |
| `template-blue-team.md` | Blue team / SOC analysis note |
| `template-attack-chain.md` | Multi-stage attack chain |
| `template-journal.md` | Daily learning journal |
| `template-concept.md` | Reference concept note |
| `template-report.md` | Formatted report |

---

### `exports/`
Timestamped flat-file exports for sharing, submission, or archival.

See `EXPORT_STANDARDS.md` for naming rules.

---

## File Placement Rules

1. **One concept, one file.** Do not combine unrelated findings in a single file.
2. **Findings belong in `findings/<category>/`** — not in `labs/` or `concepts/`.
3. **Labs belong in `labs/`** — lab walkthroughs are not findings; cross-link to findings where they overlap.
4. **Templates stay in `templates/`** — content files go in their respective folders.
5. **Exports are read-only copies** — do not edit files in `exports/`; re-export if changes are needed.

---

## Frontmatter Enforcement

Every content file **must** have valid YAML frontmatter as defined in the relevant template.

Required fields for all types: `type`, `title`, `date`, `tags`

Enforcement is manual (no runtime validators by design). When reviewing files, check that frontmatter is present and complete.
