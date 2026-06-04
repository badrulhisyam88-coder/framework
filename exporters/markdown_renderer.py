"""Markdown document renderers for each vault content type.

Each renderer takes a frontmatter dict and a content dict, and returns a
complete markdown string ready to write to disk. The output structure follows
the vault templates exactly — section headings match template-*.md files in
knowledge-vault/templates/.
"""

from __future__ import annotations

from typing import Any

from exporters.frontmatter_builder import dump_frontmatter


def render_finding(
    frontmatter: dict[str, Any],
    target: str,
    url_or_endpoint: str,
    parameter: str,
    date_tested: str,
    tester: str,
    vuln_type: str,
    cwe: str,
    cvss_score: str,
    description: str,
    steps_to_reproduce: list[str],
    payload: str,
    response: str,
    impact: str,
    mitre_rows: list[tuple[str, str, str]],
    references: list[str],
    related_concept: str,
    related_lab: str,
    related_remediation: str,
    related_finding: str,
) -> str:
    """Render a complete finding markdown document."""
    fm = dump_frontmatter(frontmatter)
    title = frontmatter.get("title", "Finding")

    steps_md = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(steps_to_reproduce))

    mitre_rows_md = "\n".join(
        f"| {tactic} | {technique} | {tid} |" for tactic, technique, tid in mitre_rows
    ) or "| — | — | — |"

    refs_md = "\n".join(f"- {ref}" for ref in references) if references else "- See OWASP Top 10"

    return f"""{fm}

# {title}

## Summary

> {description}

## Environment

| Field | Value |
|---|---|
| Target | {target} |
| URL / Endpoint | {url_or_endpoint} |
| Parameter / Input | {parameter} |
| Date Tested | {date_tested} |
| Tester | {tester} |

## Vulnerability Details

**Type:** {vuln_type}
**CWE:** {cwe}
**CVSS Score:** {cvss_score}

### Description

{description}

## Proof of Concept

### Steps to Reproduce

{steps_md}

### Payload / Request

```
{payload}
```

### Response / Evidence

```
{response}
```

## Impact

{impact}

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
{mitre_rows_md}

## References

{refs_md}

## Related

- Concept: {related_concept}
- Lab: {related_lab}
- Remediation: {related_remediation}
- Related Finding: {related_finding}
"""


def render_service_discovery(
    frontmatter: dict[str, Any],
    scope: str,
    date: str,
    host_rows: list[dict[str, Any]],
    service_rows: list[dict[str, Any]],
    notes: str,
) -> str:
    """Render a service discovery summary markdown document."""
    fm = dump_frontmatter(frontmatter)
    title = frontmatter.get("title", "Service Discovery Summary")

    hosts_md_rows = "\n".join(
        f"| {h.get('ip', '')} | {h.get('hostname', '')} |"
        f" {h.get('os_guess', '')} | {h.get('status', '')} |"
        for h in host_rows
    ) or "| — | — | — | — |"

    svc_md_rows = "\n".join(
        f"| {s.get('ip', '')} | {s.get('port', '')} | {s.get('protocol', '')} |"
        f" {s.get('service_name', '')} | {s.get('product', '')} | {s.get('version', '')} |"
        for s in service_rows
    ) or "| — | — | — | — | — | — |"

    return f"""{fm}

# {title}

## Overview

| Field | Value |
|---|---|
| Scope | {scope} |
| Date | {date} |
| Hosts Found | {len(host_rows)} |
| Services Found | {len(service_rows)} |

## Hosts

| IP | Hostname | OS Guess | Status |
|---|---|---|---|
{hosts_md_rows}

## Services

| IP | Port | Protocol | Service | Product | Version |
|---|---|---|---|---|---|
{svc_md_rows}

## Notes

{notes or "No additional notes."}

## Related Findings

<!-- Link individual findings discovered from this scan here -->
"""


def render_remediation(
    frontmatter: dict[str, Any],
    summary: str,
    root_cause: str,
    affected_components: list[str],
    short_term_fix: str,
    short_term_code: str,
    long_term_guidance: str,
    lang_table: list[tuple[str, str]],
    verification_steps: list[str],
    verification_cmd: str,
    references: list[str],
    related_concept: str,
    related_findings: list[str],
) -> str:
    """Render a remediation playbook markdown document."""
    fm = dump_frontmatter(frontmatter)
    title = frontmatter.get("title", "Remediation")

    affected_md = "\n".join(f"- {c}" for c in affected_components) or "- See description"
    lang_rows_md = (
        "\n".join(f"| {lang} | {approach} |" for lang, approach in lang_table)
        or "| — | — |"
    )
    verification_md = "\n".join(f"{i + 1}. {s}" for i, s in enumerate(verification_steps))
    refs_md = "\n".join(f"- {r}" for r in references) if references else "- See OWASP Top 10"
    related_findings_md = (
        "\n".join(f"- {f}" for f in related_findings) if related_findings else "- None"
    )

    return f"""{fm}

# {title}

## Summary

> {summary}

## Root Cause

{root_cause}

## Affected Components

{affected_md}

## Short-Term Fix

> Apply immediately to reduce exploitability.

{short_term_fix}

```
{short_term_code}
```

## Long-Term Fix

> Permanent remediation via code or architecture change.

### Developer Guidance

{long_term_guidance}

### Recommended Libraries / Functions

| Language | Recommended Approach |
|---|---|
{lang_rows_md}

## Verification Steps

{verification_md}

```bash
{verification_cmd}
```

## References

{refs_md}

## Related

- Concept: {related_concept}
- Findings:
{related_findings_md}
"""


def render_attack_chain(
    frontmatter: dict[str, Any],
    overview: str,
    target: str,
    scope: str,
    date: str,
    phases: list[dict[str, Any]],
    mitre_summary: list[tuple[str, str, str, str]],
    detection_opportunities: list[tuple[str, str, str]],
    related_findings: list[str],
    related_lab: str,
    related_blue_team: str,
) -> str:
    """Render an attack chain markdown document."""
    fm = dump_frontmatter(frontmatter)
    title = frontmatter.get("title", "Attack Chain")

    phases_md = ""
    for i, phase in enumerate(phases, start=1):
        cmd_block = f"```bash\n{phase.get('commands', '# commands')}\n```"
        phases_md += f"""
## Phase {i}: {phase.get('name', 'Phase')}

**Technique:** {phase.get('technique', '')}
**MITRE ID:** {phase.get('mitre_id', '')}

### Description

{phase.get('description', '')}

{cmd_block}

---
"""

    mitre_md = "\n".join(
        f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} |" for row in mitre_summary
    ) or "| — | — | — | — |"

    detection_md = "\n".join(
        f"| {row[0]} | {row[1]} | {row[2]} |" for row in detection_opportunities
    ) or "| — | — | — |"

    related_findings_md = (
        "\n".join(f"- {f}" for f in related_findings) if related_findings else "- None"
    )

    return f"""{fm}

# {title}

## Overview

> {overview}

## Environment

| Field | Value |
|---|---|
| Target | {target} |
| Scope | {scope} |
| Date | {date} |
| Source | real-world |

## Kill Chain

```
[Initial Access] → [Execution] → [Persistence] → [Privilege Escalation] → [Impact]
```

---
{phases_md}

## MITRE ATT&CK Summary

| Phase | Tactic | Technique | ID |
|---|---|---|---|
{mitre_md}

## Detection Opportunities

| Phase | Detection Point | Log Source |
|---|---|---|
{detection_md}

## Related

- Findings:
{related_findings_md}
- Lab: {related_lab}
- Blue Team: {related_blue_team}
"""
