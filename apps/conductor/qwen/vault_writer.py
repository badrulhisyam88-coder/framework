"""V2.7 — Knowledge Vault export: findings and lab walkthroughs.

Writes structured markdown files to the mounted knowledge vault at
KNOWLEDGE_VAULT_PATH (default /app/knowledge-vault).

All operations are non-blocking (called via asyncio.create_task).
Missing vault mount → silent skip (returns None). Never raises.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("conductor.qwen.vault_writer")

VAULT_PATH = Path(os.environ.get("KNOWLEDGE_VAULT_PATH", "/app/knowledge-vault"))

# Thread-safe sequence counter lock
_seq_lock = threading.Lock()

# ── Engine → tags mapping ─────────────────────────────────────────────────────

_ENGINE_TAGS: dict[str, list[str]] = {
    "credential_brute":   ["auth-bypass", "brute-force", "owasp-a07", "mitre-t1110"],
    "sqli_auth_bypass":   ["sqli", "auth-bypass", "owasp-a03", "mitre-t1190"],
    "access_control":     ["idor", "mass-assignment", "api", "owasp-a01", "mitre-t1078"],
    "xss_reflect":        ["xss", "reflected-xss", "owasp-a03", "mitre-t1059"],
    "cmdi_reflected":     ["cmdi", "rce", "owasp-a03", "mitre-t1059"],
    "cmdi_blind_time":    ["cmdi", "rce", "owasp-a03", "mitre-t1059"],
    "cmdi_blind_boolean": ["cmdi", "rce", "owasp-a03", "mitre-t1059"],
    "default_creds":      ["default-credentials", "auth-bypass", "owasp-a07", "mitre-t1078"],
    "metasploit_recipe":  ["metasploit", "rce", "owasp-a06", "mitre-t1210"],
    "ai_probe":           ["ai-probe", "mass-assignment", "api"],
}

_DEFAULT_TAGS = ["web", "recon"]

# ── Engine → human-readable title and CWE ────────────────────────────────────

_ENGINE_META: dict[str, dict[str, str]] = {
    "credential_brute":   {"title": "Credential Brute Force", "type": "Credential Brute Force", "cwe": "CWE-307"},
    "sqli_auth_bypass":   {"title": "SQL Injection Authentication Bypass", "type": "SQL Injection", "cwe": "CWE-89"},
    "access_control":     {"title": "Broken Access Control / IDOR", "type": "IDOR / Mass Assignment", "cwe": "CWE-284"},
    "xss_reflect":        {"title": "Reflected Cross-Site Scripting", "type": "Reflected XSS", "cwe": "CWE-79"},
    "cmdi_reflected":     {"title": "Command Injection (Reflected)", "type": "OS Command Injection", "cwe": "CWE-78"},
    "cmdi_blind_time":    {"title": "Command Injection (Blind, Time-Based)", "type": "OS Command Injection", "cwe": "CWE-78"},
    "cmdi_blind_boolean": {"title": "Command Injection (Blind, Boolean)", "type": "OS Command Injection", "cwe": "CWE-78"},
    "default_creds":      {"title": "Default Credentials", "type": "Default Credentials", "cwe": "CWE-1392"},
    "metasploit_recipe":  {"title": "Remote Code Execution via Known Exploit", "type": "RCE via CVE", "cwe": "CWE-1284"},
    "ai_probe":           {"title": "AI-Guided Probe Finding", "type": "API / Mass Assignment", "cwe": "CWE-284"},
}

_DEFAULT_META = {"title": "Web Vulnerability Finding", "type": "Web Vulnerability", "cwe": "N/A"}

# ── MITRE / OWASP per-engine ──────────────────────────────────────────────────

_ENGINE_MITRE: dict[str, list[dict[str, str]]] = {
    "credential_brute":   [{"tactic": "Credential Access", "technique": "Brute Force", "id": "T1110"}],
    "sqli_auth_bypass":   [{"tactic": "Initial Access", "technique": "Exploit Public-Facing Application", "id": "T1190"}],
    "access_control":     [{"tactic": "Privilege Escalation", "technique": "Valid Accounts", "id": "T1078"}],
    "xss_reflect":        [{"tactic": "Execution", "technique": "Command and Scripting Interpreter: JavaScript", "id": "T1059"}],
    "cmdi_reflected":     [{"tactic": "Execution", "technique": "Command and Scripting Interpreter", "id": "T1059"}],
    "cmdi_blind_time":    [{"tactic": "Execution", "technique": "Command and Scripting Interpreter", "id": "T1059"}],
    "cmdi_blind_boolean": [{"tactic": "Execution", "technique": "Command and Scripting Interpreter", "id": "T1059"}],
    "default_creds":      [{"tactic": "Credential Access", "technique": "Valid Accounts: Default Accounts", "id": "T1078"}],
    "metasploit_recipe":  [{"tactic": "Initial Access", "technique": "Exploit Public-Facing Application", "id": "T1210"}],
    "ai_probe":           [{"tactic": "Discovery", "technique": "Network Service Discovery", "id": "T1046"}],
}

_DEFAULT_MITRE = [{"tactic": "Initial Access", "technique": "Exploit Public-Facing Application", "id": "T1190"}]


_INJECTION_CHARS = re.compile(r"[$|'{\[]|\[\$")


def _finding_tags(engine_id: str, finding_type: str, artifact: dict | None = None) -> list[str]:
    """Return tags list for the given engine and finding type.

    For access_control: if the artifact's extended_payloads (or injected_fields)
    contain injection pattern characters ($, ||, ', [$, {$), replace the generic
    'idor' tag with 'injection' to correctly classify NoSQL/SQLi/SSPP probes.
    """
    tags = list(_ENGINE_TAGS.get(engine_id, _DEFAULT_TAGS))
    if engine_id == "access_control" and artifact:
        art = artifact.get("artifact", artifact) if isinstance(artifact.get("artifact"), dict) else artifact
        # Collect all payload values to scan for injection chars
        values_to_scan: list[str] = []
        for key in ("injected_fields", "extended_payloads", "payload", "body"):
            val = art.get(key)
            if isinstance(val, str):
                values_to_scan.append(val)
            elif isinstance(val, dict):
                values_to_scan.extend(str(v) for v in val.values())
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        values_to_scan.extend(str(v) for v in item.values())
                    elif isinstance(item, str):
                        values_to_scan.append(item)
        combined = " ".join(values_to_scan)
        if combined and _INJECTION_CHARS.search(combined):
            tags = ["injection" if t == "idor" else t for t in tags]
    return tags


def _next_finding_id(date_str: str) -> str:
    """Return the next FIND-WEB-{date_str}-NNN ID.

    Scans findings/web/ for existing files with the same date prefix and
    returns the next sequence number. Thread-safe via module-level lock.
    If vault not mounted, starts at 001.
    """
    with _seq_lock:
        findings_dir = VAULT_PATH / "findings" / "web"
        if not findings_dir.is_dir():
            return f"FIND-WEB-{date_str}-001"

        pattern = re.compile(rf"^FIND-WEB-{re.escape(date_str)}-(\d{{3}})_.*\.md$")
        highest = 0
        try:
            for fname in findings_dir.iterdir():
                m = pattern.match(fname.name)
                if m:
                    n = int(m.group(1))
                    if n > highest:
                        highest = n
        except Exception:
            pass
        return f"FIND-WEB-{date_str}-{highest + 1:03d}"


def _truncate_sensitive(value: Any, max_chars: int = 8) -> str:
    """Truncate a sensitive value showing first max_chars chars + '...'"""
    s = str(value)
    if len(s) > max_chars:
        return s[:max_chars] + "..."
    return s


async def export_finding(
    investigation_id: str,
    engine_id: str,
    finding_type: str,
    target_url: str,
    artifact: dict,
    branch_id: str,
) -> Path | None:
    """Export a finding to the knowledge vault.

    Returns the Path written, or None if vault not mounted or on any error.
    Non-blocking — should be called via asyncio.create_task().
    """
    try:
        return await _do_export_finding(
            investigation_id, engine_id, finding_type, target_url, artifact, branch_id
        )
    except Exception as exc:
        logger.warning("vault_writer.export_finding failed: %s", exc)
        return None


async def _do_export_finding(
    investigation_id: str,
    engine_id: str,
    finding_type: str,
    target_url: str,
    artifact: dict,
    branch_id: str,
) -> Path | None:
    if not VAULT_PATH.exists() or not VAULT_PATH.is_dir():
        logger.debug("vault_writer: vault not mounted at %s — skipping", VAULT_PATH)
        return None

    findings_dir = VAULT_PATH / "findings" / "web"
    findings_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y%m%d")
    date_iso = now.strftime("%Y-%m-%d")

    finding_id = _next_finding_id(date_str)
    slug = f"{engine_id}"
    filename = f"{finding_id}_{slug}.md"
    filepath = findings_dir / filename

    tags = _finding_tags(engine_id, finding_type, artifact=artifact)
    meta = dict(_ENGINE_META.get(engine_id, _DEFAULT_META))  # copy so we can mutate

    # For ai_probe branches, resolve the Qwen action reason from the finding title
    # stored in normalized_findings as "Qwen: <reason>" and use it as the vault title.
    try:
        from apps.validation.database import get_db as _get_db
        async with _get_db() as _db:
            _bc = await _db.execute(
                "SELECT finding_id FROM exploitation_branches WHERE branch_id=?",
                (branch_id,),
            )
            _brow = await _bc.fetchone()
            if _brow and str(_brow[0]).startswith("fnd_ai_"):
                _fc = await _db.execute(
                    "SELECT title FROM normalized_findings WHERE finding_id=?",
                    (_brow[0],),
                )
                _frow = await _fc.fetchone()
                if _frow and _frow[0]:
                    _raw = str(_frow[0])
                    # Strip "Qwen: " prefix; fall back to raw if not present
                    _reason = _raw[len("Qwen: "):] if _raw.startswith("Qwen: ") else _raw
                    if _reason:
                        meta["title"] = _reason
    except Exception:
        pass  # DB lookup is best-effort; fall back to generic engine title
    mitre_rows = _ENGINE_MITRE.get(engine_id, _DEFAULT_MITRE)

    # Extract artifact fields
    art = artifact or {}
    # If artifact is nested as {"artifact": {...}}, unwrap it
    if "artifact" in art and isinstance(art["artifact"], dict):
        art = art["artifact"]

    artifact_type = art.get("artifact_type", "unknown")
    endpoint = art.get("endpoint", art.get("url", art.get("login_url", target_url)))

    # Build PoC evidence from artifact
    poc_payload = art.get("payload", art.get("username", art.get("param", "— see artifact —")))
    poc_response = art.get("response_snippet", art.get("response", art.get("evidence", "")))

    # Truncate any sensitive credential fields
    sensitive_keys = ["password", "token", "cookie", "session", "auth"]
    redacted_art: dict[str, Any] = {}
    for k, v in art.items():
        if any(sk in k.lower() for sk in sensitive_keys):
            redacted_art[k] = _truncate_sensitive(v)
        else:
            redacted_art[k] = v

    # Build PoC response block
    if redacted_art:
        response_evidence = "\n".join(
            f"{k}: {v}" for k, v in list(redacted_art.items())[:8]
        )
    elif poc_response:
        response_evidence = str(poc_response)[:500]
    else:
        response_evidence = "— no response captured —"

    # MITRE table rows
    mitre_table_rows = "\n".join(
        f"| {r['tactic']} | {r['technique']} | {r['id']} |"
        for r in mitre_rows
    )

    # Tags YAML block
    tags_yaml = "\n".join(f"  - {t}" for t in tags)

    # Impact text
    impact = (
        f"Validation status: validated_exploitable. "
        f"Finding type '{finding_type}' confirmed. "
        f"Engine: {engine_id}. Branch: {branch_id}. "
        f"Artifact type: {artifact_type}. "
        f"Review evidence section for full exploitation context."
    )

    # Description
    description = (
        f"{meta['type']} vulnerability confirmed by {engine_id} engine. "
        f"The target endpoint {endpoint} is vulnerable. "
        f"Artifact type captured: {artifact_type}."
    )

    content = f"""---
type: finding
id: {finding_id}
title: {meta['title']}
date: "{date_iso}"
severity: high
category: web
source: ai-assist
platform: real-world
target: {target_url}
status: confirmed
tags:
{tags_yaml}
related_labs: []
related_concepts: []
related_findings: []
remediation_ref: ""
---

# {meta['title']}

## Summary

> {description}

## Environment

| Field | Value |
|---|---|
| Target | {target_url} |
| URL / Endpoint | {endpoint} |
| Parameter / Input | {poc_payload} |
| Date Tested | {date_iso} |
| Tester | ai-assist-tool |

## Vulnerability Details

**Type:** {meta['type']}
**CWE:** {meta['cwe']}
**CVSS Score:** N/A

### Description

{description}

## Proof of Concept

### Steps to Reproduce

1. Navigate to {endpoint}
2. Execute {engine_id} engine with target configuration
3. Observe exploitation result: {artifact_type}

### Payload / Request

```
{poc_payload}
```

### Response / Evidence

```
{response_evidence}
```

## Impact

{impact}

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
{mitre_table_rows}

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [{meta['cwe']}](https://cwe.mitre.org/)

## Related

- Concept: —
- Lab: —
- Remediation: —
- Related Finding: —
"""

    # Use asyncio to write without blocking event loop
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, filepath.write_text, content, "utf-8")

    # Auto-index into ChromaDB immediately — no restart required
    try:
        from apps.conductor.qwen.vault_embedder import embed_vault_entry
        indexed = await embed_vault_entry(finding_id, content)
        if not indexed:
            logger.warning(
                "vault_writer: embed_vault_entry skipped %s — "
                "no frontmatter type or ChromaDB unavailable",
                finding_id,
            )
    except Exception as _emb_exc:
        logger.debug(
            "vault_writer: embed_vault_entry failed for %s: %s", finding_id, _emb_exc
        )
        # embedding failure must never block the write path

    logger.info("vault_writer: exported finding %s → %s", finding_id, filepath)
    return filepath


# ── Failure export ────────────────────────────────────────────────────────────

def _next_failure_id(date_str: str) -> str:
    """Return the next FAIL-WEB-{date_str}-NNN ID. Thread-safe via module lock."""
    with _seq_lock:
        findings_dir = VAULT_PATH / "findings" / "web"
        if not findings_dir.is_dir():
            return f"FAIL-WEB-{date_str}-001"
        pattern = re.compile(rf"^FAIL-WEB-{re.escape(date_str)}-(\d{{3}})_.*\.md$")
        highest = 0
        try:
            for fname in findings_dir.iterdir():
                m = pattern.match(fname.name)
                if m:
                    n = int(m.group(1))
                    if n > highest:
                        highest = n
        except Exception:
            pass
        return f"FAIL-WEB-{date_str}-{highest + 1:03d}"


async def export_failure(
    investigation_id: str,
    engine_id: str,
    finding_type: str,
    target_url: str,
    exhaustion_record: dict,
    branch_id: str,
) -> "Path | None":
    """Export a failed/exhausted branch to the knowledge vault.

    Stored as FAIL-WEB-YYYYMMDD-NNN_<engine_id>.md so the AI sees
    "these payloads were tried and rejected — do not repeat them."
    Returns the Path written, or None if vault not mounted or on error.
    Non-blocking — should be called via asyncio.create_task().
    Never raises.
    """
    try:
        return await _do_export_failure(
            investigation_id, engine_id, finding_type, target_url,
            exhaustion_record, branch_id,
        )
    except Exception as exc:
        logger.warning("vault_writer.export_failure failed: %s", exc)
        return None


async def _do_export_failure(
    investigation_id: str,
    engine_id: str,
    finding_type: str,
    target_url: str,
    exhaustion_record: dict,
    branch_id: str,
) -> "Path | None":
    if not VAULT_PATH.exists() or not VAULT_PATH.is_dir():
        return None

    findings_dir = VAULT_PATH / "findings" / "web"
    findings_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y%m%d")
    date_iso = now.strftime("%Y-%m-%d")

    failure_id = _next_failure_id(date_str)
    filepath = findings_dir / f"{failure_id}_{engine_id}.md"

    tags = _ENGINE_TAGS.get(engine_id, _DEFAULT_TAGS)
    tags_yaml = "\n".join(f"  - {t}" for t in tags)

    payloads_tried = exhaustion_record.get("payloads_tried", [])
    payloads_count = len(payloads_tried)
    reason = exhaustion_record.get("reason", "")
    if not reason and payloads_tried:
        reason = payloads_tried[0].get("result", "unknown")
    detection_method = exhaustion_record.get("detection_method", "unknown")

    payloads_block = ""
    for p in payloads_tried[:5]:
        endpoint = p.get("endpoint") or p.get("payload", "?")
        result = p.get("result", "?")
        body = p.get("body", "")
        payloads_block += f"- `{endpoint}` → {result}"
        if body:
            payloads_block += f" (body: {str(body)[:80]})"
        payloads_block += "\n"
    if not payloads_block:
        payloads_block = "- No payloads recorded\n"

    content = f"""---
type: finding
id: {failure_id}
title: "FAILED: {engine_id} on {finding_type}"
date: "{date_iso}"
severity: info
category: web
source: ai-assist
platform: real-world
target: {target_url}
status: failed
outcome: exhausted
tags:
  - failed
  - {engine_id}
{tags_yaml}
payloads_tried: {payloads_count}
failure_reason: "{reason}"
detection_method: "{detection_method}"
---

# FAILED: {engine_id}

## Summary

> Engine `{engine_id}` exhausted on `{target_url}` — {payloads_count} payload(s) tried,
> all rejected. Do not retry these payloads. Use alternative techniques.

## What Was Tried

{payloads_block}
## Why It Failed

**Reason:** {reason or "payloads rejected by server"}
**Detection method:** {detection_method}
**Branch:** {branch_id}

## Do Not Retry

These payloads were rejected on `{target_url}`. Suggest alternative:
- Different endpoint (try `/user/lookup`, `/api/user`, GET instead of POST)
- Different payload format (NoSQL operators, URL-encoded vs JSON)
- Authenticated retry if session was captured
"""

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, filepath.write_text, content, "utf-8")

    try:
        from apps.conductor.qwen.vault_embedder import embed_vault_entry
        indexed = await embed_vault_entry(failure_id, content)
        if not indexed:
            logger.warning(
                "vault_writer: embed_vault_entry skipped %s — "
                "no frontmatter type or ChromaDB unavailable",
                failure_id,
            )
    except Exception as _emb_exc:
        logger.debug(
            "vault_writer: embed_vault_entry failed for %s: %s", failure_id, _emb_exc
        )
        # embedding failure must never block the write path

    logger.info("vault_writer: exported failure %s → %s", failure_id, filepath)
    return filepath


async def export_lab_walkthrough(
    investigation_id: str,
    target_url: str,
    findings: list[dict],
    succeeded_branches: list[dict],
) -> Path | None:
    """Export a lab walkthrough to the knowledge vault.

    Returns the Path written, or None if vault not mounted or on any error.
    Non-blocking — should be called via asyncio.create_task().
    """
    try:
        return await _do_export_lab_walkthrough(
            investigation_id, target_url, findings, succeeded_branches
        )
    except Exception as exc:
        logger.warning("vault_writer.export_lab_walkthrough failed: %s", exc)
        return None


async def _do_export_lab_walkthrough(
    investigation_id: str,
    target_url: str,
    findings: list[dict],
    succeeded_branches: list[dict],
) -> Path | None:
    if not VAULT_PATH.exists() or not VAULT_PATH.is_dir():
        logger.debug("vault_writer: vault not mounted — skipping lab walkthrough")
        return None

    labs_dir = VAULT_PATH / "labs"
    labs_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y%m%d")
    date_iso = now.strftime("%Y-%m-%d")

    # Build slug from investigation_id (short)
    inv_slug = investigation_id[:8] if investigation_id else "unknown"
    filename = f"{date_str}_portswigger_{inv_slug}.md"
    filepath = labs_dir / filename

    # Collect tags from succeeded engines
    all_tags: list[str] = ["portswigger", "linux", "web"]
    engine_ids: list[str] = []
    for b in succeeded_branches:
        eid = b.get("engine_id", "")
        if eid:
            engine_ids.append(eid)
            for t in _ENGINE_TAGS.get(eid, []):
                if t not in all_tags:
                    all_tags.append(t)

    tags_yaml = "\n".join(f"  - {t}" for t in all_tags)

    # Build findings section
    findings_lines: list[str] = []
    for f in findings[:20]:
        ft = f.get("finding_type", "")
        title = f.get("title", "")
        severity = f.get("severity", "")
        endpoint = f.get("endpoint", "")
        findings_lines.append(f"- **{ft}**: {title} (severity={severity}, endpoint={endpoint})")
    findings_text = "\n".join(findings_lines) if findings_lines else "— no findings recorded —"

    # Build exploitation steps
    exploit_steps: list[str] = []
    for i, b in enumerate(succeeded_branches, 1):
        eid = b.get("engine_id", "")
        art = b.get("artifact") or {}
        if "artifact" in art and isinstance(art["artifact"], dict):
            art = art["artifact"]
        atype = art.get("artifact_type", "unknown")
        endpoint = art.get("endpoint", art.get("url", ""))
        exploit_steps.append(
            f"{i}. Execute `{eid}` engine against `{endpoint or target_url}` — result: `{atype}`"
        )
    exploit_text = "\n".join(exploit_steps) if exploit_steps else "— no engines succeeded —"

    # Finding references for Related section
    related_findings = " ".join(
        f"[[FIND-WEB-{date_str}-{i+1:03d}_{b.get('engine_id', 'unknown')}]]"
        for i, b in enumerate(succeeded_branches)
    )

    lab_id = f"LAB-PORTSWIGGER-{inv_slug.upper()}-{date_str}"

    content = f"""---
type: lab-walkthrough
id: {lab_id}
title: PortSwigger — Investigation {inv_slug}
date: {date_iso}
platform: portswigger
difficulty: medium
os: linux
status: completed
completion_time: ""
tags:
{tags_yaml}
related_findings: []
related_concepts: []
flags:
  user: ""
  root: ""
challenge_id: portswigger_{inv_slug}
category: web
---

# PortSwigger — Investigation {inv_slug}

## Overview

| Field | Value |
|---|---|
| Platform | portswigger |
| Challenge | Investigation {inv_slug} |
| Difficulty | medium |
| OS | Linux |
| Port | 80 / 443 |
| Date | {date_iso} |
| Category | web |
| Estimated Time | — |

## Objectives

- Exploit web vulnerabilities discovered during automated investigation
- Confirm exploitation via ai-assist-tool engine execution
- Capture artifacts: credentials, session cookies, command output

## Enumeration

### Target Discovery

```bash
# Target: {target_url}
```

### Service Enumeration

- Target: {target_url}
- Investigation ID: {investigation_id}

## Findings Discovered

{findings_text}

## Exploitation

### Goals

- Confirm exploitability of discovered findings
- Capture exploitation artifacts via V2 engines

### Steps

{exploit_text}

### Key Payload

```
# See individual finding references for specific payload details
```

## Flags

| Flag | Value |
|---|---|
| Flag | *Not recorded* |

## Lessons Learned

Complete the lessons learned section after reviewing the investigation artifacts.

## Learning Objectives Review

- Confirm how ai-assist-tool V2 engines map to real exploitation techniques
- Review artifact capture for each succeeded branch
- Cross-reference with knowledge vault findings

## Blue Team Perspective

### Detection Signals

- Unusual authentication patterns or repeated failed login attempts
- Unexpected SQL keywords or special characters in login parameters
- Command injection strings in HTTP parameters
- Sudden successful authentication after repeated failures from the same IP

### Mitigation

- Parameterized queries and prepared statements for database interactions
- Input validation and output encoding for XSS prevention
- Principle of least privilege for all application accounts
- Web Application Firewall rules for common injection patterns
- Account lockout policies to prevent brute force attacks

## MITRE ATT&CK

| Technique ID | Name |
|---|---|
| T1190 | Exploit Public-Facing Application |

## OWASP References

- A01:2021 — Broken Access Control
- A03:2021 — Injection
- A07:2021 — Identification and Authentication Failures

## Related

{related_findings}
- Finding: <!-- Link FIND-* IDs after exporting findings -->
- Remediation: <!-- Link REM-* IDs after exporting remediation -->
"""

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, filepath.write_text, content, "utf-8")

    logger.info("vault_writer: exported lab walkthrough → %s", filepath)
    return filepath
