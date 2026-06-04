"""Nuclei result normalizer — converts nuclei JSON output to NormalizedFinding list."""

from __future__ import annotations

from typing import Any

from apps.scanner_orchestration.execution.models import ScanExecution
from apps.scanner_orchestration.normalization.finding_type_map import (
    normalize_finding_type,
    normalize_severity,
)
from apps.scanner_orchestration.normalization.models import NormalizedFinding


def normalize_nuclei_results(
    raw_result: dict[str, Any],
    scan: ScanExecution,
) -> list[NormalizedFinding]:
    """Convert nuclei JSON results to NormalizedFinding list.

    CVE-linked templates (those with CVE IDs in info.reference) are classified
    as finding_type='cve_matched' unless a specific vulnerability class (sqli,
    xss, etc.) can be determined from the template tags.  The original scanner
    severity is stored in raw_data so it survives the CVSS upgrade step.
    """
    findings: list[NormalizedFinding] = []
    results: list[dict] = raw_result.get("results", [])

    for result in results:
        template_id = result.get("template-id", "")
        info: dict = result.get("info", {})

        name = info.get("name", template_id)
        severity_raw = info.get("severity", "info")
        description = info.get("description", "")
        tags_raw: list[str] = info.get("tags", [])
        references: list[str] = info.get("reference", [])
        # Extract CVE IDs from references (e.g. "CVE-2024-1234")
        cves: list[str] = [
            r.strip() for r in references
            if r.upper().strip().startswith("CVE-") and len(r.strip()) >= 12
        ]
        cwes: list[str] = info.get("cwe", [])

        matcher_name = result.get("matcher-name", "")
        matched_at = result.get("matched-at", scan.target)
        extracted_results: list[str] = result.get("extracted-results", [])

        sev = normalize_severity(severity_raw)
        ft = _nuclei_template_to_finding_type(template_id, tags_raw, name, bool(cves))

        endpoint = _extract_endpoint(matched_at)

        desc_parts = [description]
        if matcher_name:
            desc_parts.append(f"Matched: {matcher_name}")
        if extracted_results:
            desc_parts.append(f"Extracted: {', '.join(extracted_results[:3])}")
        if cves:
            desc_parts.append(f"CVEs: {', '.join(cves[:3])}")
        elif references:
            desc_parts.append(f"References: {', '.join(references[:2])}")

        tags = ["nuclei", template_id] + [t for t in tags_raw if t]

        # Store the original scanner severity so cve_enricher can record it.
        raw_with_meta = dict(result)
        raw_with_meta["_scanner_severity"] = sev
        raw_with_meta["_template_id"] = template_id

        findings.append(NormalizedFinding(
            scan_id=scan.scan_id,
            investigation_id=scan.investigation_id,
            source_scanner="nuclei",
            finding_type=ft,
            severity=sev,
            title=name,
            description="\n\n".join(p for p in desc_parts if p)[:1000],
            target=scan.target,
            endpoint=endpoint,
            related_cves=[c for c in cves if c],
            related_cwes=[c for c in cwes if c],
            raw_data=raw_with_meta,
            tags=tags,
        ))

    return findings


# ── Finding type derivation ────────────────────────────────────────────────

# Vulnerability classes that take priority over generic "cve" classification.
_SPECIFIC_TAGS: list[str] = [
    "sqli", "sql-injection", "sql_injection",
    "xss", "cross-site-scripting",
    "default-login", "default-credentials", "default-logins",
    "auth-bypass", "authentication-bypass", "broken-auth",
    "ssrf",
    "xxe",
    "command-injection", "rce", "remote-code-execution",
    "lfi", "path-traversal", "local-file-inclusion",
    "csrf",
]

# Tags that indicate informational / non-vulnerability findings.
_INFO_TAGS: list[str] = [
    "misconfig", "misconfiguration",
    "ssl", "tls",
    "info-disclosure", "information-disclosure",
    "tech", "technology",
    "exposed-panel", "panel",
]


def _nuclei_template_to_finding_type(
    template_id: str,
    tags: list[str],
    name: str,
    has_cves: bool,
) -> str:
    """Derive canonical finding_type from nuclei template metadata.

    Priority order:
    1. Specific vulnerability class from tags (sqli, xss, etc.)
    2. CVE-linked template → "cve_matched"
    3. Informational / misconfiguration tags
    4. Fallback: slugify the template name
    """
    tags_lower = {t.lower() for t in tags}

    # 1. Specific vulnerability class wins over generic CVE classification.
    for tag in _SPECIFIC_TAGS:
        if tag in tags_lower:
            return normalize_finding_type(tag)

    # 2. CVE template (has extracted CVE IDs, or tagged "cve").
    if has_cves or "cve" in tags_lower:
        return "cve_matched"

    # 3. Informational / misconfiguration.
    for tag in _INFO_TAGS:
        if tag in tags_lower:
            return normalize_finding_type(tag)

    # 4. Derive from template_id (e.g. "cve-2024-1234" → "cve_matched").
    tid_lower = template_id.lower()
    if tid_lower.startswith("cve-"):
        return "cve_matched"

    return normalize_finding_type(name)


def _extract_endpoint(matched_at: str) -> str | None:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(matched_at)
        path = parsed.path
        return path if path and path != "/" else None
    except Exception:
        return None
