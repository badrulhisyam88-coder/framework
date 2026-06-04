"""Export ai-assist-tool Finding records to knowledge-vault markdown files.

This module is intentionally stateless — it receives domain objects and
produces files. It does not query the database or call the FastAPI app.
"""

from __future__ import annotations

import re
from pathlib import Path

from apps.validation.models import CVE, Finding, Host, Service
from exporters.export_validator import validate_finding_frontmatter, validate_markdown_content
from exporters.frontmatter_builder import (
    _FINDING_TYPE_MITRE_DETAIL,
    build_finding_frontmatter,
    infer_category,
)
from exporters.link_builder import finding_to_concept, finding_to_remediation
from exporters.markdown_renderer import render_finding

# ---------------------------------------------------------------------------
# Filename helpers
# ---------------------------------------------------------------------------

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(text: str, max_len: int = 40) -> str:
    s = text.lower().replace("_", "-")
    s = _SLUG_RE.sub("-", s).strip("-")
    return s[:max_len].rstrip("-")


def _category_prefix(category: str) -> str:
    return {"web": "WEB", "api": "API", "network": "NET", "cloud": "CLOUD"}.get(category, "WEB")


def next_sequence(output_dir: Path, category: str, date_str: str) -> int:
    """Return the next 3-digit sequence number for a given category + date."""
    prefix = f"FIND-{_category_prefix(category)}-{date_str}-"
    if not output_dir.exists():
        return 1
    existing_nums: list[int] = []
    for f in output_dir.iterdir():
        if f.suffix == ".md" and f.name.startswith(prefix):
            # FIND-WEB-20260518-001_slug.md → "001"
            after_prefix = f.name[len(prefix):]
            num_part = after_prefix.split("_")[0].split(".")[0]
            try:
                existing_nums.append(int(num_part))
            except ValueError:
                pass
    return max(existing_nums, default=0) + 1


def build_find_id(category: str, date_str: str, seq: int) -> str:
    return f"FIND-{_category_prefix(category)}-{date_str}-{seq:03d}"


def build_filename(find_id: str, finding_type: str) -> str:
    slug = _slugify(finding_type)
    return f"{find_id}_{slug}.md"


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------

_FINDING_TYPE_TO_VULN_CLASS: dict[str, str] = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "ssh_cred": "SSH Default / Weak Credential",
    "web_header": "Missing Security Headers",
    "web_wordpress": "WordPress Vulnerability",
    "web_drupal": "Drupal Vulnerability",
    "web_apache": "Apache Misconfiguration",
    "web_nginx": "Nginx Misconfiguration",
    "tls_config": "TLS/SSL Misconfiguration",
    "telnet_cleartext": "Cleartext Protocol (Telnet)",
    "smb_enum": "SMB Enumeration Exposure",
    "cve_poc": "CVE Proof-of-Concept",
}

_FINDING_TYPE_TO_CWE: dict[str, str] = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "ssh_cred": "CWE-521",
    "web_header": "CWE-693",
    "web_nginx": "CWE-16",
    "web_apache": "CWE-16",
    "tls_config": "CWE-326",
    "telnet_cleartext": "CWE-319",
    "smb_enum": "CWE-200",
}

_FINDING_TYPE_TO_CONCEPT_SLUG: dict[str, str] = {
    "sqli": "concept-sqli",
    "xss": "concept-xss",
    "tls_config": "concept-tls",
    "ssh_cred": "concept-credential-attacks",
    "smb_enum": "concept-smb",
    "telnet_cleartext": "concept-cleartext-protocols",
}

_FINDING_TYPE_TO_REMEDIATION_SLUG: dict[str, str] = {
    "sqli": "remediation-web-sqli",
    "xss": "remediation-web-xss",
    "tls_config": "remediation-web-tls",
    "ssh_cred": "remediation-network-ssh-cred",
    "smb_enum": "remediation-network-smb",
    "telnet_cleartext": "remediation-network-telnet",
    "web_header": "remediation-web-headers",
    "web_nginx": "remediation-web-nginx",
    "web_apache": "remediation-web-apache",
    "web_wordpress": "remediation-web-wordpress",
    "web_drupal": "remediation-web-drupal",
}

# Use the shared tuple dict from frontmatter_builder — no duplication.
_FINDING_TYPE_TO_MITRE = _FINDING_TYPE_MITRE_DETAIL


def _build_impact(finding: Finding, host: Host | None, service: Service | None = None) -> str:
    status = finding.validation_status
    svc_info = f" on port {service.port}" if service else ""
    host_info = f" ({host.ip})" if host else ""
    return (
        f"Validation status: {status}. Finding type {finding.finding_type!r} "
        f"confirmed{svc_info}{host_info}. "
        "Review evidence section for full exploitation context."
    )


# ---------------------------------------------------------------------------
# Primary export function
# ---------------------------------------------------------------------------


def export_finding(
    finding: Finding,
    host: Host | None = None,
    service: Service | None = None,
    cve: CVE | None = None,
    vault_path: Path | None = None,
) -> Path:
    """Export a single Finding to the knowledge-vault.

    Returns the path of the written file.
    Raises ValueError if frontmatter validation fails.
    """
    # --- Resolve fields ---
    ftype = finding.finding_type.lower()
    category = infer_category(ftype)
    date_str = finding.timestamp.strftime("%Y%m%d")
    date_iso = finding.timestamp.strftime("%Y-%m-%d")

    # --- Output directory ---
    from exporters.config import get_findings_path as _gfp
    out_dir = (vault_path / "findings" / category) if vault_path else _gfp(category)
    out_dir.mkdir(parents=True, exist_ok=True)

    seq = next_sequence(out_dir, category, date_str)
    find_id = build_find_id(category, date_str, seq)
    filename = build_filename(find_id, ftype)

    # --- Remediation / concept refs ---
    rem_slug = _FINDING_TYPE_TO_REMEDIATION_SLUG.get(
        ftype, f"remediation-{category}-{_slugify(ftype)}"
    )
    rem_link = finding_to_remediation(category, f"{rem_slug}.md", rem_slug)
    rem_ref = f"{rem_slug}.md"

    concept_slug = _FINDING_TYPE_TO_CONCEPT_SLUG.get(ftype, "")
    concept_link = (
        finding_to_concept(category, f"{concept_slug}.md", concept_slug)
        if concept_slug
        else "—"
    )

    # --- Target label ---
    target_label = host.ip if host else "unknown"
    if host and host.hostname:
        target_label = f"{host.hostname} ({host.ip})"

    # Build a readable URL/endpoint from available context
    url_endpoint = ""
    if service and host:
        proto = service.service_name or "tcp"
        url_endpoint = f"{proto}://{host.ip}:{service.port}"
    elif service:
        url_endpoint = f"port {service.port}"

    # --- MITRE row ---
    mitre_row = _FINDING_TYPE_TO_MITRE.get(ftype, ("", "", ""))

    # --- CVE context ---
    cvss_label = str(finding.cvss_score) if finding.cvss_score else "N/A"
    if cve and cve.cvss_score:
        cvss_label = f"{cve.cvss_score}"

    # --- Description ---
    description = finding.evidence.context.get("description", "")
    if not description:
        vuln_class = _FINDING_TYPE_TO_VULN_CLASS.get(ftype, ftype)
        description = (
            f"{vuln_class} identified on {target_label}. "
            f"Validation status: {finding.validation_status}."
        )
        if finding.cve_id:
            description += f" CVE: {finding.cve_id}."

    # --- Steps ---
    steps = finding.evidence.context.get("steps", [])
    if not steps:
        steps = ["Review evidence payload and response below."]

    # --- Frontmatter ---
    fm = build_finding_frontmatter(
        find_id=find_id,
        title=_FINDING_TYPE_TO_VULN_CLASS.get(ftype, ftype),
        date=date_iso,
        severity=finding.severity.value,
        category=category,
        finding_type=ftype,
        target=target_label,
        status="confirmed" if "exploitable" in str(finding.validation_status) else "draft",
        remediation_ref=rem_ref,
    )

    # --- Validate frontmatter ---
    vr = validate_finding_frontmatter(fm)
    if not vr.valid:
        raise ValueError(f"Finding frontmatter validation failed: {vr.errors}")

    # --- Render ---
    cwe = _FINDING_TYPE_TO_CWE.get(ftype, "")
    content = render_finding(
        frontmatter=fm,
        target=target_label,
        url_or_endpoint=url_endpoint,
        parameter=finding.evidence.context.get("parameter", ""),
        date_tested=date_iso,
        tester="ai-assist-tool",
        vuln_type=_FINDING_TYPE_TO_VULN_CLASS.get(ftype, ftype),
        cwe=cwe,
        cvss_score=cvss_label,
        description=description,
        steps_to_reproduce=steps,
        payload=finding.evidence.sent or "",
        response=(finding.evidence.received or "")[:2000],
        impact=_build_impact(finding, host, service),
        mitre_rows=[mitre_row] if any(mitre_row) else [],
        references=finding.evidence.context.get("references", []),
        related_concept=concept_link,
        related_lab="—",
        related_remediation=rem_link,
        related_finding="—",
    )

    # --- Structural validate ---
    content_vr = validate_markdown_content(content)
    if not content_vr.valid:
        raise ValueError(f"Rendered finding content invalid: {content_vr.errors}")

    out_path = out_dir / filename
    out_path.write_text(content, encoding="utf-8")
    return out_path
