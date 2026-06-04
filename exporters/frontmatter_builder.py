"""YAML frontmatter builders for each vault document type.

All builders return plain dicts. The markdown_renderer owns the serialisation.
No third-party YAML dependency — frontmatter serialisation is handled by
dump_frontmatter() which covers the simple key/value/list structures used here.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Minimal YAML serialiser for frontmatter blocks
# ---------------------------------------------------------------------------


def _yaml_scalar(value: Any) -> str:
    """Serialise a scalar value to a YAML-safe string."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value)
    # Quote if the string contains characters that would confuse a YAML parser
    needs_quoting = (
        any(c in s for c in ':"{}[]|>&*!,#%@`\'')
        or s.startswith(" ")
        or s.endswith(" ")
        or s in ("true", "false", "null", "yes", "no")
        or (s and s[0].isdigit())
    )
    if needs_quoting:
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return s


def dump_frontmatter(data: dict[str, Any]) -> str:
    """Serialise a dict to a YAML frontmatter block (--- delimited)."""
    lines: list[str] = ["---"]
    for key, val in data.items():
        if isinstance(val, list):
            if not val:
                lines.append(f"{key}: []")
            else:
                lines.append(f"{key}:")
                for item in val:
                    lines.append(f"  - {_yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {_yaml_scalar(val)}")
    lines.append("---")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Per-type frontmatter builders
# ---------------------------------------------------------------------------

# Maps ValidationType strings to OWASP tags
_VALIDATION_TYPE_TO_OWASP: dict[str, str] = {
    "sqli": "owasp-a03",
    "xss": "owasp-a03",
    "rce": "owasp-a03",
    "command_injection": "owasp-a03",
    "web_header": "owasp-a05",
    "web_wordpress": "owasp-a06",
    "web_drupal": "owasp-a06",
    "web_apache": "owasp-a05",
    "web_nginx": "owasp-a05",
    "tls_config": "owasp-a02",
    "ssh_cred": "owasp-a07",
    "telnet_cleartext": "owasp-a02",
    "smb_enum": "owasp-a01",
    "cve_poc": "owasp-a06",
}

# Maps ValidationType strings to MITRE technique IDs
_VALIDATION_TYPE_TO_MITRE: dict[str, str] = {
    "sqli": "mitre-t1190",
    "xss": "mitre-t1190",
    "rce": "mitre-t1059",
    "command_injection": "mitre-t1059",
    "web_header": "mitre-t1190",
    "web_wordpress": "mitre-t1190",
    "web_drupal": "mitre-t1190",
    "web_apache": "mitre-t1190",
    "web_nginx": "mitre-t1190",
    "tls_config": "mitre-t1040",
    "ssh_cred": "mitre-t1078",
    "telnet_cleartext": "mitre-t1040",
    "smb_enum": "mitre-t1021",
    "cve_poc": "mitre-t1190",
}

# Maps ValidationType strings to (tactic, technique_name, technique_id) tuples.
# Used by finding_exporter and attack_observation_exporter for document body rendering.
_FINDING_TYPE_MITRE_DETAIL: dict[str, tuple[str, str, str]] = {
    "sqli": ("Initial Access", "Exploit Public-Facing Application", "T1190"),
    "xss": ("Initial Access", "Exploit Public-Facing Application", "T1190"),
    "ssh_cred": ("Credential Access", "Valid Accounts", "T1078"),
    "tls_config": ("Credential Access", "Network Sniffing", "T1040"),
    "telnet_cleartext": ("Credential Access", "Network Sniffing", "T1040"),
    "smb_enum": ("Discovery", "Network Share Discovery", "T1135"),
    "web_nginx": ("Initial Access", "Exploit Public-Facing Application", "T1190"),
    "web_apache": ("Initial Access", "Exploit Public-Facing Application", "T1190"),
    "web_wordpress": ("Initial Access", "Exploit Public-Facing Application", "T1190"),
    "web_drupal": ("Initial Access", "Exploit Public-Facing Application", "T1190"),
    "web_header": ("Defense Evasion", "Impair Defenses", "T1562"),
    "cve_poc": ("Initial Access", "Exploit Public-Facing Application", "T1190"),
}

# Maps ValidationType strings to vault finding category
_VALIDATION_TYPE_TO_CATEGORY: dict[str, str] = {
    "ssh_cred": "network",
    "web_header": "web",
    "web_wordpress": "web",
    "web_drupal": "web",
    "web_apache": "web",
    "web_nginx": "web",
    "tls_config": "web",
    "sqli": "web",
    "telnet_cleartext": "network",
    "smb_enum": "network",
    "cve_poc": "web",
}


def infer_category(finding_type: str) -> str:
    """Derive vault category from a ValidationType string."""
    return _VALIDATION_TYPE_TO_CATEGORY.get(finding_type.lower(), "web")


def build_finding_tags(
    finding_type: str,
    severity: str,
    extra_tags: list[str] | None = None,
) -> list[str]:
    """Build a deduplicated, sorted tag list for a finding frontmatter."""
    tags: list[str] = [finding_type.lower().replace("_", "-")]
    owasp = _VALIDATION_TYPE_TO_OWASP.get(finding_type.lower())
    if owasp:
        tags.append(owasp)
    mitre = _VALIDATION_TYPE_TO_MITRE.get(finding_type.lower())
    if mitre:
        tags.append(mitre)
    tags.append(severity.lower())
    if extra_tags:
        tags.extend(extra_tags)
    # Deduplicate while preserving insertion order
    seen: set[str] = set()
    result: list[str] = []
    for t in tags:
        if t not in seen:
            seen.add(t)
            result.append(t)
    return result


def build_finding_frontmatter(
    find_id: str,
    title: str,
    date: str,
    severity: str,
    category: str,
    finding_type: str,
    target: str,
    status: str,
    related_labs: list[str] | None = None,
    related_concepts: list[str] | None = None,
    related_findings: list[str] | None = None,
    remediation_ref: str = "",
    extra_tags: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "type": "finding",
        "id": find_id,
        "title": title,
        "date": date,
        "severity": severity,
        "category": category,
        "source": "ai-assist",
        "platform": "real-world",
        "target": target,
        "status": status,
        "tags": build_finding_tags(finding_type, severity, extra_tags),
        "related_labs": related_labs or [],
        "related_concepts": related_concepts or [],
        "related_findings": related_findings or [],
        "remediation_ref": remediation_ref,
    }


def build_service_discovery_frontmatter(
    find_id: str,
    title: str,
    date: str,
    scope: str,
    host_count: int,
    service_count: int,
) -> dict[str, Any]:
    return {
        "type": "service-discovery",
        "id": find_id,
        "title": title,
        "date": date,
        "category": "network",
        "source": "ai-assist",
        "platform": "real-world",
        "scope": scope,
        "host_count": host_count,
        "service_count": service_count,
        "tags": ["service-discovery", "network", "reconnaissance", "mitre-t1046"],
        "related_findings": [],
    }


def build_remediation_frontmatter(
    rem_id: str,
    title: str,
    date: str,
    category: str,
    severity: str,
    finding_type: str,
    related_findings: list[str] | None = None,
) -> dict[str, Any]:
    tags = ["remediation", finding_type.lower().replace("_", "-")]
    owasp = _VALIDATION_TYPE_TO_OWASP.get(finding_type.lower())
    if owasp:
        tags.append(owasp)
    tags.append(category)
    return {
        "type": "remediation",
        "id": rem_id,
        "title": title,
        "date": date,
        "category": category,
        "severity": severity,
        "status": "draft",
        "tags": tags,
        "related_findings": related_findings or [],
        "related_concepts": [],
    }


def build_attack_chain_frontmatter(
    chain_id: str,
    title: str,
    date: str,
    initial_access: str,
    outcome: str,
    tags: list[str],
    related_findings: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "type": "attack-chain",
        "id": chain_id,
        "title": title,
        "date": date,
        "status": "draft",
        "target_environment": "real-world",
        "initial_access": initial_access,
        "outcome": outcome,
        "tags": ["attack-chain"] + tags,
        "related_findings": related_findings or [],
        "related_labs": [],
        "related_concepts": [],
        "mitre_techniques": mitre_techniques or [],
    }
