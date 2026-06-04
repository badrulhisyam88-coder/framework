"""Export multi-finding attack observations to knowledge-vault attack-chains/.

An attack observation is a set of related findings that together describe a
multi-step adversary path. This exporter composes them into a single attack
chain markdown document.
"""

from __future__ import annotations

import re
from pathlib import Path

from apps.validation.models import Finding, Host
from exporters.config import get_attack_chains_path
from exporters.export_validator import validate_attack_chain_frontmatter, validate_markdown_content
from exporters.frontmatter_builder import (
    _FINDING_TYPE_MITRE_DETAIL,
    _VALIDATION_TYPE_TO_MITRE,
    build_attack_chain_frontmatter,
)
from exporters.link_builder import wikilink
from exporters.markdown_renderer import render_attack_chain

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(text: str, max_len: int = 40) -> str:
    s = text.lower()
    s = _SLUG_RE.sub("-", s).strip("-")
    return s[:max_len].rstrip("-")


def _next_chain_seq(out_dir: Path, date_str: str) -> int:
    prefix = f"CHAIN-{date_str}-"
    if not out_dir.exists():
        return 1
    nums: list[int] = []
    for f in out_dir.iterdir():
        if f.suffix == ".md" and f.name.startswith(prefix):
            after = f.name[len(prefix):]
            num_part = after.split(".")[0]
            try:
                nums.append(int(num_part))
            except ValueError:
                pass
    return max(nums, default=0) + 1


def _chain_date(findings: list[Finding]) -> tuple[str, str]:
    """Return (YYYYMMDD, YYYY-MM-DD) from the earliest finding timestamp."""
    if not findings:
        from datetime import datetime
        ts = datetime.utcnow()
    else:
        ts = min(f.timestamp for f in findings)
    return ts.strftime("%Y%m%d"), ts.strftime("%Y-%m-%d")


def export_attack_observation(
    findings: list[Finding],
    chain_title: str,
    overview: str,
    target: str,
    scope: str,
    outcome: str,
    host_map: dict[str, Host] | None = None,
    vault_finding_refs: list[str] | None = None,
    vault_path: Path | None = None,
) -> Path:
    """Export a multi-finding attack chain to knowledge-vault/attack-chains/.

    Args:
        findings: Ordered list of Finding objects forming the chain.
        chain_title: Human-readable name for this attack chain.
        overview: Narrative summary of the full attack path.
        target: Target description (e.g., "internal-dc-01").
        scope: Scope label (e.g., "Internal data-centre segment").
        outcome: End state achieved (e.g., "unauthenticated access to admin interface").
        host_map: Optional mapping from host_id to Host for IP resolution.
        vault_finding_refs: Optional list of vault FIND-* IDs (e.g. FIND-WEB-20260518-001).
            If omitted, related_findings is left empty to avoid storing internal UUIDs.
        vault_path: Override vault root path.

    Returns:
        Path of the written markdown file.
    """
    if not findings:
        raise ValueError("Cannot export an attack chain with no findings.")

    out_dir = (vault_path / "attack-chains") if vault_path else get_attack_chains_path()
    out_dir.mkdir(parents=True, exist_ok=True)

    date_str, date_iso = _chain_date(findings)
    seq = _next_chain_seq(out_dir, date_str)
    chain_id = f"CHAIN-{date_str}-{seq:03d}"
    slug = _slugify(chain_title)
    filename = f"{date_str}_chain_{slug}.md"

    # Collect tags + MITRE techniques
    tags: list[str] = []
    mitre_techniques: list[str] = []
    for f in findings:
        ftype = f.finding_type.lower()
        tags.append(ftype.replace("_", "-"))
        mitre = _VALIDATION_TYPE_TO_MITRE.get(ftype)
        if mitre:
            mitre_techniques.append(mitre.upper().replace("MITRE-", ""))

    # Deduplicate
    seen: set[str] = set()
    unique_tags: list[str] = []
    for t in tags:
        if t not in seen:
            seen.add(t)
            unique_tags.append(t)

    seen_m: set[str] = set()
    unique_mitre: list[str] = []
    for m in mitre_techniques:
        if m not in seen_m:
            seen_m.add(m)
            unique_mitre.append(m)

    fm = build_attack_chain_frontmatter(
        chain_id=chain_id,
        title=chain_title,
        date=date_iso,
        initial_access=findings[0].finding_type if findings else "",
        outcome=outcome,
        tags=unique_tags,
        related_findings=vault_finding_refs or [],
        mitre_techniques=unique_mitre,
    )

    vr = validate_attack_chain_frontmatter(fm)
    if not vr.valid:
        raise ValueError(f"Attack chain frontmatter validation failed: {vr.errors}")

    # Build phases — one phase per finding
    phases: list[dict] = []
    for _i, f in enumerate(findings, start=1):
        ftype = f.finding_type.lower()
        host = (host_map or {}).get(f.host_id)
        host_label = host.ip if host else f.host_id
        mitre_entry = _FINDING_TYPE_MITRE_DETAIL.get(ftype, ("", "", ""))
        phases.append({
            "name": f"{ftype.replace('_', ' ').title()} — {host_label}",
            "technique": mitre_entry[1],
            "mitre_id": mitre_entry[2],
            "description": (
                f"Finding ID: {f.id}\n"
                f"Type: {f.finding_type} | Severity: {f.severity.value} | "
                f"Status: {f.validation_status}"
            ),
            "commands": f.evidence.sent or "# See evidence payload",
        })

    # MITRE summary table
    mitre_summary: list[tuple[str, str, str, str]] = []
    for i, f in enumerate(findings):
        ftype = f.finding_type.lower()
        row = _FINDING_TYPE_MITRE_DETAIL.get(ftype, ("—", "—", "—"))
        phase_label = f"Phase {i + 1}"
        mitre_summary.append((phase_label, row[0], row[1], row[2]))

    # Detection opportunities
    detection: list[tuple[str, str, str]] = []
    for i, f in enumerate(findings):
        ftype = f.finding_type.lower()
        detection_hints = {
            "sqli": ("SQL error patterns in HTTP responses", "WAF / Application logs"),
            "xss": ("Script injection in HTTP parameters", "WAF / Browser logs"),
            "ssh_cred": ("Successful SSH auth from unexpected source", "Auth logs / SIEM"),
            "tls_config": ("Downgrade negotiation", "Network capture"),
            "telnet_cleartext": ("Telnet traffic on port 23", "Network IDS"),
            "smb_enum": ("Null session SMB connection", "Windows Event Log"),
            "web_header": ("Missing security headers in responses", "Proxy logs"),
        }
        hint = detection_hints.get(ftype, ("Review finding evidence", "Application logs"))
        detection.append((f"Phase {i + 1}: {ftype}", hint[0], hint[1]))

    # Related finding links
    related_finding_links: list[str] = [wikilink(str(f.id)) for f in findings]

    content = render_attack_chain(
        frontmatter=fm,
        overview=overview,
        target=target,
        scope=scope,
        date=date_iso,
        phases=phases,
        mitre_summary=mitre_summary,
        detection_opportunities=detection,
        related_findings=related_finding_links,
        related_lab="—",
        related_blue_team="—",
    )

    content_vr = validate_markdown_content(content)
    if not content_vr.valid:
        raise ValueError(f"Rendered attack chain content invalid: {content_vr.errors}")

    out_path = out_dir / filename
    out_path.write_text(content, encoding="utf-8")
    return out_path
