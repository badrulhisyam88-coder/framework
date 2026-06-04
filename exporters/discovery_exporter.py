"""Export service discovery scan results to knowledge-vault markdown.

Produces a service-discovery summary document in findings/network/ that
records all hosts and services found during a scan run.
"""

from __future__ import annotations

import re
from pathlib import Path

from apps.validation.models import Host, Service
from exporters.config import get_findings_path
from exporters.export_validator import validate_markdown_content
from exporters.frontmatter_builder import build_service_discovery_frontmatter
from exporters.markdown_renderer import render_service_discovery

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(text: str, max_len: int = 30) -> str:
    s = text.lower()
    s = _SLUG_RE.sub("-", s).strip("-")
    return s[:max_len].rstrip("-")


def _next_discovery_seq(out_dir: Path, date_str: str) -> int:
    prefix = f"FIND-NET-{date_str}-"
    if not out_dir.exists():
        return 1
    nums: list[int] = []
    for f in out_dir.iterdir():
        if f.suffix == ".md" and f.name.startswith(prefix):
            after = f.name[len(prefix):]
            num_part = after.split("_")[0].split(".")[0]
            try:
                nums.append(int(num_part))
            except ValueError:
                pass
    return max(nums, default=0) + 1


def export_discovery_summary(
    hosts: list[Host],
    services: list[Service],
    scan_date: str,
    scope: str,
    notes: str = "",
    vault_path: Path | None = None,
) -> Path:
    """Export a service discovery summary to knowledge-vault/findings/network/.

    Args:
        hosts: List of Host objects discovered during the scan.
        services: List of Service objects discovered.
        scan_date: Date string in YYYYMMDD format.
        scope: Human-readable scope label (e.g., "10.0.0.0/24").
        notes: Optional free-text notes about the scan.
        vault_path: Override vault root path.

    Returns:
        Path of the written markdown file.
    """
    out_dir = (vault_path / "findings" / "network") if vault_path else get_findings_path("network")
    out_dir.mkdir(parents=True, exist_ok=True)

    date_iso = f"{scan_date[:4]}-{scan_date[4:6]}-{scan_date[6:]}"
    seq = _next_discovery_seq(out_dir, scan_date)
    find_id = f"FIND-NET-{scan_date}-{seq:03d}"
    scope_slug = _slugify(scope)
    filename = f"{find_id}_service-discovery-{scope_slug}.md"
    title = f"Service Discovery — {scope}"

    fm = build_service_discovery_frontmatter(
        find_id=find_id,
        title=title,
        date=date_iso,
        scope=scope,
        host_count=len(hosts),
        service_count=len(services),
    )

    # Build host rows for the table
    host_ip_map: dict[str, Host] = {h.id: h for h in hosts}
    host_rows = [
        {
            "ip": h.ip,
            "hostname": h.hostname or "",
            "os_guess": h.os_guess or "",
            "status": h.status.value,
        }
        for h in hosts
    ]

    # Build service rows
    svc_rows = [
        {
            "ip": host_ip_map[s.host_id].ip if s.host_id in host_ip_map else s.host_id,
            "port": str(s.port),
            "protocol": s.protocol.value,
            "service_name": s.service_name or "",
            "product": s.product or "",
            "version": s.version or "",
        }
        for s in services
    ]

    content = render_service_discovery(
        frontmatter=fm,
        scope=scope,
        date=date_iso,
        host_rows=host_rows,
        service_rows=svc_rows,
        notes=notes,
    )

    vr = validate_markdown_content(content)
    if not vr.valid:
        raise ValueError(f"Discovery summary content invalid: {vr.errors}")

    out_path = out_dir / filename
    out_path.write_text(content, encoding="utf-8")
    return out_path
