"""PDF report generator service.

Renders a HTML template via Jinja2, then converts it to a PDF with
WeasyPrint. Loads all data through the existing repositories so the
report stays consistent with the rest of the UI.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

from apps.validation.database import get_db
from apps.validation.models import (
    Asset,
    Finding,
    ReportConfig,
)
from apps.validation.repositories import (
    AssetRepository,
    CVERepository,
    FindingRepository,
    HostRepository,
    QueueRepository,
    ServiceRepository,
)
from sdk import Logger

_TEMPLATE_DIR = "frontend/templates"
_TEMPLATE_NAME = "report_pdf.html"


# Severity ordering for sorts and "top issues" ranking.
_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _parse_target(target: str) -> tuple[Any, str | None, str | None]:
    """Return (cidr, exact_ip, hostname) for an asset target string."""
    t = (target or "").strip()
    if not t:
        return None, None, None

    if "/" in t:
        try:
            return ipaddress.ip_network(t, strict=False), None, None
        except ValueError:
            pass

    if t.endswith(".x") or t.endswith(".*"):
        candidate = t[:-1] + "0/24"
        try:
            return ipaddress.ip_network(candidate, strict=False), None, None
        except ValueError:
            pass

    try:
        return None, str(ipaddress.ip_address(t)), None
    except ValueError:
        pass

    return None, None, t


async def _hosts_for_asset(asset: Asset, host_repo: HostRepository) -> list:
    """All hosts in the discovery store that match this asset's target."""
    cidr, ip, hostname = _parse_target(asset.target)
    all_hosts = await host_repo.list_all()
    matched = []
    for host in all_hosts:
        if ip and host.ip == ip:
            matched.append(host)
            continue
        if cidr is not None:
            try:
                if ipaddress.ip_address(host.ip) in cidr:
                    matched.append(host)
                    continue
            except ValueError:
                pass
        if hostname and host.hostname and host.hostname.lower() == hostname.lower():
            matched.append(host)
    return matched


def _filter_findings_by_severity(findings: list[Finding], severity_filter: str) -> list[Finding]:
    if severity_filter == "high_above":
        return [f for f in findings if str(f.severity) in ("high", "critical")]
    if severity_filter == "critical_only":
        return [f for f in findings if str(f.severity) == "critical"]
    return findings


class ReportGenerator:
    """Generate a defensible PDF security report."""

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(_TEMPLATE_DIR),
            autoescape=select_autoescape(["html", "xml"]),
        )

    async def generate(self, config: ReportConfig) -> bytes:
        Logger.info(
            "report.generate.start",
            extra={
                "title": config.title,
                "asset_count": len(config.asset_ids),
                "severity_filter": config.severity_filter,
            },
        )

        async with get_db() as db:
            asset_repo = AssetRepository(db)
            host_repo = HostRepository(db)
            service_repo = ServiceRepository(db)
            finding_repo = FindingRepository(db)
            queue_repo = QueueRepository(db)
            cve_repo = CVERepository(db)

            enriched_assets: list[dict[str, Any]] = []
            enriched_findings: list[dict[str, Any]] = []

            for asset_id in config.asset_ids:
                asset = await asset_repo.get_by_id(asset_id)
                if not asset:
                    continue

                hosts = await _hosts_for_asset(asset, host_repo)
                asset_services: list = []
                asset_findings: list = []

                for host in hosts:
                    services = await service_repo.list_by_host(host.id)
                    asset_services.extend(services)

                    all_host_findings = [
                        f
                        for f in await finding_repo.list_all(limit=100_000)
                        if f.host_id == host.id
                    ]
                    filtered = _filter_findings_by_severity(
                        all_host_findings, config.severity_filter
                    )

                    for finding in filtered:
                        service = None
                        if finding.service_id:
                            service = await service_repo.get_by_id(finding.service_id)
                        cve = None
                        if finding.cve_id:
                            cve = await cve_repo.get_by_id(finding.cve_id)
                        queue_item = None
                        if finding.queue_item_id:
                            queue_item = await queue_repo.get_by_id(
                                finding.queue_item_id
                            )

                        plugin_name = queue_item.plugin_name if queue_item else None
                        auto_approved = bool(
                            queue_item
                            and queue_item.notes
                            and "Watchlist" in queue_item.notes
                        )

                        enriched = {
                            "id": finding.id,
                            "finding_type": finding.finding_type,
                            "severity": str(finding.severity),
                            "cvss_score": finding.cvss_score,
                            "validation_status": str(finding.validation_status),
                            "status": str(finding.status),
                            "timestamp": finding.timestamp,
                            "evidence": finding.evidence,
                            "environment_context": finding.environment_context,
                            "cve_id": finding.cve_id,
                            "cve": cve,
                            "host": host,
                            "service": service,
                            "queue_item": queue_item,
                            "asset_name": asset.name,
                            "host_ip": host.ip,
                            "port": service.port if service else None,
                            "service_name": service.service_name if service else None,
                            "version": service.version if service else None,
                            "banner": service.banner if service else None,
                            "plugin_name": plugin_name,
                            "scan_type": asset.scan_type,
                            "auto_approved": auto_approved,
                        }
                        asset_findings.append(enriched)
                        enriched_findings.append(enriched)

                enriched_assets.append(
                    {
                        "asset": asset,
                        "hosts": hosts,
                        "services": asset_services,
                        "findings": asset_findings,
                    }
                )

            # Summary counters.
            critical_count = sum(
                1 for f in enriched_findings if f["severity"] == "critical"
            )
            high_count = sum(1 for f in enriched_findings if f["severity"] == "high")
            medium_count = sum(
                1 for f in enriched_findings if f["severity"] == "medium"
            )
            low_count = sum(1 for f in enriched_findings if f["severity"] == "low")
            exploitable_count = sum(
                1
                for f in enriched_findings
                if f["validation_status"] == "validated_exploitable"
            )
            resolved_count = sum(
                1
                for f in enriched_findings
                if f["status"] in ("acknowledged", "resolved", "suppressed")
            )

            # Findings sorted by severity rank desc, then cvss desc.
            findings_sorted = sorted(
                enriched_findings,
                key=lambda f: (
                    -_SEVERITY_RANK.get(f["severity"], 0),
                    -(f["cvss_score"] or 0.0),
                ),
            )

            resolved_findings = [
                f
                for f in findings_sorted
                if f["status"] in ("acknowledged", "resolved", "suppressed")
            ]

            top_issues = findings_sorted[:3]

            cve_count = await cve_repo.count()
            try:
                last_sync = await cve_repo.get_sync_meta("last_sync")
            except Exception:
                last_sync = None

        context = {
            "title": config.title,
            "prepared_by": config.prepared_by,
            "period_start": config.period_start,
            "period_end": config.period_end,
            "generated_at": datetime.utcnow(),
            "assets": enriched_assets,
            "findings": findings_sorted,
            "summary": {
                "total_assets": len(enriched_assets),
                "total_findings": len(enriched_findings),
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "exploitable_count": exploitable_count,
                "resolved_count": resolved_count,
            },
            "top_issues": top_issues,
            "watchlist_status": [],
            "sections": config.sections,
            "resolved_findings": resolved_findings,
            "cve_count": cve_count,
            "last_sync": last_sync,
        }

        template = self._env.get_template(_TEMPLATE_NAME)
        html_str = template.render(**context)
        pdf_bytes = HTML(string=html_str, base_url=_TEMPLATE_DIR).write_pdf()

        Logger.info(
            "report.generate.complete",
            extra={
                "title": config.title,
                "asset_count": len(enriched_assets),
                "finding_count": len(enriched_findings),
                "size_bytes": len(pdf_bytes),
            },
        )
        return pdf_bytes
