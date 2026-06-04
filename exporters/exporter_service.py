"""Orchestration layer for all ai-assist-tool vault exporters.

This module provides a single entry point for exporting findings, discovery
summaries, remediation playbooks, and attack chains. It coordinates the
individual exporters and ensures output directories exist before writing.

Usage (standalone CLI):
    python -m exporters.exporter_service --help
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from apps.validation.models import CVE, Finding, Host, Service
from exporters.attack_observation_exporter import export_attack_observation
from exporters.config import ensure_output_dirs, get_vault_path
from exporters.discovery_exporter import export_discovery_summary
from exporters.finding_exporter import export_finding
from exporters.remediation_exporter import export_remediation

logger = logging.getLogger(__name__)


@dataclass
class ExportBatch:
    """Container for a batch of findings ready for vault export."""

    findings: list[Finding] = field(default_factory=list)
    hosts: dict[str, Host] = field(default_factory=dict)
    services: dict[str, Service] = field(default_factory=dict)
    cves: dict[str, CVE] = field(default_factory=dict)


@dataclass
class ExportReport:
    """Summary of an export run."""

    findings_written: list[Path] = field(default_factory=list)
    remediations_written: list[Path] = field(default_factory=list)
    discovery_written: list[Path] = field(default_factory=list)
    chains_written: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_written(self) -> int:
        return (
            len(self.findings_written)
            + len(self.remediations_written)
            + len(self.discovery_written)
            + len(self.chains_written)
        )

    def log_summary(self) -> None:
        logger.info(
            "Export complete",
            extra={
                "findings": len(self.findings_written),
                "remediations": len(self.remediations_written),
                "discovery": len(self.discovery_written),
                "chains": len(self.chains_written),
                "errors": len(self.errors),
            },
        )


class ExporterService:
    """Coordinates vault export for ai-assist-tool operational findings.

    All exports are isolated to the knowledge-vault. This service does not
    modify the ai-assist-tool database or any runtime state.
    """

    def __init__(self, vault_path: Path | None = None) -> None:
        self.vault_path = vault_path or get_vault_path()

    def export_findings(
        self,
        batch: ExportBatch,
        export_remediations: bool = True,
    ) -> ExportReport:
        """Export all findings in the batch plus optional remediation playbooks.

        Args:
            batch: ExportBatch containing findings with their related objects.
            export_remediations: Whether to also write remediation playbooks.

        Returns:
            ExportReport summarising what was written and any errors.
        """
        ensure_output_dirs()
        report = ExportReport()

        for finding in batch.findings:
            host = batch.hosts.get(finding.host_id)
            service = batch.services.get(finding.service_id or "")
            cve = batch.cves.get(finding.cve_id or "")

            try:
                path = export_finding(
                    finding=finding,
                    host=host,
                    service=service,
                    cve=cve,
                    vault_path=self.vault_path,
                )
                report.findings_written.append(path)
                logger.info("Exported finding", extra={"path": str(path), "finding_id": finding.id})
            except Exception as exc:
                msg = f"Failed to export finding {finding.id}: {exc}"
                logger.error(msg)
                report.errors.append(msg)
                continue

            if export_remediations:
                try:
                    date_str = finding.timestamp.strftime("%Y%m%d")
                    # Extract vault FIND-* ID from the written filename stem
                    vault_find_id = path.stem.split("_")[0]
                    rem_path = export_remediation(
                        finding=finding,
                        date_str=date_str,
                        vault_find_id=vault_find_id,
                        vault_path=self.vault_path,
                    )
                    report.remediations_written.append(rem_path)
                    logger.info("Exported remediation", extra={"path": str(rem_path)})
                except Exception as exc:
                    msg = f"Failed to export remediation for finding {finding.id}: {exc}"
                    logger.warning(msg)
                    report.errors.append(msg)

        return report

    def export_discovery(
        self,
        hosts: list[Host],
        services: list[Service],
        scan_date: str,
        scope: str,
        notes: str = "",
    ) -> ExportReport:
        """Export a service discovery scan summary.

        Args:
            hosts: Discovered Host objects.
            services: Discovered Service objects.
            scan_date: YYYYMMDD format date string.
            scope: Human-readable scope label (IP range, CIDR, etc.).
            notes: Optional contextual notes about the scan.

        Returns:
            ExportReport with discovery path or errors.
        """
        ensure_output_dirs()
        report = ExportReport()
        try:
            path = export_discovery_summary(
                hosts=hosts,
                services=services,
                scan_date=scan_date,
                scope=scope,
                notes=notes,
                vault_path=self.vault_path,
            )
            report.discovery_written.append(path)
            logger.info("Exported discovery summary", extra={"path": str(path)})
        except Exception as exc:
            msg = f"Failed to export discovery summary: {exc}"
            logger.error(msg)
            report.errors.append(msg)
        return report

    def export_attack_chain(
        self,
        findings: list[Finding],
        chain_title: str,
        overview: str,
        target: str,
        scope: str,
        outcome: str,
        host_map: dict[str, Host] | None = None,
        vault_finding_refs: list[str] | None = None,
    ) -> ExportReport:
        """Export a multi-finding attack chain narrative.

        Args:
            findings: Ordered list of Finding objects forming the chain.
            chain_title: Human-readable name for this attack chain.
            overview: Narrative summary of the attack path.
            target: Target description.
            scope: Scope label.
            outcome: End state achieved.
            host_map: Optional host_id → Host mapping for IP resolution.
            vault_finding_refs: Vault FIND-* IDs to include in related_findings.
                Pass the IDs returned by export_findings() to link correctly.

        Returns:
            ExportReport with chain path or errors.
        """
        ensure_output_dirs()
        report = ExportReport()
        try:
            path = export_attack_observation(
                findings=findings,
                chain_title=chain_title,
                overview=overview,
                target=target,
                scope=scope,
                outcome=outcome,
                host_map=host_map,
                vault_finding_refs=vault_finding_refs,
                vault_path=self.vault_path,
            )
            report.chains_written.append(path)
            logger.info("Exported attack chain", extra={"path": str(path)})
        except Exception as exc:
            msg = f"Failed to export attack chain: {exc}"
            logger.error(msg)
            report.errors.append(msg)
        return report
