"""End-to-end test: export operational findings to knowledge-vault.

Run from ai-assist-tool/ project root:
    .venv/bin/python scripts/e2e_export_test.py
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from apps.validation.models import (
    CVE,
    Evidence,
    Finding,
    FindingSeverity,
    FindingStatus,
    Host,
    HostStatus,
    Service,
    ServiceProtocol,
    ValidationStatus,
    ValidationType,
)
from exporters.exporter_service import ExportBatch, ExporterService

VAULT_PATH = Path(__file__).parent.parent / "knowledge-vault"


def _sep(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print("=" * 60)


def run() -> None:
    print(f"Vault path: {VAULT_PATH}")
    print(f"Vault exists: {VAULT_PATH.exists()}")

    svc = ExporterService(vault_path=VAULT_PATH)

    # ------------------------------------------------------------------
    # 1. Build mock domain objects
    # ------------------------------------------------------------------
    _sep("Building mock domain objects")

    host = Host(
        id="host-001",
        ip="10.0.1.55",
        hostname="internal-web-01",
        os_guess="Linux 4.15",
        status=HostStatus.ACTIVE,
    )

    service = Service(
        id="svc-001",
        host_id="host-001",
        port=80,
        protocol=ServiceProtocol.TCP,
        service_name="http",
        product="nginx",
        version="1.18.0",
    )

    sqli_finding = Finding(
        id="finding-sqli-001",
        host_id="host-001",
        service_id="svc-001",
        cve_id=None,
        timestamp=datetime(2026, 5, 18, 10, 0, 0),
        finding_type=ValidationType.SQLI,
        severity=FindingSeverity.HIGH,
        validation_status=ValidationStatus.VALIDATED_EXPLOITABLE,
        status=FindingStatus.OPEN,
        evidence=Evidence(
            sent="' OR 1=1--",
            received="HTTP/1.1 200 OK\n{\"token\": \"admin-jwt-abc123\"}",
            context={
                "parameter": "username",
                "description": (
                    "SQL injection in the login endpoint allows authentication bypass. "
                    "The username parameter is concatenated directly into a SQL WHERE clause."
                ),
                "steps": [
                    "Navigate to http://10.0.1.55/login",
                    "Enter ' OR 1=1-- as the username",
                    "Observe successful login response with admin token",
                ],
                "references": [
                    "[OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)",
                    "[CWE-89](https://cwe.mitre.org/data/definitions/89.html)",
                ],
            },
        ),
    )

    ssh_finding = Finding(
        id="finding-ssh-001",
        host_id="host-001",
        service_id="svc-002",
        cve_id=None,
        timestamp=datetime(2026, 5, 18, 11, 0, 0),
        finding_type=ValidationType.SSH_CRED,
        severity=FindingSeverity.CRITICAL,
        validation_status=ValidationStatus.VALIDATED_EXPLOITABLE,
        status=FindingStatus.OPEN,
        evidence=Evidence(
            sent="ssh admin@10.0.1.55 (password: admin)",
            received="Welcome to Ubuntu 20.04 LTS",
            context={
                "parameter": "SSH credential",
                "description": "SSH service accessible with default admin:admin credential.",
            },
        ),
    )

    print(f"  Created host: {host.ip} ({host.hostname})")
    print(f"  Created service: port {service.port} {service.product} {service.version}")
    print(f"  Created SQLi finding: {sqli_finding.id} severity={sqli_finding.severity}")
    print(f"  Created SSH finding: {ssh_finding.id} severity={ssh_finding.severity}")

    # ------------------------------------------------------------------
    # 2. Export findings
    # ------------------------------------------------------------------
    _sep("Phase 1: Exporting findings")

    batch = ExportBatch(
        findings=[sqli_finding, ssh_finding],
        hosts={host.id: host},
        services={service.id: service},
        cves={},
    )

    report = svc.export_findings(batch, export_remediations=True)

    print(f"\n  Findings written ({len(report.findings_written)}):")
    for p in report.findings_written:
        print(f"    ✓ {p.relative_to(VAULT_PATH)}")

    print(f"\n  Remediations written ({len(report.remediations_written)}):")
    for p in report.remediations_written:
        print(f"    ✓ {p.relative_to(VAULT_PATH)}")

    if report.errors:
        print(f"\n  Errors ({len(report.errors)}):")
        for e in report.errors:
            print(f"    ✗ {e}")

    # ------------------------------------------------------------------
    # 3. Export service discovery
    # ------------------------------------------------------------------
    _sep("Phase 2: Exporting service discovery summary")

    extra_hosts = [
        Host(id="h2", ip="10.0.1.56", hostname="db-01", os_guess="Linux"),
        Host(id="h3", ip="10.0.1.57", hostname="api-gw", os_guess="Linux"),
    ]
    extra_services = [
        Service(id="s2", host_id="h2", port=3306, service_name="mysql", product="MySQL", version="8.0"),
        Service(id="s3", host_id="h3", port=443, service_name="https", product="nginx", version="1.20"),
        Service(id="s4", host_id="h3", port=8080, service_name="http-alt", product="nodejs"),
    ]

    disc_report = svc.export_discovery(
        hosts=[host] + extra_hosts,
        services=[service] + extra_services,
        scan_date="20260518",
        scope="10.0.1.0/24",
        notes="Internal data-centre scan — segment A. Three hosts found, one with SQLi confirmed.",
    )

    print(f"\n  Discovery written ({len(disc_report.discovery_written)}):")
    for p in disc_report.discovery_written:
        print(f"    ✓ {p.relative_to(VAULT_PATH)}")

    # ------------------------------------------------------------------
    # 4. Export attack chain
    # ------------------------------------------------------------------
    _sep("Phase 3: Exporting attack chain")

    chain_report = svc.export_attack_chain(
        findings=[sqli_finding, ssh_finding],
        chain_title="Web SQLi to SSH Root Access",
        overview=(
            "SQL injection on the login endpoint was exploited to extract admin credentials "
            "from the database. The credentials were reused to authenticate via SSH "
            "with root-equivalent access on the same host."
        ),
        target="internal-web-01 (10.0.1.55)",
        scope="Internal segment A — 10.0.1.0/24",
        outcome="Root SSH access via credential reuse from SQLi data extraction",
        host_map={host.id: host},
    )

    print(f"\n  Attack chains written ({len(chain_report.chains_written)}):")
    for p in chain_report.chains_written:
        print(f"    ✓ {p.relative_to(VAULT_PATH)}")

    # ------------------------------------------------------------------
    # 5. Verify files on disk
    # ------------------------------------------------------------------
    _sep("Verifying output files exist and have content")

    all_written = (
        report.findings_written
        + report.remediations_written
        + disc_report.discovery_written
        + chain_report.chains_written
    )
    for p in all_written:
        size = p.stat().st_size
        lines = len(p.read_text().splitlines())
        print(f"  {p.relative_to(VAULT_PATH)}: {size} bytes, {lines} lines")

    # ------------------------------------------------------------------
    # 6. Quick spot-check: show first 30 lines of first finding
    # ------------------------------------------------------------------
    if report.findings_written:
        _sep("Spot-check: first 30 lines of first finding export")
        first = report.findings_written[0]
        for i, line in enumerate(first.read_text().splitlines()[:30], 1):
            print(f"  {i:3d}  {line}")

    _sep("COMPLETE")
    total = len(all_written)
    errors = len(report.errors) + len(disc_report.errors) + len(chain_report.errors)
    print(f"  Files written: {total}")
    print(f"  Errors:        {errors}")
    print(f"  Status:        {'✓ PASS' if errors == 0 else '✗ FAIL'}")


if __name__ == "__main__":
    run()
