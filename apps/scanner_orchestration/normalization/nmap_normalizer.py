"""Nmap result normalizer — converts parsed nmap output to NormalizedFinding list."""

from __future__ import annotations

from typing import Any

from apps.scanner_orchestration.execution.models import ScanExecution
from apps.scanner_orchestration.normalization.models import NormalizedFinding

# Ports/services that carry learning context
_HIGH_INTEREST_SERVICES: dict[str, tuple[str, str]] = {
    "http":    ("http_service_detected", "medium"),
    "https":   ("http_service_detected", "low"),
    "ftp":     ("cleartext_transmission", "medium"),
    "telnet":  ("cleartext_transmission", "high"),
    "ssh":     ("service_banner_disclosed", "low"),
    "smb":     ("smb_exposure", "medium"),
    "mysql":   ("service_banner_disclosed", "high"),
    "mssql":   ("service_banner_disclosed", "high"),
    "postgresql": ("service_banner_disclosed", "high"),
    "vnc":     ("service_banner_disclosed", "high"),
    "rdp":     ("service_banner_disclosed", "medium"),
}


def normalize_nmap_results(
    raw_result: dict[str, Any],
    scan: ScanExecution,
) -> list[NormalizedFinding]:
    """Convert nmap parsed output (hosts + services dicts) to NormalizedFinding list."""
    findings: list[NormalizedFinding] = []

    hosts: list[dict] = raw_result.get("hosts", [])
    for host in hosts:
        ip = host.get("ip", scan.target)
        services: list[dict] = host.get("services", [])
        for svc in services:
            port = svc.get("port")
            protocol = svc.get("protocol", "tcp")
            service_name = (svc.get("service_name") or "").lower()
            product = svc.get("product", "")
            version = svc.get("version", "")
            banner = svc.get("banner", "")

            # Determine finding type + severity from service
            ft, sev = _classify_service(service_name, port)

            title = f"Open {protocol.upper()} port {port}"
            if service_name:
                title += f" ({service_name})"
            if product:
                title += f" — {product}"
                if version:
                    title += f" {version}"

            description = (
                f"Port {port}/{protocol} is open on {ip}. "
                f"Service: {service_name or 'unknown'}"
            )
            if product:
                description += f", Product: {product}"
            if version:
                description += f" {version}"
            if banner:
                description += f"\nBanner: {banner[:200]}"

            tags = ["nmap", f"port-{port}", protocol]
            if service_name:
                tags.append(service_name)

            findings.append(NormalizedFinding(
                scan_id=scan.scan_id,
                investigation_id=scan.investigation_id,
                source_scanner="nmap",
                finding_type=ft,
                severity=sev,
                title=title,
                description=description,
                target=ip,
                port=port,
                raw_data=svc,
                tags=tags,
            ))

    # Add any script findings (e.g. nmap NSE script results)
    for host in hosts:
        for script in host.get("scripts", []):
            script_id = script.get("id", "")
            output = script.get("output", "")
            ft = _script_to_finding_type(script_id)
            sev = _script_to_severity(script_id)
            findings.append(NormalizedFinding(
                scan_id=scan.scan_id,
                investigation_id=scan.investigation_id,
                source_scanner="nmap",
                finding_type=ft,
                severity=sev,
                title=f"NSE: {script_id}",
                description=output[:500],
                target=host.get("ip", scan.target),
                raw_data=script,
                tags=["nmap", "nse", script_id],
            ))

    return findings


def _classify_service(service_name: str, port: int | None) -> tuple[str, str]:
    """Return (finding_type, severity) for a discovered service."""
    if service_name in _HIGH_INTEREST_SERVICES:
        return _HIGH_INTEREST_SERVICES[service_name]
    # Port-based fallback
    if port in (21, 23):
        return "cleartext_transmission", "high"
    if port in (3306, 5432, 1433, 1521):
        return "service_banner_disclosed", "high"
    return "open_port_detected", "info"


def _script_to_finding_type(script_id: str) -> str:
    _NSE_MAP = {
        "ssh-auth-methods": "ssh_cred",
        "ssh-hostkey": "service_banner_disclosed",
        "http-default-accounts": "default_credentials",
        "http-auth": "weak_credentials",
        "smb-security-mode": "smb_exposure",
        "ssl-cert": "tls_weakness",
        "ssl-dh-params": "tls_weakness",
        "vuln": "known_vulnerability",
        "ftp-anon": "service_banner_disclosed",
        "telnet-ntlm-info": "cleartext_transmission",
    }
    for key, ft in _NSE_MAP.items():
        if key in script_id.lower():
            return ft
    return "information_disclosure"


def _script_to_severity(script_id: str) -> str:
    _HIGH_RISK = {"default-accounts", "vuln", "exploit", "brute"}
    _MED_RISK = {"auth", "anon", "dh-params"}
    sid = script_id.lower()
    if any(k in sid for k in _HIGH_RISK):
        return "high"
    if any(k in sid for k in _MED_RISK):
        return "medium"
    return "info"
