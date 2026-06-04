"""ZAP alert normalizer — converts OWASP ZAP JSON alerts to NormalizedFinding list."""

from __future__ import annotations

from typing import Any

from apps.scanner_orchestration.execution.models import ScanExecution
from apps.scanner_orchestration.normalization.finding_type_map import (
    normalize_finding_type,
)
from apps.scanner_orchestration.normalization.models import NormalizedFinding


def normalize_zap_results(
    raw_result: dict[str, Any],
    scan: ScanExecution,
) -> list[NormalizedFinding]:
    """Convert ZAP /alerts JSON response to NormalizedFinding list."""
    findings: list[NormalizedFinding] = []
    alerts: list[dict] = raw_result.get("alerts", [])

    for alert in alerts:
        alert_name = alert.get("name", alert.get("alert", "Unknown"))
        risk_code = alert.get("riskcode", "0")
        confidence = alert.get("confidence", "2")
        description = alert.get("desc", "")
        solution = alert.get("solution", "")
        url = alert.get("url", scan.target)
        cweid = alert.get("cweid", "")
        reference = alert.get("reference", "")

        # Some ZAP fields use risk names, some use numeric codes
        risk_name = alert.get("riskdesc", "")
        sev = _map_zap_risk(risk_code, risk_name)
        ft = normalize_finding_type(alert_name)

        # Parse endpoint from URL
        endpoint = _extract_endpoint(url)

        tags = ["zap"]
        if confidence:
            tags.append(f"confidence-{confidence}")

        cwes = [f"CWE-{cweid}"] if cweid and cweid != "0" else []

        desc_full = description
        if solution:
            desc_full += f"\n\nRemediation: {solution}"
        if reference:
            desc_full += f"\n\nReference: {reference[:200]}"

        findings.append(NormalizedFinding(
            scan_id=scan.scan_id,
            investigation_id=scan.investigation_id,
            source_scanner="zap",
            finding_type=ft,
            severity=sev,
            title=alert_name,
            description=desc_full[:1000],
            target=scan.target,
            endpoint=endpoint,
            related_cwes=cwes,
            raw_data=alert,
            tags=tags,
        ))

    return findings


def _map_zap_risk(risk_code: str, risk_name: str) -> str:
    _CODE_MAP = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    code_sev = _CODE_MAP.get(str(risk_code), "info")
    if code_sev != "info":
        return code_sev
    # Try risk name
    name_lower = risk_name.lower()
    if "high" in name_lower:
        return "high"
    if "medium" in name_lower:
        return "medium"
    if "low" in name_lower:
        return "low"
    return "info"


def _extract_endpoint(url: str) -> str | None:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path
        return path if path and path != "/" else None
    except Exception:
        return None
