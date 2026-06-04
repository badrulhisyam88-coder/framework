"""Validate rules for V1.7 FilterOrchestrator.

Rules that classify findings as 'validated' — confirmed worth the
exploitation phase's time.
"""
from apps.conductor.rules.base import RuleResult
from apps.conductor.rules.helpers import finding_type


class ValidateVulnerabilityConfirmed:
    id = "validate_vulnerability_confirmed"
    description = "Validate any vulnerability_confirmed finding from any engine."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding_type(finding) != "vulnerability_confirmed":
            return RuleResult(matched=False)
        probe = finding.get("probe_id", "engine")
        return RuleResult(
            matched=True,
            status="validated",
            reason=f"vulnerability confirmed by {probe} engine",
        )


class ValidateHighRiskZapAlert:
    id = "validate_high_risk_zap_alert"
    description = "Validate ZAP alerts rated High or Critical."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding_type(finding) != "zap_alert":
            return RuleResult(matched=False)
        evidence = finding.get("evidence", {})
        if "risk" not in evidence:
            return RuleResult.evidence_gap("zap_alert missing risk field")
        if evidence["risk"] not in ("High", "Critical"):
            return RuleResult(matched=False)
        alert_id = evidence.get("alert_id", "unknown")
        return RuleResult(
            matched=True,
            status="validated",
            reason=f"high-risk ZAP alert: {alert_id}",
        )


class ValidateCriticalNucleiFinding:
    id = "validate_critical_nuclei_finding"
    description = "Validate nuclei findings at critical or high severity."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding.get("probe_id") != "nuclei":
            return RuleResult(matched=False)
        severity = finding.get("severity", "")
        if severity not in ("critical", "high"):
            return RuleResult(matched=False)
        evidence = finding.get("evidence", {})
        template_id = evidence.get("template_id", "unknown")
        return RuleResult(
            matched=True,
            status="validated",
            reason=f"nuclei {severity}-severity template match: {template_id}",
        )


class ValidateLoginFormWithoutCsrf:
    id = "validate_login_form_without_csrf"
    description = "Validate login forms that have no CSRF token — direct submission possible."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding_type(finding) != "login_form_detected":
            return RuleResult(matched=False)
        forms = finding.get("evidence", {}).get("detected_forms")
        if not forms:
            return RuleResult(matched=False)
        if not all(isinstance(f, dict) and f.get("csrf_field") is None for f in forms):
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="validated",
            reason="login form without CSRF token, direct submission possible",
        )


class ValidateServiceDetectedWithVersion:
    id = "validate_service_detected_with_version"
    description = "Validate service_detected findings that carry a version string."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding_type(finding) != "service_detected":
            return RuleResult(matched=False)
        evidence = finding.get("evidence", {})
        version = evidence.get("service_version", "")
        if not version:
            service = evidence.get("service", "unknown")
            port = evidence.get("port", "?")
            return RuleResult.evidence_gap(
                f"nmap missing service_version for {port}/{service}"
            )
        service = evidence.get("service", "")
        port = evidence.get("port", "")
        return RuleResult(
            matched=True,
            status="validated",
            reason=f"service identified: {service} {version} on port {port}",
        )


class ValidateSqliEndpointsFound:
    id = "validate_sqli_endpoints_found"
    description = (
        "Validate sqli findings that have non-empty login endpoints and do not require auth. "
        "Endpoints are accessible and injectable without a session."
    )

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding_type(finding) != "sqli":
            return RuleResult(matched=False)
        evidence = finding.get("evidence", {})
        endpoints = evidence.get("detected_login_endpoints", [])
        if not endpoints:
            return RuleResult(matched=False)
        if evidence.get("auth_required") is True:
            return RuleResult(matched=False)
        count = len(endpoints)
        return RuleResult(
            matched=True,
            status="validated",
            reason=f"sqli: {count} accessible login endpoint(s) found, no auth required",
        )


class ValidateApiExposureAccessible:
    id = "validate_api_exposure_accessible"
    description = (
        "Validate api_exposure findings where at least one hit path returned 200 "
        "and no 401/403 responses were observed — API accessible without credentials."
    )

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding_type(finding) != "api_exposure":
            return RuleResult(matched=False)
        evidence = finding.get("evidence", {})
        hit_paths = evidence.get("hit_paths", [])
        if not hit_paths:
            return RuleResult(matched=False)
        accessible = [
            p for p in hit_paths
            if isinstance(p, dict) and p.get("status_code") == 200
        ]
        if not accessible:
            return RuleResult(matched=False)
        auth_gated = any(
            isinstance(p, dict) and p.get("status_code") in (401, 403)
            for p in hit_paths
        )
        if auth_gated:
            return RuleResult(matched=False)
        count = len(accessible)
        return RuleResult(
            matched=True,
            status="validated",
            reason=f"api_exposure: {count} path(s) return 200 with no auth gate observed",
        )


class ValidateCmdiEndpointsFound:
    id = "validate_cmdi_endpoints_found"
    description = (
        "Validate command_injection findings with non-empty detected_paths and no auth required. "
        "Paths are accessible and testable without a session. "
        "Evidence field is 'detected_paths' (list[str] from cmdi_recon probe)."
    )

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding_type(finding) != "command_injection":
            return RuleResult(matched=False)
        evidence = finding.get("evidence", {})
        paths = evidence.get("detected_paths", [])
        if not paths:
            return RuleResult(matched=False)
        if evidence.get("auth_required") is True:
            return RuleResult(matched=False)
        count = len(paths)
        return RuleResult(
            matched=True,
            status="validated",
            reason=f"cmdi: {count} accessible endpoint(s) found, no auth required",
        )


VALIDATE_RULES = [
    ValidateVulnerabilityConfirmed(),
    ValidateHighRiskZapAlert(),
    ValidateCriticalNucleiFinding(),
    ValidateLoginFormWithoutCsrf(),
    ValidateServiceDetectedWithVersion(),
    ValidateSqliEndpointsFound(),
    ValidateApiExposureAccessible(),
    ValidateCmdiEndpointsFound(),
]
