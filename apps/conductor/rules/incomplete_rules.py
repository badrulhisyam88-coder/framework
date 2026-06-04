"""Incomplete rules for V1.7 FilterOrchestrator.

Rules that classify findings as 'incomplete' — worth exploitation's time
but missing data needed to proceed without operator input.
"""
from apps.conductor.rules.base import RuleResult
from apps.conductor.rules.helpers import finding_type


class IncompleteLoginFormWithCsrf:
    id = "incomplete_login_form_with_csrf"
    description = "Mark login forms incomplete when CSRF protection is present."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding_type(finding) != "login_form_detected":
            return RuleResult(matched=False)
        forms = finding.get("evidence", {}).get("detected_forms")
        if not forms:
            return RuleResult(matched=False)
        has_csrf = any(
            isinstance(f, dict) and f.get("csrf_field") is not None for f in forms
        )
        if not has_csrf:
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="incomplete",
            reason="login form has CSRF protection",
            gaps=["csrf_token_needed"],
        )


class IncompleteSqliAuthRequired:
    id = "incomplete_sqli_auth_required"
    description = "Mark sqli findings incomplete when authentication is required."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding_type(finding) != "sqli":
            return RuleResult(matched=False)
        if finding.get("evidence", {}).get("auth_required") is not True:
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="incomplete",
            reason="sqli candidates require authentication",
            gaps=["session_needed"],
        )


class IncompleteCmdiAuthRequired:
    id = "incomplete_cmdi_auth_required"
    description = "Mark command_injection findings incomplete when authentication is required."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding_type(finding) != "command_injection":
            return RuleResult(matched=False)
        if finding.get("evidence", {}).get("auth_required") is not True:
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="incomplete",
            reason="cmdi candidates require authentication",
            gaps=["session_needed"],
        )


class IncompletePluginMissingTool:
    id = "incomplete_plugin_missing_tool"
    description = "Mark vulnerability_confirmed incomplete when the plugin tool is unavailable."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding.get("evidence", {}).get("tool_available") is not False:
            return RuleResult(matched=False)
        if finding_type(finding) != "vulnerability_confirmed":
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="incomplete",
            reason="plugin tool unavailable",
            gaps=["tool_missing"],
        )


class IncompleteApiExposureAuthUnknown:
    id = "incomplete_api_exposure_auth_unknown"
    description = "Mark api_exposure findings incomplete when endpoints require authentication."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding_type(finding) != "api_exposure":
            return RuleResult(matched=False)
        evidence = finding.get("evidence", {})
        hit_paths = evidence.get("hit_paths")
        if hit_paths is None:
            return RuleResult.evidence_gap("api_recon missing hit_paths evidence")
        if not isinstance(hit_paths, list):
            return RuleResult(matched=False)
        if hit_paths and all(isinstance(entry, str) for entry in hit_paths):
            return RuleResult.evidence_gap("api_recon missing per-path response codes")
        has_auth_required = any(
            isinstance(entry, dict) and entry.get("status_code") in (401, 403)
            for entry in hit_paths
        )
        if not has_auth_required:
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="incomplete",
            reason="API endpoints require authentication",
            gaps=["session_needed", "credentials_needed"],
        )


class IncompleteZapAlertMediumRisk:
    id = "incomplete_zap_alert_medium_risk"
    description = "Mark medium-risk ZAP alerts incomplete pending exploit validation."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding_type(finding) != "zap_alert":
            return RuleResult(matched=False)
        evidence = finding.get("evidence", {})
        if evidence.get("risk") != "Medium":
            return RuleResult(matched=False)
        alert_id = evidence.get("alert_id", "unknown")
        return RuleResult(
            matched=True,
            status="incomplete",
            reason=f"medium-risk ZAP alert: {alert_id}",
            gaps=["exploit_validation_needed"],
        )


class IncompleteServiceVersionUnknown:
    id = "incomplete_service_version_unknown"
    description = (
        "Mark service_detected incomplete when nmap returned 'unknown' as the service version. "
        "Registered BEFORE ValidateServiceDetectedWithVersion in registry.py — 'unknown' is a "
        "truthy string and would otherwise be falsely validated with an uninformative reason. "
        "NOT added to INCOMPLETE_RULES below; registry.py injects it at validate-order position."
    )

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding_type(finding) != "service_detected":
            return RuleResult(matched=False)
        version = finding.get("evidence", {}).get("service_version", "")
        if version.lower() != "unknown":
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="incomplete",
            reason="service version not fingerprinted (nmap returned 'unknown')",
            gaps=["service_version_unknown"],
        )


INCOMPLETE_RULES = [
    IncompleteLoginFormWithCsrf(),
    IncompleteSqliAuthRequired(),
    IncompleteCmdiAuthRequired(),
    IncompletePluginMissingTool(),
    IncompleteApiExposureAuthUnknown(),
    IncompleteZapAlertMediumRisk(),
    # IncompleteServiceVersionUnknown is defined above but registered in registry.py
    # before ValidateServiceDetectedWithVersion (first-match-wins ordering requirement).
]
