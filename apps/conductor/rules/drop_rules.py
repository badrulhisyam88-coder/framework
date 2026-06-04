"""Drop rules for V1.7 FilterOrchestrator.

Rules that classify findings as 'dropped' — verified dead ends that
should be hidden from the operator UI by default.
"""
from apps.conductor.rules.base import RuleResult
from apps.conductor.rules.helpers import detect_server, finding_type


class DropWordpressOnNonWordpressServer:
    id = "drop_wordpress_on_non_wordpress_server"
    description = "Drop wordpress engine findings when recon shows a non-wordpress server."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding.get("probe_id") != "wordpress":
            return RuleResult(matched=False)
        server = detect_server(all_findings)
        if not server:
            return RuleResult(matched=False)
        if "wordpress" in server:
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="dropped",
            reason=f"wordpress engine ran but recon shows non-wordpress server: {server}",
        )


class DropDrupalOnNonDrupalServer:
    id = "drop_drupal_on_non_drupal_server"
    description = "Drop drupal engine findings when recon shows a non-drupal server."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding.get("probe_id") != "drupal":
            return RuleResult(matched=False)
        server = detect_server(all_findings)
        if not server:
            return RuleResult(matched=False)
        if "drupal" in server:
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="dropped",
            reason=f"drupal engine ran but recon shows non-drupal server: {server}",
        )


class DropApacheOnNonApacheServer:
    id = "drop_apache_on_non_apache_server"
    description = "Drop apache engine findings when recon shows a non-apache server."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding.get("probe_id") != "apache":
            return RuleResult(matched=False)
        server = detect_server(all_findings)
        if not server:
            return RuleResult(matched=False)
        if "apache" in server:
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="dropped",
            reason=f"apache engine ran but recon shows non-apache server: {server}",
        )


class DropNginxOnNonNginxServer:
    id = "drop_nginx_on_non_nginx_server"
    description = "Drop nginx engine findings when recon shows a non-nginx server."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding.get("probe_id") != "nginx":
            return RuleResult(matched=False)
        server = detect_server(all_findings)
        if not server:
            return RuleResult(matched=False)
        if "nginx" in server:
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="dropped",
            reason=f"nginx engine ran but recon shows non-nginx server: {server}",
        )


class DropSqliWithEmptyEndpoints:
    id = "drop_sqli_with_empty_endpoints"
    description = "Drop sqli findings when no login endpoints were detected."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding_type(finding) != "sqli":
            return RuleResult(matched=False)
        endpoints = finding.get("evidence", {}).get("detected_login_endpoints")
        if endpoints != []:
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="dropped",
            reason="no login endpoints detected to test for sqli",
        )


class DropPluginFindingWhenToolUnavailable:
    id = "drop_plugin_finding_when_tool_unavailable"
    description = "Drop vulnerability_assessed findings when the plugin tool is unavailable."

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding.get("evidence", {}).get("tool_available") is not False:
            return RuleResult(matched=False)
        if finding_type(finding) != "vulnerability_assessed":
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="dropped",
            reason="plugin tool unavailable. Install tool to enable check.",
        )


_PASSIVE_PROBE_HEADER_TYPES = frozenset({
    "http_service_detected",
    "server_version_leaked",
    "missing_csp_header",
    "missing_hsts_header",
    "missing_x_frame_options",
    "missing_x_content_type_options",
    "missing_referrer_policy",
    "missing_permissions_policy",
    "waf_cdn_detected",
    "http_methods_advertised",
})


class DropPassiveProbeSecurityHeaders:
    id = "drop_passive_probe_security_headers"
    description = (
        "Drop passive_probe informational findings (security headers, banners, WAF detection). "
        "These are recon-phase observations, not action-required items for the exploitation phase."
    )

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding.get("probe_id") != "passive_probe":
            return RuleResult(matched=False)
        if finding_type(finding) not in _PASSIVE_PROBE_HEADER_TYPES:
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="dropped",
            reason="passive_probe informational finding (not action-required)",
        )


# Noise tags observed in DB (2026-05-25 investigation):
# - wildcard-dns-detect: tags=['dns', 'wildcard', 'discovery']
# - secrets-patterns-pii: tags=['global-matchers', 'exposure', 'token', ...]
# 'secrets-patterns' is a template_id substring, not an actual tag — global-matchers catches it.
_NUCLEI_NOISE_TAGS = frozenset({"dns", "wildcard", "global-matchers"})


class DropNucleiInfoLowNoise:
    id = "drop_nuclei_info_low_noise"
    description = (
        "Drop nuclei info/low-severity findings whose evidence.tags include known noise patterns. "
        "Noise tags from DB: 'dns', 'wildcard', 'global-matchers'. "
        "Severity is a top-level finding field, not inside evidence."
    )

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult:
        if finding.get("probe_id") != "nuclei":
            return RuleResult(matched=False)
        if finding_type(finding) != "vulnerability_assessed":
            return RuleResult(matched=False)
        severity = finding.get("severity", "")
        if severity not in ("info", "low"):
            return RuleResult(matched=False)
        tags = finding.get("evidence", {}).get("tags") or []
        noise_tag = next((t for t in tags if t in _NUCLEI_NOISE_TAGS), None)
        if noise_tag is None:
            return RuleResult(matched=False)
        return RuleResult(
            matched=True,
            status="dropped",
            reason=f"nuclei {severity} finding with noise tag '{noise_tag}' (low signal)",
        )


DROPPED_RULES = [
    DropWordpressOnNonWordpressServer(),
    DropDrupalOnNonDrupalServer(),
    DropApacheOnNonApacheServer(),
    DropNginxOnNonNginxServer(),
    DropSqliWithEmptyEndpoints(),
    DropPluginFindingWhenToolUnavailable(),
    DropPassiveProbeSecurityHeaders(),
    DropNucleiInfoLowNoise(),
]
