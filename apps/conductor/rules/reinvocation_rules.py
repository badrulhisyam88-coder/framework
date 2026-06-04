"""Re-invocation rules for V1.7 FilterOrchestrator two-pass.

Rules that request re-invocation of an existing engine with refined
parameters derived from first-pass recon evidence. Each rule returns
a list of ReinvocationRequest objects (empty list = no match).

ReinvocationRequests are deduped by (engine_id, config) before dispatch
so multiple findings that trigger the same re-invocation don't cause
duplicate engine runs.
"""
from __future__ import annotations

from apps.conductor.rules.base import ReinvocationRequest
from apps.conductor.rules.helpers import extract_paths_from_zap_findings, finding_type


class ReinvokeNmapNseOnOpenPort:
    id = "reinvoke_nmap_nse_on_open_port"
    description = "Re-invoke nmap with NSE scripts against a discovered open port."

    def evaluate(
        self, finding: dict, all_findings: list[dict]
    ) -> list[ReinvocationRequest]:
        if finding_type(finding) != "service_detected":
            return []
        ev = finding.get("evidence", {})
        port = ev.get("port")
        if not port:
            return []
        return [ReinvocationRequest(
            engine_id="nmap",
            config={"args": f"-p {port} --script=default,version"},
            source_finding_id=finding.get("id", ""),
            rule_id=self.id,
        )]


class ReinvokeSqliWithLoginEndpoints:
    id = "reinvoke_sqli_with_login_endpoints"
    description = "Re-invoke sqli_recon focused on discovered login endpoint paths."

    def evaluate(
        self, finding: dict, all_findings: list[dict]
    ) -> list[ReinvocationRequest]:
        if finding_type(finding) != "sqli":
            return []
        endpoints = finding.get("evidence", {}).get("detected_login_endpoints")
        if not isinstance(endpoints, list) or not endpoints:
            return []
        paths = [e["path"] for e in endpoints if isinstance(e, dict) and e.get("path")]
        if not paths:
            return []
        return [ReinvocationRequest(
            engine_id="sqli_recon",
            config={"candidate_paths": paths},
            source_finding_id=finding.get("id", ""),
            rule_id=self.id,
        )]


class ReinvokeCmdiWithDetectedPaths:
    id = "reinvoke_cmdi_with_detected_paths"
    description = "Re-invoke cmdi_recon focused on discovered command-injection paths."

    def evaluate(
        self, finding: dict, all_findings: list[dict]
    ) -> list[ReinvocationRequest]:
        if finding_type(finding) != "command_injection":
            return []
        detected = finding.get("evidence", {}).get("detected_paths")
        if not isinstance(detected, list) or not detected:
            return []
        return [ReinvocationRequest(
            engine_id="cmdi_recon",
            config={"candidate_paths": list(detected)},
            source_finding_id=finding.get("id", ""),
            rule_id=self.id,
        )]


class ReinvokeAuthReconWithFormPaths:
    id = "reinvoke_auth_recon_with_form_paths"
    description = "Re-invoke auth_recon focused on discovered login form paths."

    def evaluate(
        self, finding: dict, all_findings: list[dict]
    ) -> list[ReinvocationRequest]:
        if finding_type(finding) != "login_form_detected":
            return []
        forms = finding.get("evidence", {}).get("detected_forms")
        if not isinstance(forms, list) or not forms:
            return []
        paths = [f["path"] for f in forms if isinstance(f, dict) and f.get("path")]
        if not paths:
            return []
        return [ReinvocationRequest(
            engine_id="auth_recon",
            config={"candidate_paths": paths},
            source_finding_id=finding.get("id", ""),
            rule_id=self.id,
        )]


class ReinvokeApiReconWithHitPaths:
    id = "reinvoke_api_recon_with_hit_paths"
    description = "Re-invoke api_recon focused on confirmed API hit paths."

    def evaluate(
        self, finding: dict, all_findings: list[dict]
    ) -> list[ReinvocationRequest]:
        if finding_type(finding) != "api_exposure":
            return []
        hit_paths = finding.get("evidence", {}).get("hit_paths")
        if not isinstance(hit_paths, list) or not hit_paths:
            return []
        paths = [h["path"] for h in hit_paths if isinstance(h, dict) and h.get("path")]
        if not paths:
            return []
        return [ReinvocationRequest(
            engine_id="api_recon",
            config={"candidate_paths": paths},
            source_finding_id=finding.get("id", ""),
            rule_id=self.id,
        )]


class ReinvokeSshWithExtendedWordlist:
    id = "reinvoke_ssh_with_extended_wordlist"
    description = "Re-invoke SSH engine with extended credential wordlist on SSH services."

    def evaluate(
        self, finding: dict, all_findings: list[dict]
    ) -> list[ReinvocationRequest]:
        if finding_type(finding) != "service_detected":
            return []
        ev = finding.get("evidence", {})
        if ev.get("service", "").lower() != "ssh":
            return []
        port = ev.get("port")
        scheme = ev.get("scheme", "tcp")
        service_info: dict = {}
        if port:
            service_info = {"port": port, "service": "ssh", "scheme": scheme}
        return [ReinvocationRequest(
            engine_id="ssh",
            config={"wordlist_id": "credentials_extended", "service_info": service_info},
            source_finding_id=finding.get("id", ""),
            rule_id=self.id,
        )]


class ReinvokeWordpressWithZapPath:
    id = "reinvoke_wordpress_with_zap_path"
    description = "Re-invoke WordPress engine when ZAP discovers a WordPress-shaped path."

    def evaluate(
        self, finding: dict, all_findings: list[dict]
    ) -> list[ReinvocationRequest]:
        if finding_type(finding) != "zap_endpoint_discovered":
            return []
        url = finding.get("evidence", {}).get("url", "")
        if not any(marker in url.lower() for marker in ("/wp-", "/wordpress/")):
            return []
        # Extract the base path prefix (everything before /wp-)
        for marker in ("/wp-", "/wordpress/"):
            idx = url.lower().find(marker)
            if idx >= 0:
                # Get path portion only (strip scheme/host)
                from urllib.parse import urlparse
                parsed = urlparse(url)
                full_path = parsed.path
                marker_idx = full_path.lower().find(marker)
                wp_base_path = full_path[:marker_idx] if marker_idx > 0 else ""
                return [ReinvocationRequest(
                    engine_id="wordpress",
                    config={"wp_base_path": wp_base_path},
                    source_finding_id=finding.get("id", ""),
                    rule_id=self.id,
                )]
        return []


class ReinvokeNucleiWithTemplate:
    id = "reinvoke_nuclei_with_template"
    description = "Re-invoke nuclei with the matched template for deeper scanning."

    def evaluate(
        self, finding: dict, all_findings: list[dict]
    ) -> list[ReinvocationRequest]:
        if finding_type(finding) != "vulnerability_assessed":
            return []
        if finding.get("probe_id") != "nuclei":
            return []
        template_id = finding.get("evidence", {}).get("template_id")
        if not template_id or template_id == "unknown":
            return []
        return [ReinvocationRequest(
            engine_id="nuclei",
            config={
                "templates": [template_id],
                "severity": ["critical", "high", "medium", "low", "info"],
            },
            source_finding_id=finding.get("id", ""),
            rule_id=self.id,
        )]


REINVOCATION_RULES = [
    ReinvokeNmapNseOnOpenPort(),
    ReinvokeSqliWithLoginEndpoints(),
    ReinvokeCmdiWithDetectedPaths(),
    ReinvokeAuthReconWithFormPaths(),
    ReinvokeApiReconWithHitPaths(),
    ReinvokeSshWithExtendedWordlist(),
    ReinvokeWordpressWithZapPath(),
    ReinvokeNucleiWithTemplate(),
]
