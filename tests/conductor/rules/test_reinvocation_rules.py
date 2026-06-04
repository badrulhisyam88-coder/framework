"""Tests for re-invocation rules."""
from __future__ import annotations

from apps.conductor.rules.reinvocation_rules import (
    ReinvokeApiReconWithHitPaths,
    ReinvokeAuthReconWithFormPaths,
    ReinvokeCmdiWithDetectedPaths,
    ReinvokeNmapNseOnOpenPort,
    ReinvokeNucleiWithTemplate,
    ReinvokeSqliWithLoginEndpoints,
    ReinvokeSshWithExtendedWordlist,
    ReinvokeWordpressWithZapPath,
)


def _finding(category="", probe_id="", evidence=None, path=""):
    return {
        "id": "fnd-test",
        "category": category,
        "probe_id": probe_id,
        "path": path,
        "evidence": evidence if evidence is not None else {},
    }


# ── ReinvokeNmapNseOnOpenPort ─────────────────────────────────────────────────

def test_nmap_nse_fires_on_service_detected_with_port():
    rule = ReinvokeNmapNseOnOpenPort()
    finding = _finding(category="service_detected", evidence={"port": 22, "service": "ssh"})
    reqs = rule.evaluate(finding, [])
    assert len(reqs) == 1
    assert reqs[0].engine_id == "nmap"
    assert "22" in reqs[0].config["args"]
    assert reqs[0].rule_id == rule.id


def test_nmap_nse_no_match_wrong_type():
    rule = ReinvokeNmapNseOnOpenPort()
    finding = _finding(category="sqli")
    assert rule.evaluate(finding, []) == []


def test_nmap_nse_no_match_missing_port():
    rule = ReinvokeNmapNseOnOpenPort()
    finding = _finding(category="service_detected", evidence={})
    assert rule.evaluate(finding, []) == []


# ── ReinvokeSqliWithLoginEndpoints ────────────────────────────────────────────

def test_sqli_reinvoke_fires_on_sqli_with_endpoints():
    rule = ReinvokeSqliWithLoginEndpoints()
    finding = _finding(
        category="sqli",
        evidence={"detected_login_endpoints": [{"path": "/api/login", "status_code": 200}]},
    )
    reqs = rule.evaluate(finding, [])
    assert len(reqs) == 1
    assert reqs[0].engine_id == "sqli_recon"
    assert "/api/login" in reqs[0].config["candidate_paths"]


def test_sqli_reinvoke_no_match_empty_endpoints():
    rule = ReinvokeSqliWithLoginEndpoints()
    finding = _finding(category="sqli", evidence={"detected_login_endpoints": []})
    assert rule.evaluate(finding, []) == []


def test_sqli_reinvoke_no_match_wrong_type():
    rule = ReinvokeSqliWithLoginEndpoints()
    finding = _finding(category="api_exposure")
    assert rule.evaluate(finding, []) == []


# ── ReinvokeCmdiWithDetectedPaths ─────────────────────────────────────────────

def test_cmdi_reinvoke_fires_on_command_injection():
    rule = ReinvokeCmdiWithDetectedPaths()
    finding = _finding(
        category="command_injection",
        evidence={"detected_paths": ["/vulnerabilities/exec/", "/commandi.php"]},
    )
    reqs = rule.evaluate(finding, [])
    assert len(reqs) == 1
    assert reqs[0].engine_id == "cmdi_recon"
    assert "/vulnerabilities/exec/" in reqs[0].config["candidate_paths"]


def test_cmdi_reinvoke_no_match_empty_paths():
    rule = ReinvokeCmdiWithDetectedPaths()
    finding = _finding(category="command_injection", evidence={"detected_paths": []})
    assert rule.evaluate(finding, []) == []


# ── ReinvokeAuthReconWithFormPaths ────────────────────────────────────────────

def test_auth_reinvoke_fires_on_login_form_detected():
    rule = ReinvokeAuthReconWithFormPaths()
    finding = _finding(
        category="login_form_detected",
        evidence={"detected_forms": [{"path": "/login.php"}, {"path": "/admin/login"}]},
    )
    reqs = rule.evaluate(finding, [])
    assert len(reqs) == 1
    assert reqs[0].engine_id == "auth_recon"
    assert "/login.php" in reqs[0].config["candidate_paths"]
    assert "/admin/login" in reqs[0].config["candidate_paths"]


def test_auth_reinvoke_no_match_empty_forms():
    rule = ReinvokeAuthReconWithFormPaths()
    finding = _finding(category="login_form_detected", evidence={"detected_forms": []})
    assert rule.evaluate(finding, []) == []


# ── ReinvokeApiReconWithHitPaths ──────────────────────────────────────────────

def test_api_reinvoke_fires_on_api_exposure():
    rule = ReinvokeApiReconWithHitPaths()
    finding = _finding(
        category="api_exposure",
        evidence={"hit_paths": [{"path": "/api/docs", "status_code": 200}]},
    )
    reqs = rule.evaluate(finding, [])
    assert len(reqs) == 1
    assert reqs[0].engine_id == "api_recon"
    assert "/api/docs" in reqs[0].config["candidate_paths"]


def test_api_reinvoke_no_match_missing_hit_paths():
    rule = ReinvokeApiReconWithHitPaths()
    finding = _finding(category="api_exposure", evidence={"signals": ["some signal"]})
    assert rule.evaluate(finding, []) == []


# ── ReinvokeSshWithExtendedWordlist ───────────────────────────────────────────

def test_ssh_reinvoke_fires_on_ssh_service():
    rule = ReinvokeSshWithExtendedWordlist()
    finding = _finding(
        category="service_detected",
        evidence={"service": "ssh", "port": 22, "scheme": "tcp"},
    )
    reqs = rule.evaluate(finding, [])
    assert len(reqs) == 1
    assert reqs[0].engine_id == "ssh"
    assert reqs[0].config["wordlist_id"] == "credentials_extended"


def test_ssh_reinvoke_no_match_non_ssh():
    rule = ReinvokeSshWithExtendedWordlist()
    finding = _finding(
        category="service_detected",
        evidence={"service": "http", "port": 80},
    )
    assert rule.evaluate(finding, []) == []


# ── ReinvokeWordpressWithZapPath ──────────────────────────────────────────────

def test_wordpress_reinvoke_fires_on_wp_zap_endpoint():
    rule = ReinvokeWordpressWithZapPath()
    finding = _finding(
        category="zap_endpoint_discovered",
        evidence={"url": "http://target/blog/wp-login.php"},
    )
    reqs = rule.evaluate(finding, [])
    assert len(reqs) == 1
    assert reqs[0].engine_id == "wordpress"
    assert reqs[0].config["wp_base_path"] == "/blog"


def test_wordpress_reinvoke_no_match_non_wp_url():
    rule = ReinvokeWordpressWithZapPath()
    finding = _finding(
        category="zap_endpoint_discovered",
        evidence={"url": "http://target/api/docs"},
    )
    assert rule.evaluate(finding, []) == []


def test_wordpress_reinvoke_no_match_wrong_type():
    rule = ReinvokeWordpressWithZapPath()
    finding = _finding(category="sqli")
    assert rule.evaluate(finding, []) == []


# ── ReinvokeNucleiWithTemplate ────────────────────────────────────────────────

def test_nuclei_reinvoke_fires_on_vulnerability_assessed():
    rule = ReinvokeNucleiWithTemplate()
    finding = _finding(
        category="vulnerability_assessed",
        probe_id="nuclei",
        evidence={"template_id": "cve-2021-4034"},
    )
    reqs = rule.evaluate(finding, [])
    assert len(reqs) == 1
    assert reqs[0].engine_id == "nuclei"
    assert "cve-2021-4034" in reqs[0].config["templates"]


def test_nuclei_reinvoke_no_match_non_nuclei_probe():
    rule = ReinvokeNucleiWithTemplate()
    finding = _finding(
        category="vulnerability_assessed",
        probe_id="wordpress",
        evidence={"template_id": "cve-2021-4034"},
    )
    assert rule.evaluate(finding, []) == []


def test_nuclei_reinvoke_no_match_unknown_template():
    rule = ReinvokeNucleiWithTemplate()
    finding = _finding(
        category="vulnerability_assessed",
        probe_id="nuclei",
        evidence={"template_id": "unknown"},
    )
    assert rule.evaluate(finding, []) == []
