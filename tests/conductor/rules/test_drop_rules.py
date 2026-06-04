"""Tests for drop rules."""
from __future__ import annotations

from apps.conductor.rules.drop_rules import (
    DropApacheOnNonApacheServer,
    DropNginxOnNonNginxServer,
    DropPluginFindingWhenToolUnavailable,
    DropSqliWithEmptyEndpoints,
    DropWordpressOnNonWordpressServer,
)


def _finding(category: str = "", probe_id: str = "", evidence: dict | None = None) -> dict:
    return {
        "id": "fnd-test",
        "category": category,
        "title": "",
        "severity": "",
        "description": "",
        "path": "",
        "evidence": evidence if evidence is not None else {},
        "confidence": "",
        "next_actions": [],
        "probe_id": probe_id,
        "phase": "recon",
    }


def _server_finding(server: str) -> dict:
    return {
        "id": "fnd-server",
        "category": "http_service_detected",
        "title": "",
        "severity": "",
        "description": "",
        "path": "",
        "evidence": {"server": server},
        "confidence": "",
        "next_actions": [],
        "probe_id": "passive_probe",
        "phase": "recon",
    }


def test_drop_wordpress_drops_on_nginx_server():
    rule = DropWordpressOnNonWordpressServer()
    finding = _finding(category="vulnerability_confirmed", probe_id="wordpress")
    all_findings = [_server_finding("nginx/1.18")]
    result = rule.evaluate(finding, all_findings)
    assert result.matched
    assert result.status == "dropped"
    assert "nginx" in result.reason


def test_drop_wordpress_no_match_unknown_server():
    rule = DropWordpressOnNonWordpressServer()
    finding = _finding(category="vulnerability_confirmed", probe_id="wordpress")
    result = rule.evaluate(finding, [])
    assert not result.matched


def test_drop_wordpress_no_match_wordpress_server():
    rule = DropWordpressOnNonWordpressServer()
    finding = _finding(category="vulnerability_confirmed", probe_id="wordpress")
    all_findings = [_server_finding("wordpress/6.0")]
    result = rule.evaluate(finding, all_findings)
    assert not result.matched


def test_drop_sqli_empty_endpoints():
    rule = DropSqliWithEmptyEndpoints()
    finding = _finding(category="sqli", evidence={"detected_login_endpoints": []})
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "dropped"


def test_drop_sqli_no_match_nonempty_endpoints():
    rule = DropSqliWithEmptyEndpoints()
    finding = _finding(
        category="sqli",
        evidence={"detected_login_endpoints": [
            {"path": "/login", "status_code": 200, "method": "POST"}
        ]},
    )
    result = rule.evaluate(finding, [])
    assert not result.matched


def test_drop_sqli_no_match_none_endpoints():
    rule = DropSqliWithEmptyEndpoints()
    finding = _finding(category="sqli", evidence={"detected_login_endpoints": None})
    result = rule.evaluate(finding, [])
    assert not result.matched


def test_drop_plugin_tool_unavailable_vulnerability_assessed():
    rule = DropPluginFindingWhenToolUnavailable()
    finding = _finding(category="vulnerability_assessed", evidence={"tool_available": False})
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "dropped"


def test_drop_plugin_tool_unavailable_no_match_vulnerability_confirmed():
    rule = DropPluginFindingWhenToolUnavailable()
    finding = _finding(category="vulnerability_confirmed", evidence={"tool_available": False})
    result = rule.evaluate(finding, [])
    assert not result.matched


def test_drop_apache_drops_on_nginx_server():
    rule = DropApacheOnNonApacheServer()
    finding = _finding(category="vulnerability_confirmed", probe_id="apache")
    all_findings = [_server_finding("nginx/1.18.0")]
    result = rule.evaluate(finding, all_findings)
    assert result.matched
    assert result.status == "dropped"
    assert "nginx" in result.reason


def test_drop_nginx_drops_on_apache_server():
    rule = DropNginxOnNonNginxServer()
    finding = _finding(category="vulnerability_confirmed", probe_id="nginx")
    all_findings = [_server_finding("apache/2.4")]
    result = rule.evaluate(finding, all_findings)
    assert result.matched
    assert result.status == "dropped"
    assert "apache" in result.reason
