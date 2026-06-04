"""Tests for validate rules."""
from __future__ import annotations

from apps.conductor.rules.validate_rules import (
    ValidateCriticalNucleiFinding,
    ValidateHighRiskZapAlert,
    ValidateLoginFormWithoutCsrf,
    ValidateServiceDetectedWithVersion,
    ValidateVulnerabilityConfirmed,
)


def _finding(
    category: str = "",
    probe_id: str = "",
    severity: str = "",
    evidence: dict | None = None,
) -> dict:
    return {
        "id": "fnd-test",
        "category": category,
        "title": "",
        "severity": severity,
        "description": "",
        "path": "",
        "evidence": evidence if evidence is not None else {},
        "confidence": "",
        "next_actions": [],
        "probe_id": probe_id,
        "phase": "recon",
    }


def test_validate_vulnerability_confirmed_matches():
    rule = ValidateVulnerabilityConfirmed()
    finding = _finding(category="vulnerability_confirmed", probe_id="nmap")
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "validated"
    assert "nmap" in result.reason


def test_validate_vulnerability_confirmed_no_match_assessed():
    rule = ValidateVulnerabilityConfirmed()
    finding = _finding(category="vulnerability_assessed", probe_id="nmap")
    result = rule.evaluate(finding, [])
    assert not result.matched


def test_validate_zap_alert_high():
    rule = ValidateHighRiskZapAlert()
    finding = _finding(
        category="zap_alert",
        evidence={"risk": "High", "alert_id": "XSS"},
    )
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "validated"
    assert "XSS" in result.reason


def test_validate_zap_alert_critical():
    rule = ValidateHighRiskZapAlert()
    finding = _finding(
        category="zap_alert",
        evidence={"risk": "Critical", "alert_id": "SQLi"},
    )
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "validated"


def test_validate_zap_alert_no_match_medium():
    rule = ValidateHighRiskZapAlert()
    finding = _finding(category="zap_alert", evidence={"risk": "Medium"})
    result = rule.evaluate(finding, [])
    assert not result.matched


def test_validate_nuclei_high_severity():
    rule = ValidateCriticalNucleiFinding()
    finding = _finding(
        category="vulnerability_confirmed",
        probe_id="nuclei",
        severity="high",
        evidence={"template_id": "cve-2021-44228"},
    )
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "validated"
    assert "high" in result.reason


def test_validate_nuclei_critical_severity():
    rule = ValidateCriticalNucleiFinding()
    finding = _finding(
        category="vulnerability_confirmed",
        probe_id="nuclei",
        severity="critical",
        evidence={"template_id": "cve-2021-44228"},
    )
    result = rule.evaluate(finding, [])
    assert result.matched
    assert "critical" in result.reason


def test_validate_nuclei_no_match_medium():
    rule = ValidateCriticalNucleiFinding()
    finding = _finding(
        category="vulnerability_confirmed",
        probe_id="nuclei",
        severity="medium",
    )
    result = rule.evaluate(finding, [])
    assert not result.matched


def test_validate_login_form_no_csrf():
    rule = ValidateLoginFormWithoutCsrf()
    finding = _finding(
        category="login_form_detected",
        evidence={"detected_forms": [{"csrf_field": None}]},
    )
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "validated"


def test_validate_login_form_no_match_has_csrf():
    rule = ValidateLoginFormWithoutCsrf()
    finding = _finding(
        category="login_form_detected",
        evidence={"detected_forms": [{"csrf_field": "user_token"}]},
    )
    result = rule.evaluate(finding, [])
    assert not result.matched


def test_validate_login_form_no_match_empty_forms():
    rule = ValidateLoginFormWithoutCsrf()
    finding = _finding(
        category="login_form_detected",
        evidence={"detected_forms": []},
    )
    result = rule.evaluate(finding, [])
    assert not result.matched


def test_validate_service_detected_with_version():
    rule = ValidateServiceDetectedWithVersion()
    finding = _finding(
        category="service_detected",
        evidence={"service_version": "OpenSSH 7.4", "service": "ssh", "port": 22},
    )
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "validated"
    assert "OpenSSH" in result.reason


def test_validate_service_detected_no_match_empty_version():
    rule = ValidateServiceDetectedWithVersion()
    finding = _finding(
        category="service_detected",
        evidence={"service_version": "", "service": "ssh", "port": 22},
    )
    result = rule.evaluate(finding, [])
    assert result.matched  # evidence_gap is matched=True
    assert result.is_evidence_gap
    assert "service_version" in result.reason
