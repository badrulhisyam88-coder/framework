"""Tests for incomplete rules."""
from __future__ import annotations

from apps.conductor.rules.incomplete_rules import (
    IncompleteApiExposureAuthUnknown,
    IncompleteCmdiAuthRequired,
    IncompleteLoginFormWithCsrf,
    IncompletePluginMissingTool,
    IncompleteSqliAuthRequired,
    IncompleteZapAlertMediumRisk,
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


def test_incomplete_login_form_csrf_present():
    rule = IncompleteLoginFormWithCsrf()
    finding = _finding(
        category="login_form_detected",
        evidence={"detected_forms": [{"csrf_field": "user_token"}]},
    )
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "incomplete"
    assert result.gaps == ["csrf_token_needed"]


def test_incomplete_login_form_no_match_no_csrf():
    rule = IncompleteLoginFormWithCsrf()
    finding = _finding(
        category="login_form_detected",
        evidence={"detected_forms": [{"csrf_field": None}]},
    )
    result = rule.evaluate(finding, [])
    assert not result.matched


def test_incomplete_sqli_auth_required():
    rule = IncompleteSqliAuthRequired()
    finding = _finding(
        category="sqli",
        evidence={"auth_required": True, "detected_login_endpoints": [{"path": "/login"}]},
    )
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "incomplete"
    assert "session_needed" in result.gaps


def test_incomplete_sqli_no_match_not_auth_required():
    rule = IncompleteSqliAuthRequired()
    finding = _finding(
        category="sqli",
        evidence={"auth_required": False},
    )
    result = rule.evaluate(finding, [])
    assert not result.matched


def test_incomplete_cmdi_auth_required():
    rule = IncompleteCmdiAuthRequired()
    finding = _finding(
        category="command_injection",
        evidence={"auth_required": True},
    )
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "incomplete"


def test_incomplete_cmdi_no_match_not_auth_required():
    rule = IncompleteCmdiAuthRequired()
    finding = _finding(
        category="command_injection",
        evidence={"auth_required": False},
    )
    result = rule.evaluate(finding, [])
    assert not result.matched


def test_incomplete_plugin_missing_tool_vulnerability_confirmed():
    rule = IncompletePluginMissingTool()
    finding = _finding(
        category="vulnerability_confirmed",
        evidence={"tool_available": False},
    )
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "incomplete"
    assert "tool_missing" in result.gaps


def test_incomplete_plugin_no_match_vulnerability_assessed():
    rule = IncompletePluginMissingTool()
    finding = _finding(
        category="vulnerability_assessed",
        evidence={"tool_available": False},
    )
    result = rule.evaluate(finding, [])
    assert not result.matched


def test_incomplete_api_exposure_401():
    rule = IncompleteApiExposureAuthUnknown()
    finding = _finding(
        category="api_exposure",
        evidence={
            "hit_paths": [{"path": "/api", "status_code": 401, "content_type": "application/json"}]
        },
    )
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "incomplete"
    assert "session_needed" in result.gaps


def test_incomplete_api_exposure_403():
    rule = IncompleteApiExposureAuthUnknown()
    finding = _finding(
        category="api_exposure",
        evidence={
            "hit_paths": [{"path": "/admin", "status_code": 403, "content_type": "text/html"}]
        },
    )
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "incomplete"


def test_incomplete_api_exposure_no_match_200_only():
    rule = IncompleteApiExposureAuthUnknown()
    finding = _finding(
        category="api_exposure",
        evidence={
            "hit_paths": [
                {"path": "/api/v1", "status_code": 200, "content_type": "application/json"},
                {"path": "/api/v2", "status_code": 200, "content_type": "application/json"},
            ]
        },
    )
    result = rule.evaluate(finding, [])
    assert not result.matched


def test_incomplete_zap_alert_medium():
    rule = IncompleteZapAlertMediumRisk()
    finding = _finding(
        category="zap_alert",
        evidence={"risk": "Medium", "alert_id": "CSRF"},
    )
    result = rule.evaluate(finding, [])
    assert result.matched
    assert result.status == "incomplete"
    assert "CSRF" in result.reason
    assert "exploit_validation_needed" in result.gaps


def test_incomplete_zap_alert_no_match_low():
    rule = IncompleteZapAlertMediumRisk()
    finding = _finding(
        category="zap_alert",
        evidence={"risk": "Low", "alert_id": "info-leak"},
    )
    result = rule.evaluate(finding, [])
    assert not result.matched
