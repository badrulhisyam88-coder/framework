"""Tests for workspace-data.json validation status fields (PR J)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.investigation_workspace.aggregations import _build_aggregations, _dominant_validation


# ── _dominant_validation helper ───────────────────────────────────────────────

def test_dominant_all_dropped():
    findings = [
        {"validation_status": "dropped", "validation_reason": "non-wordpress server", "enumeration_gaps": []},
        {"validation_status": "dropped", "validation_reason": "non-wordpress server", "enumeration_gaps": []},
    ]
    status, reason, gaps = _dominant_validation(findings)
    assert status == "dropped"
    assert gaps == []


def test_dominant_any_validated():
    findings = [
        {"validation_status": "validated", "validation_reason": "ok", "enumeration_gaps": []},
        {"validation_status": "pending", "validation_reason": None, "enumeration_gaps": []},
    ]
    status, reason, gaps = _dominant_validation(findings)
    assert status == "validated"


def test_dominant_any_incomplete():
    findings = [
        {"validation_status": "incomplete", "validation_reason": "needs creds", "enumeration_gaps": ["credentials_needed"]},
        {"validation_status": "pending", "validation_reason": None, "enumeration_gaps": []},
    ]
    status, reason, gaps = _dominant_validation(findings)
    assert status == "incomplete"
    assert "credentials_needed" in gaps


def test_dominant_all_pending():
    findings = [
        {"validation_status": "pending", "validation_reason": None, "enumeration_gaps": []},
    ]
    status, reason, gaps = _dominant_validation(findings)
    assert status == "pending"


def test_dominant_incomplete_dedupes_gaps():
    findings = [
        {"validation_status": "incomplete", "validation_reason": "r1", "enumeration_gaps": ["session_needed", "credentials_needed"]},
        {"validation_status": "incomplete", "validation_reason": "r2", "enumeration_gaps": ["session_needed"]},
    ]
    _, _, gaps = _dominant_validation(findings)
    assert gaps.count("session_needed") == 1


# ── _build_aggregations card includes validation fields ───────────────────────

def _make_finding(fid: str, ftype: str, **kwargs) -> dict:
    return {
        "finding_id": fid,
        "finding_type": ftype,
        "title": f"Finding {fid}",
        "description": "",
        "severity": "info",
        "endpoint": "",
        "raw_data": {"_phase": "recon"},
        "validation_status": "pending",
        "validation_reason": None,
        "enumeration_gaps": [],
        **kwargs,
    }


def test_catch_all_card_includes_validation_status():
    f1 = _make_finding("f1", "service_detected", validation_status="validated", validation_reason="version found")
    cards = _build_aggregations("recon", ["f1"], {"f1": f1})
    assert cards
    card = cards[0]
    assert "validation_status" in card
    assert card["validation_status"] == "validated"


def test_catch_all_card_incomplete_has_gaps():
    f1 = _make_finding("f1", "service_detected", validation_status="incomplete", enumeration_gaps=["session_needed"])
    cards = _build_aggregations("recon", ["f1"], {"f1": f1})
    card = cards[0]
    assert card["validation_status"] == "incomplete"
    assert "session_needed" in card["enumeration_gaps"]


def test_pending_finding_card_has_pending_status():
    f1 = _make_finding("f1", "some_type")
    cards = _build_aggregations("recon", ["f1"], {"f1": f1})
    card = cards[0]
    assert card["validation_status"] == "pending"


def test_security_headers_card_includes_validation_status():
    f1 = _make_finding("f1", "missing_csp_header", validation_status="validated")
    f2 = _make_finding("f2", "missing_hsts_header", validation_status="pending")
    cards = _build_aggregations("recon", ["f1", "f2"], {"f1": f1, "f2": f2})
    header_cards = [c for c in cards if c.get("kind") == "security_headers"]
    assert header_cards
    card = header_cards[0]
    assert "validation_status" in card
    # f1 is validated, so dominant = validated
    assert card["validation_status"] == "validated"


# ── workspace-data.json excludes dropped by default ──────────────────────────

def test_dominant_validation_dropped_not_present_in_mixed():
    """When not all are dropped, dropped status does NOT dominate."""
    findings = [
        {"validation_status": "dropped", "validation_reason": "dead end", "enumeration_gaps": []},
        {"validation_status": "validated", "validation_reason": "ok", "enumeration_gaps": []},
    ]
    status, _, _ = _dominant_validation(findings)
    assert status == "validated"  # validated wins over mixed dropped


def test_build_aggregations_empty_findings_by_id():
    """_build_aggregations handles missing finding IDs gracefully."""
    cards = _build_aggregations("recon", ["missing-id"], {})
    assert cards == []
