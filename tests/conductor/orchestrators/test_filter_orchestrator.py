"""Tests for FilterOrchestrator."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.conductor.events.bus import EventBus
from apps.conductor.orchestrators.filter import FilterOrchestrator


def _finding(
    fid: str = "fnd-001",
    category: str = "vulnerability_confirmed",
    evidence: dict | None = None,
    probe_id: str = "nmap",
    severity: str = "high",
) -> dict:
    return {
        "id": fid,
        "category": category,
        "title": "Test Finding",
        "severity": severity,
        "description": "",
        "path": "",
        "evidence": evidence if evidence is not None else {},
        "confidence": "high",
        "next_actions": [],
        "probe_id": probe_id,
        "phase": "recon",
    }


def _make_filter_orch(findings: list[dict]) -> tuple[FilterOrchestrator, MagicMock]:
    bus = EventBus()
    mock_findings_orch = MagicMock()
    mock_findings_orch.list_findings.return_value = findings
    orch = FilterOrchestrator(investigation_id="inv-test", bus=bus)
    orch.wire_findings(mock_findings_orch)
    return orch, mock_findings_orch


@pytest.mark.asyncio
async def test_filter_runs_on_recon_findings():
    finding = _finding()
    orch, _ = _make_filter_orch([finding])
    result = await orch.run_filter()
    assert result is not None


@pytest.mark.asyncio
async def test_filter_updates_finding_to_validated():
    finding = _finding(fid="fnd-001", category="vulnerability_confirmed", probe_id="nmap")
    orch, _ = _make_filter_orch([finding])
    await orch.run_filter()
    res = orch.get_result("fnd-001")
    assert res is not None
    assert res["validation_status"] == "validated"
    assert res["validation_reason"]


@pytest.mark.asyncio
async def test_filter_updates_finding_to_dropped():
    finding = _finding(
        fid="fnd-002",
        category="sqli",
        evidence={"detected_login_endpoints": []},
        probe_id="sqli_recon",
    )
    orch, _ = _make_filter_orch([finding])
    await orch.run_filter()
    res = orch.get_result("fnd-002")
    assert res is not None
    assert res["validation_status"] == "dropped"


@pytest.mark.asyncio
async def test_filter_updates_finding_to_incomplete():
    finding = _finding(
        fid="fnd-003",
        category="login_form_detected",
        evidence={"detected_forms": [{"csrf_field": "user_token"}]},
        probe_id="auth_recon",
    )
    orch, _ = _make_filter_orch([finding])
    await orch.run_filter()
    res = orch.get_result("fnd-003")
    assert res is not None
    assert res["validation_status"] == "incomplete"
    import json
    gaps = json.loads(res["enumeration_gaps"])
    assert "csrf_token_needed" in gaps


@pytest.mark.asyncio
async def test_filter_leaves_unmatched_findings_as_no_result():
    finding = _finding(
        fid="fnd-004",
        category="some_unknown_type_xyz",
        evidence={},
        probe_id="unknown",
    )
    orch, _ = _make_filter_orch([finding])
    await orch.run_filter()
    assert orch.get_result("fnd-004") is None


@pytest.mark.asyncio
async def test_filter_first_match_wins():
    # drop_sqli_with_empty_endpoints fires before incomplete_sqli_auth_required
    finding = _finding(
        fid="fnd-005",
        category="sqli",
        evidence={"detected_login_endpoints": [], "auth_required": True},
        probe_id="sqli_recon",
    )
    orch, _ = _make_filter_orch([finding])
    await orch.run_filter()
    res = orch.get_result("fnd-005")
    assert res is not None
    assert res["validation_status"] == "dropped"


@pytest.mark.asyncio
async def test_filter_emits_completion_event():
    finding = _finding()
    bus = EventBus()
    mock_findings_orch = MagicMock()
    mock_findings_orch.list_findings.return_value = [finding]
    orch = FilterOrchestrator(investigation_id="inv-evt", bus=bus)
    orch.wire_findings(mock_findings_orch)

    emitted_events: list[dict] = []
    bus.subscribe(emitted_events.append)

    await orch.run_filter()

    event_types = [e["event_type"] for e in emitted_events]
    assert "filter_phase_completed" in event_types

    completed = next(e for e in emitted_events if e["event_type"] == "filter_phase_completed")
    assert "counts" in completed["payload"]


@pytest.mark.asyncio
async def test_filter_handles_rule_evaluation_error():
    finding = _finding(fid="fnd-007", category="vulnerability_confirmed")
    good_finding = _finding(fid="fnd-008", category="vulnerability_confirmed", probe_id="ssh")

    bus = EventBus()
    mock_findings_orch = MagicMock()
    mock_findings_orch.list_findings.return_value = [finding, good_finding]
    orch = FilterOrchestrator(investigation_id="inv-err", bus=bus)
    orch.wire_findings(mock_findings_orch)

    bad_rule = MagicMock()
    bad_rule.id = "bad_rule"
    bad_rule.evaluate.side_effect = RuntimeError("rule exploded")

    with patch("apps.conductor.orchestrators.filter.REGISTERED_RULES", [bad_rule]):
        counts = await orch.run_filter()

    # Should not raise; both findings land as pending/error
    assert counts is not None
    assert counts.get("error", 0) + counts.get("pending", 0) >= 1


@pytest.mark.asyncio
async def test_filter_calls_db_writer_for_classified_findings():
    finding = _finding(fid="fnd-009", category="vulnerability_confirmed", probe_id="nmap")
    orch, _ = _make_filter_orch([finding])

    update_fn = AsyncMock()
    orch.wire_db_writer(update_fn)

    await orch.run_filter()

    update_fn.assert_called_once()
    call_args = update_fn.call_args[0]
    assert call_args[0] == "fnd-009"
    assert call_args[1] == "validated"


@pytest.mark.asyncio
async def test_filter_cancellation():
    finding = _finding(fid="fnd-010", category="vulnerability_confirmed")
    bus = EventBus()
    mock_findings_orch = MagicMock()
    mock_findings_orch.list_findings.return_value = [finding]
    orch = FilterOrchestrator(investigation_id="inv-cancel", bus=bus)
    orch.wire_findings(mock_findings_orch)

    emitted_events: list[dict] = []
    bus.subscribe(emitted_events.append)

    orch.cancel()
    await orch.run_filter()

    event_types = [e["event_type"] for e in emitted_events]
    assert "filter_phase_cancelled" in event_types
