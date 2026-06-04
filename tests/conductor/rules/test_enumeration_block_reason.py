"""Tests for RuleResult.evidence_gap and FilterOrchestrator evidence_gap handling (PR J)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from apps.conductor.events.bus import EventBus
from apps.conductor.orchestrators.filter import FilterOrchestrator
from apps.conductor.rules.base import RuleResult


def _finding(fid: str = "fnd-001", category: str = "service_detected", evidence: dict | None = None) -> dict:
    return {
        "id": fid,
        "category": category,
        "title": "Test Finding",
        "severity": "info",
        "description": "",
        "path": "",
        "evidence": evidence or {},
        "confidence": "medium",
        "next_actions": [],
        "probe_id": "nmap",
        "phase": "recon",
    }


def _make_filter(findings: list[dict]) -> FilterOrchestrator:
    bus = EventBus()
    mock_fo = MagicMock()
    mock_fo.list_findings.return_value = findings
    orch = FilterOrchestrator(investigation_id="inv-test", bus=bus)
    orch.wire_findings(mock_fo)
    return orch


# ── RuleResult.evidence_gap factory ──────────────────────────────────────────

def test_evidence_gap_creates_matched_result():
    result = RuleResult.evidence_gap("nmap missing service_version for 22/ssh")
    assert result.matched is True
    assert result.is_evidence_gap is True
    assert "service_version" in result.reason
    assert result.status is None
    assert result.gaps is None


def test_evidence_gap_does_not_set_status():
    result = RuleResult.evidence_gap("some reason")
    assert result.status is None


def test_normal_ruleresult_is_not_evidence_gap():
    result = RuleResult(matched=True, status="validated", reason="ok")
    assert result.is_evidence_gap is False


# ── FilterOrchestrator evidence_gap handling ──────────────────────────────────

@pytest.mark.asyncio
async def test_evidence_gap_sets_block_reason_leaves_pending():
    """When the only matching rule signals evidence_gap, finding stays pending with block_reason."""
    from apps.conductor.rules.base import RuleResult

    finding = _finding(fid="fnd-gap", category="service_detected", evidence={"service_version": "", "service": "ssh", "port": 22})
    orch = _make_filter([finding])

    block_calls: list[tuple] = []

    async def fake_block_fn(finding_id: str, reason: str) -> None:
        block_calls.append((finding_id, reason))

    orch.wire_block_reason_writer(fake_block_fn)
    await orch.run_filter()

    res = orch.get_result("fnd-gap")
    # Finding should have pending status (no classification rule matched)
    # but block_reason recorded from evidence_gap
    assert res is not None
    assert res.get("validation_status") == "pending"
    assert res.get("enumeration_block_reason") is not None
    assert "service_version" in res["enumeration_block_reason"]
    assert len(block_calls) == 1
    assert block_calls[0][0] == "fnd-gap"


@pytest.mark.asyncio
async def test_evidence_gap_block_reason_preserved_when_subsequent_rule_classifies():
    """When evidence_gap fires, chain continues; if later rule classifies, both block_reason and status are set."""
    from apps.conductor.rules.base import RuleResult

    # vulnerability_confirmed finding — ValidateVulnerabilityConfirmed will match this
    # We'll use a finding that triggers evidence_gap in one rule then gets classified by another
    finding = _finding(fid="fnd-both", category="vulnerability_confirmed", evidence={"probe_id": "nmap"})
    orch = _make_filter([finding])

    block_calls: list[tuple] = []

    async def fake_block_fn(finding_id: str, reason: str) -> None:
        block_calls.append((finding_id, reason))

    orch.wire_block_reason_writer(fake_block_fn)
    await orch.run_filter()

    res = orch.get_result("fnd-both")
    # ValidateVulnerabilityConfirmed should classify it as validated
    assert res is not None
    assert res.get("validation_status") == "validated"


@pytest.mark.asyncio
async def test_rule_chain_continues_after_evidence_gap():
    """Evidence gap does not stop rule evaluation — next rule can still match."""
    # service_detected with empty version triggers evidence_gap in ValidateServiceDetectedWithVersion
    # but no subsequent rule matches service_detected, so ends as pending
    finding = _finding(fid="fnd-chain", category="service_detected", evidence={"service_version": "", "service": "http", "port": 80})
    orch = _make_filter([finding])

    results = await orch.run_filter()
    # Should be pending (no classification matched) but gap recorded
    res = orch.get_result("fnd-chain")
    assert res is not None
    assert res.get("enumeration_block_reason") is not None


@pytest.mark.asyncio
async def test_block_reason_writer_called_with_correct_args():
    from apps.conductor.rules.base import RuleResult

    finding = _finding(fid="fnd-verify", category="service_detected", evidence={"service_version": "", "service": "telnet", "port": 23})
    orch = _make_filter([finding])

    calls: list[tuple] = []
    async def capture_fn(fid: str, reason: str) -> None:
        calls.append((fid, reason))

    orch.wire_block_reason_writer(capture_fn)
    await orch.run_filter()

    assert any(fid == "fnd-verify" for fid, _ in calls)


@pytest.mark.asyncio
async def test_no_block_reason_when_no_evidence_gap_rule_fires():
    finding = _finding(fid="fnd-clean", category="vulnerability_confirmed", evidence={})
    orch = _make_filter([finding])

    await orch.run_filter()
    res = orch.get_result("fnd-clean")
    assert res is not None
    # validated, no block_reason
    assert res.get("validation_status") == "validated"
    assert res.get("enumeration_block_reason") is None
