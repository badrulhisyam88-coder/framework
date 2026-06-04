"""Tests for FilterOrchestrator two-pass re-invocation (PR I)."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from apps.conductor.events.bus import EventBus
from apps.conductor.orchestrators.filter import FilterOrchestrator
from apps.conductor.rules.base import ReinvocationRequest


def _make_filter():
    bus = MagicMock(spec=EventBus)
    bus.emit = AsyncMock()
    return FilterOrchestrator(investigation_id="inv-test", bus=bus)


def _make_findings_orch(findings: list[dict]):
    fo = MagicMock()
    fo.list_findings = MagicMock(return_value=list(findings))
    return fo


def _finding(fid: str, category: str, evidence: dict | None = None, probe_id: str = ""):
    return {
        "id": fid,
        "category": category,
        "probe_id": probe_id,
        "evidence": evidence if evidence is not None else {},
        "next_actions": [],
    }


# ── wire_reinvocation_dispatcher wires correctly ──────────────────────────────

def test_wire_reinvocation_dispatcher_stores_fn():
    fo = _make_filter()
    fn = AsyncMock()
    fo.wire_reinvocation_dispatcher(fn)
    assert fo._reinvoke_fn is fn


# ── dedup logic ───────────────────────────────────────────────────────────────

def test_dedup_removes_duplicate_requests():
    req_a = ReinvocationRequest(engine_id="nmap", config={"args": "-p 22"})
    req_b = ReinvocationRequest(engine_id="nmap", config={"args": "-p 22"})
    req_c = ReinvocationRequest(engine_id="nmap", config={"args": "-p 80"})
    unique = FilterOrchestrator._dedup_requests([req_a, req_b, req_c])
    assert len(unique) == 2
    configs = [r.config["args"] for r in unique]
    assert "-p 22" in configs
    assert "-p 80" in configs


def test_dedup_different_engine_ids_not_deduped():
    req_a = ReinvocationRequest(engine_id="nmap", config={"args": "-p 22"})
    req_b = ReinvocationRequest(engine_id="ssh", config={"args": "-p 22"})
    unique = FilterOrchestrator._dedup_requests([req_a, req_b])
    assert len(unique) == 2


# ── reinvoke_fn is called when dispatcher wired ───────────────────────────────

@pytest.mark.asyncio
async def test_run_filter_calls_reinvoke_fn_for_service_detected():
    fo = _make_filter()
    dispatched = []

    async def mock_dispatch(engine_id, config):
        dispatched.append((engine_id, config))

    fo.wire_reinvocation_dispatcher(mock_dispatch)

    findings = [
        _finding("f1", "service_detected", evidence={"port": 22, "service": "ssh"}),
    ]
    fo.wire_findings(_make_findings_orch(findings))
    await fo.run_filter()

    # ReinvokeNmapNseOnOpenPort should fire for service_detected
    engine_ids = [d[0] for d in dispatched]
    assert "nmap" in engine_ids


@pytest.mark.asyncio
async def test_run_filter_reinvoke_fn_not_called_when_not_wired():
    fo = _make_filter()
    findings = [
        _finding("f1", "service_detected", evidence={"port": 22, "service": "ssh"}),
    ]
    fo.wire_findings(_make_findings_orch(findings))
    # No dispatcher wired
    await fo.run_filter()
    # service_detected with no version fires evidence_gap, so result is stored as pending with block_reason
    res = fo.get_result("f1")
    assert res is None or res.get("validation_status") == "pending"


@pytest.mark.asyncio
async def test_run_filter_second_pass_processes_new_findings():
    fo = _make_filter()
    new_finding = _finding(
        "f2", "vulnerability_assessed", evidence={"tool_available": False}
    )

    call_count = [0]

    async def mock_dispatch(engine_id, config):
        call_count[0] += 1
        # Inject a new finding after first reinvoke dispatch
        fo._findings_orch.list_findings.return_value = [
            _finding("f1", "service_detected", evidence={"port": 22, "service": "ssh"}),
            new_finding,
        ]

    fo.wire_reinvocation_dispatcher(mock_dispatch)

    findings_orch = _make_findings_orch([
        _finding("f1", "service_detected", evidence={"port": 22, "service": "ssh"}),
    ])
    fo.wire_findings(findings_orch)
    await fo.run_filter()

    # The second pass should have picked up f2
    result_f2 = fo.get_result("f2")
    assert result_f2 is not None
    assert result_f2["validation_status"] == "dropped"


@pytest.mark.asyncio
async def test_run_filter_deduplicates_reinvocations():
    fo = _make_filter()
    dispatched = []

    async def mock_dispatch(engine_id, config):
        dispatched.append((engine_id, config))

    fo.wire_reinvocation_dispatcher(mock_dispatch)

    # Two service_detected findings on port 22 — should produce 1 nmap reinvoke, not 2
    findings = [
        _finding("f1", "service_detected", evidence={"port": 22, "service": "ssh"}),
        _finding("f2", "service_detected", evidence={"port": 22, "service": "ssh"}),
    ]
    fo.wire_findings(_make_findings_orch(findings))
    await fo.run_filter()

    nmap_dispatches = [d for d in dispatched if d[0] == "nmap" and "-p 22" in d[1].get("args", "")]
    assert len(nmap_dispatches) == 1


# ── collect_reinvocations helper ──────────────────────────────────────────────

def test_collect_reinvocations_returns_requests():
    fo = _make_filter()
    findings = [
        _finding("f1", "sqli", evidence={
            "detected_login_endpoints": [{"path": "/api/login", "status_code": 200}]
        }),
    ]
    requests = fo._collect_reinvocations(findings)
    engine_ids = [r.engine_id for r in requests]
    assert "sqli_recon" in engine_ids


def test_collect_reinvocations_empty_on_no_match():
    fo = _make_filter()
    # pending finding with no matching reinvoke rule
    findings = [_finding("f1", "zap_alert", evidence={"risk": "Low"})]
    requests = fo._collect_reinvocations(findings)
    assert requests == []


# ── cancelled flag respected ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_filter_reinvoke_skipped_when_cancelled():
    fo = _make_filter()
    dispatched = []

    async def mock_dispatch(engine_id, config):
        dispatched.append(engine_id)

    fo.wire_reinvocation_dispatcher(mock_dispatch)
    fo.cancel()

    findings = [
        _finding("f1", "service_detected", evidence={"port": 22, "service": "ssh"}),
    ]
    fo.wire_findings(_make_findings_orch(findings))
    await fo.run_filter()
    assert dispatched == []
