"""Regression tests — Conductor lifecycle events (PR B.1 fix).

Proves that Conductor emits the correct top-level event for each
investigation outcome:
  - investigation_completed on successful phase traversal
  - investigation_failed   on _run_phases exception
  - investigation_cancelled on operator cancel

test_conductor_emits_investigation_completed_on_success is the primary
regression for Bug 1 discovered during the live parity gate. If the
bus event stops being emitted, this test will fail within 10s.
"""
from __future__ import annotations

import asyncio

import pytest

import apps.conductor.engines.mock  # noqa: F401 — register mock engines


def _fresh_bundle():
    from apps.conductor.events.bus import EventBus

    bus = EventBus()
    return bus


async def _wait_for(cond, *, timeout: float = 10.0, interval: float = 0.05) -> bool:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if cond():
            return True
        await asyncio.sleep(interval)
    return False


# ── Test 1: investigation_completed on success ────────────────────────────────


@pytest.mark.asyncio
async def test_conductor_emits_investigation_completed_on_success(tmp_path):
    """Conductor emits investigation_completed after all phases run.

    Uses MockEngineSimple (registered for recon, sleeps 2s then emits 3 findings).
    investigation_completed must arrive before the 10s assertion timeout.
    """
    from apps.conductor.conductor import Conductor
    from apps.conductor.events.bus import EventBus

    bus = EventBus()
    conductor = Conductor(bus=bus, db_path=tmp_path / "test.db")

    received: list[dict] = []
    bus.subscribe(received.append)

    # Exploitation phase is operator-driven; auto-complete it in the test
    async def _auto_complete_exploitation(event: dict) -> None:
        if (event.get("event_type") == "phase_started"
                and event.get("payload", {}).get("phase") == "exploitation"):
            eid = event.get("investigation_id")
            if eid:
                await conductor.operator_complete_exploitation(eid)

    bus.subscribe(_auto_complete_exploitation)

    inv_id = await conductor.start_investigation("mock://target", {"max_chain_depth": 0})

    completed = await _wait_for(
        lambda: any(
            e["event_type"] == "investigation_completed"
            and e["investigation_id"] == inv_id
            for e in received
        ),
        timeout=10.0,
    )
    assert completed, (
        f"investigation_completed not received within 10s for {inv_id}; "
        f"got event_types: {[e['event_type'] for e in received]}"
    )

    # Verify it came from the Conductor orchestrator (not just PhaseOrchestrator)
    conductor_events = [
        e for e in received
        if e["event_type"] == "investigation_completed"
        and e["investigation_id"] == inv_id
        and e["orchestrator"] == "conductor"
    ]
    assert conductor_events, (
        "investigation_completed received but not from orchestrator='conductor'; "
        "got orchestrators: "
        + str([e["orchestrator"] for e in received if e["event_type"] == "investigation_completed"])
    )


# ── Test 2: investigation_failed on _run_phases exception ────────────────────


@pytest.mark.asyncio
async def test_conductor_emits_investigation_failed_on_phase_error(tmp_path, monkeypatch):
    """Conductor emits investigation_failed when _run_phases raises.

    Note: individual engine run() failures are absorbed by the Execution
    Orchestrator (they emit engine_failed but don't propagate to _run_phases).
    This test simulates a phase-level failure by monkeypatching
    PhaseOrchestrator.start_next_phase to raise — the realistic path for
    orchestrator-internal bugs (DB errors, assertion failures, etc.).
    """
    from apps.conductor.conductor import Conductor
    from apps.conductor.events.bus import EventBus
    from apps.conductor.orchestrators.phase import PhaseOrchestrator

    async def _raise_on_first_call(self):
        raise RuntimeError("simulated phase-level failure")

    monkeypatch.setattr(PhaseOrchestrator, "start_next_phase", _raise_on_first_call)

    bus = EventBus()
    conductor = Conductor(bus=bus, db_path=tmp_path / "test.db")

    received: list[dict] = []
    bus.subscribe(received.append)

    inv_id = await conductor.start_investigation("mock://target", {"max_chain_depth": 0})

    failed = await _wait_for(
        lambda: any(
            e["event_type"] == "investigation_failed"
            and e["investigation_id"] == inv_id
            for e in received
        ),
        timeout=5.0,
    )
    assert failed, (
        f"investigation_failed not received within 5s for {inv_id}; "
        f"got event_types: {[e['event_type'] for e in received]}"
    )

    # Context state must be FAILED
    ctx = conductor.get_context(inv_id)
    assert ctx is not None
    assert ctx.state == "FAILED", f"expected FAILED, got {ctx.state}"


# ── Test 3: investigation_cancelled on operator cancel ────────────────────────


@pytest.mark.asyncio
async def test_conductor_emits_investigation_cancelled_on_cancel(tmp_path):
    """Conductor emits investigation_cancelled when operator cancels mid-run."""
    from apps.conductor.conductor import Conductor
    from apps.conductor.events.bus import EventBus

    bus = EventBus()
    conductor = Conductor(bus=bus, db_path=tmp_path / "test.db")

    received: list[dict] = []
    bus.subscribe(received.append)

    inv_id = await conductor.start_investigation("mock://target", {"max_chain_depth": 0})

    # Wait for engine to start (MockEngineSimple sleeps 2s — give it a moment)
    started = await _wait_for(
        lambda: any(e["event_type"] == "engine_started" for e in received),
        timeout=5.0,
    )
    assert started, "engine never started"

    await asyncio.sleep(0.2)  # engines are in their 2s sleep
    await conductor.cancel_investigation(inv_id)

    cancelled = await _wait_for(
        lambda: any(
            e["event_type"] == "investigation_cancelled"
            and e["investigation_id"] == inv_id
            for e in received
        ),
        timeout=5.0,
    )
    assert cancelled, (
        f"investigation_cancelled not received for {inv_id}; "
        f"got event_types: {[e['event_type'] for e in received]}"
    )

    ctx = conductor.get_context(inv_id)
    assert ctx is not None
    assert ctx.state == "CANCELLED", f"expected CANCELLED, got {ctx.state}"
