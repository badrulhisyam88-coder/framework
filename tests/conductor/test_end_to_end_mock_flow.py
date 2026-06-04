"""Integration test — PR A end-to-end mock flow verification.

Covers all 10 assertions specified in the PR A prompt:
  1. start_investigation returns id; SQLite row exists
  2. Phase progression: RECON_RUNNING → RECON_COMPLETE
  3. Findings ingress: 5 unique findings from 2 engines
  4. Dedup: same finding_id → not double-counted
  5. Chain depth limit: cycle halts at max_depth
  6. Chain dispatch: mock_simple is auto-fired from mock_chained
  7. Cancellation: engines cancelled within 5s
  8. OutputChannel → SessionOrchestrator: request count > 0
  9. Event bus delivers expected event types
  10. Existing investigation_workspace probes import cleanly

Uses a temp-dir SQLite db so tests don't dirty data/orchestration.db.
"""
from __future__ import annotations

import asyncio
import sqlite3
import tempfile
from collections import Counter
from pathlib import Path

import pytest

from apps.conductor.conductor import Conductor
from apps.conductor.engines.mock import MockEngineChained, MockEngineSimple
from apps.conductor.events.bus import EventBus

# ── helpers ──────────────────────────────────────────────────────────────────


def fresh_bus() -> EventBus:
    return EventBus()


async def _wait_for(cond, *, timeout: float = 10.0, interval: float = 0.1) -> bool:
    """Poll *cond* every *interval* seconds until True or *timeout* elapses."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if cond():
            return True
        await asyncio.sleep(interval)
    return False


# ── fixture: conductor with temp db ──────────────────────────────────────────


@pytest.fixture
async def conductor_bundle():
    """Yield (conductor, bus, db_path) with isolated SQLite + fresh event bus."""
    bus = fresh_bus()
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "orchestration.db"
        conductor = Conductor(bus=bus, db_path=db_path)
        yield conductor, bus, db_path


# ── Test 1: start_investigation + SQLite row ──────────────────────────────────


@pytest.mark.asyncio
async def test_start_investigation_returns_id(conductor_bundle):
    conductor, bus, db_path = conductor_bundle
    inv_id = await conductor.start_investigation("mock://target", {})
    assert isinstance(inv_id, str) and len(inv_id) > 0

    # Give background tasks a moment to settle
    await asyncio.sleep(0.1)

    conn = sqlite3.connect(str(db_path))
    sql = "SELECT id, target, state FROM investigations WHERE id=?"
    row = conn.execute(sql, (inv_id,)).fetchone()
    conn.close()
    assert row is not None
    assert row[1] == "mock://target"


# ── Test 2: phase progression ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_phase_progression_recon_to_complete(conductor_bundle):
    conductor, bus, db_path = conductor_bundle

    phase_events: list[str] = []

    def on_event(e):
        if e["event_type"] in ("phase_started", "phase_completed"):
            phase_events.append(e["event_type"])

    bus.subscribe(on_event)

    await conductor.start_investigation("mock://target", {})

    # Wait up to 10s for recon to complete (mock engines sleep 2s)
    completed = await _wait_for(lambda: "phase_completed" in phase_events, timeout=10.0)
    assert completed, f"phase_completed not received within 10s; got: {phase_events}"
    assert "phase_started" in phase_events


# ── Test 3: findings ingress count ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_findings_ingress_count(conductor_bundle):
    conductor, bus, db_path = conductor_bundle

    received: list[str] = []
    bus.subscribe(lambda e: received.append(e["event_type"]))

    inv_id = await conductor.start_investigation("mock://target", {})

    completed = await _wait_for(lambda: "phase_completed" in received, timeout=10.0)
    assert completed, f"phase_completed not received; got: {received}"

    ctx = conductor.get_context(inv_id)
    findings = ctx.findings_orch.list_findings()
    # MockEngineSimple: 3, MockEngineChained: 2 = 5 before any chain dispatch
    assert len(findings) >= 5, f"expected >=5 unique findings, got {len(findings)}"


# ── shared event collector approach ──────────────────────────────────────────


async def _run_investigation_collect_events(
    conductor: Conductor,
    bus: EventBus,
    target: str = "mock://target",
    config: dict | None = None,
) -> tuple[str, list[dict]]:
    events: list[dict] = []
    bus.subscribe(events.append)
    # max_chain_depth=2 makes the cycle hit the depth limit in ~4-6s total
    inv_config = config if config is not None else {"max_chain_depth": 2}
    inv_id = await conductor.start_investigation(target, inv_config)
    # Wait for phase_completed (mock engines sleep 2s → phase done ~2s)
    await _wait_for(
        lambda: any(e["event_type"] == "phase_completed" for e in events),
        timeout=10.0,
    )
    # Wait for chain to cycle and hit depth limit (max_chain_depth=2 → ~4-6s more)
    await _wait_for(
        lambda: any(e["event_type"] == "chain_depth_exceeded" for e in events),
        timeout=10.0,
    )
    # Brief settle for any trailing events
    await asyncio.sleep(0.3)
    return inv_id, events


# ── Test 3 (revised) + 4 + 5 + 6 + 8 + 9 in one investigation run ────────────


@pytest.mark.asyncio
async def test_full_flow(conductor_bundle):
    conductor, bus, db_path = conductor_bundle
    inv_id, events = await _run_investigation_collect_events(conductor, bus)

    ctx = conductor.get_context(inv_id)
    findings = ctx.findings_orch.list_findings()
    event_types = [e["event_type"] for e in events]
    counts = Counter(event_types)

    # ── Test 3: findings count ───────────────────────────────────────────────
    # 5 direct findings + chain dispatch fires mock_simple again (3 more)
    # Dedup of fnd_mock_chained_cycle should absorb the cyclic re-emission
    assert len(findings) >= 5, f"expected >=5 findings, got {len(findings)}"

    # ── Test 4: dedup ────────────────────────────────────────────────────────
    # finding_updated events signal dedup fired; or finding IDs are unique
    finding_ids = [f["id"] for f in findings]
    assert len(finding_ids) == len(set(finding_ids)), "duplicate finding IDs in store"

    # ── Test 5: chain depth limit ────────────────────────────────────────────
    exceeded = [e for e in events if e["event_type"] == "chain_depth_exceeded"]
    assert len(exceeded) > 0, "chain_depth_exceeded event never fired (cycle not stopped)"

    # ── Test 6: chain dispatch ───────────────────────────────────────────────
    auto_fired = [e for e in events if e["event_type"] == "chain_auto_fired"]
    # At least one auto-fire should have happened (for mock_simple from chain finding)
    assert len(auto_fired) > 0, "chain_auto_fired never emitted"

    # ── Test 8: request count > 0 ────────────────────────────────────────────
    req_count = ctx.session_orch.get_request_count("mock://test")
    assert req_count > 0, "SessionOrchestrator recorded no requests"

    # ── Test 9: event bus events ─────────────────────────────────────────────
    required_events = {
        "investigation_started",
        "phase_started",
        "engine_started",
        "finding_ingested",
        "phase_completed",
    }
    received = set(event_types)
    missing = required_events - received
    assert not missing, f"missing expected event types: {missing}"

    n_started = counts["engine_started"]
    n_ingested = counts["finding_ingested"]
    assert n_started >= 2, f"expected >=2 engine_started, got {n_started}"
    assert n_ingested >= 5, f"expected >=5 finding_ingested, got {n_ingested}"


# ── Test 7: cancellation ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cancellation(conductor_bundle):
    conductor, bus, db_path = conductor_bundle
    events: list[dict] = []
    bus.subscribe(events.append)

    inv_id = await conductor.start_investigation("mock://target", {})

    # Wait for engines to start
    started = await _wait_for(
        lambda: any(e["event_type"] == "engine_started" for e in events),
        timeout=5.0,
    )
    assert started, "engines never started"

    await asyncio.sleep(0.5)  # let engines get into their sleep

    await conductor.cancel_investigation(inv_id)

    # Wait for cancellation events
    await asyncio.sleep(1.0)

    ctx = conductor.get_context(inv_id)
    assert ctx.state == "CANCELLED"

    cancelled_events = [e for e in events if "cancel" in e["event_type"]]
    assert len(cancelled_events) > 0, "no cancellation events emitted"


# ── Test 10: existing probe imports unbroken ──────────────────────────────────


def test_existing_workspace_bootstrap_imports():
    from apps.investigation_workspace.bootstrap.runtime import _runner

    assert callable(_runner)


def test_existing_workspace_probe_events_import():
    from apps.investigation_workspace.probe.events import FindingEvent, StageEvent

    assert FindingEvent is not None
    assert StageEvent is not None


def test_existing_passive_probe_import():
    from apps.investigation_workspace.probe.passive import run_passive_probe

    assert callable(run_passive_probe)


@pytest.mark.asyncio
async def test_existing_passive_probe_runs_and_emits():
    """Passive probe against an unreachable target should fail-close without crashing."""
    from apps.investigation_workspace.probe.passive import run_passive_probe

    events = []
    async for event in run_passive_probe("http://127.0.0.1:1"):
        events.append(event)

    # Probe must emit at least one StageEvent even on connection failure
    from apps.investigation_workspace.probe.events import StageEvent

    assert any(isinstance(e, StageEvent) for e in events), \
        "passive_probe emitted nothing — regression in existing probe path"


# ── Engine-level unit checks ──────────────────────────────────────────────────


def test_mock_engine_simple_registration():
    from apps.conductor.engines.base import engine_registry

    engine = engine_registry.get("mock_simple")
    assert engine is not None
    assert "recon" in engine.capabilities.phases


def test_mock_engine_chained_registration():
    from apps.conductor.engines.base import engine_registry

    engine = engine_registry.get("mock_chained")
    assert engine is not None
    assert "recon" in engine.capabilities.phases


def test_conductor_import():
    from apps.conductor.conductor import Conductor

    assert Conductor is not None
    assert MockEngineSimple is not None
    assert MockEngineChained is not None
    print("OK")
