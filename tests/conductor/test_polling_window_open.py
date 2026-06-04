"""Regression tests — Conductor polling window (Bug 3 fix).

Proves that is_recon_active() returns True DURING a Conductor-path
investigation (so the frontend polling loop stays alive) and False
after it completes.

Bug 3 root cause: run.recon_run was created post-completion with
completed_at already set, so is_recon_active() was False from the
first poll onward. Fix: create the stub with completed_at=None before
Conductor starts; mutate it to a timestamp after done.wait() resolves.
"""
from __future__ import annotations

import asyncio
import time
import uuid

import pytest

import apps.conductor.engines.mock  # noqa: F401 — register mock engines

# ── helpers ──────────────────────────────────────────────────────────────────


async def _wait_for(cond, *, timeout: float = 10.0, interval: float = 0.05) -> bool:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if cond():
            return True
        await asyncio.sleep(interval)
    return False


def _make_phased_run(investigation_id: str, target: str):
    """Create a minimal PhasedRun as runtime.kick_off would."""
    from apps.investigation_workspace.bootstrap.runtime import PhasedRun
    return PhasedRun(
        investigation_id=investigation_id,
        target=target,
        started_at=time.time(),
    )


# ── Test 1: is_recon_active() is True during, False after ───────────────────


@pytest.mark.asyncio
async def test_recon_active_true_during_parallel_track_investigation(tmp_path):
    """is_recon_active() returns True while Conductor is running, False after.

    MockEngineSimple sleeps 2s then emits 3 findings — gives us a
    reliable window to assert the mid-run state.

    run must be registered in _RUNS (as kick_off does) so is_recon_active()
    can look it up by investigation_id.
    """
    from apps.conductor.conductor import Conductor
    from apps.conductor.events.bus import EventBus
    from apps.investigation_workspace.bootstrap.runtime import (
        _RUNS,
        _run_all_probes_via_conductor,
        is_recon_active,
    )

    bus = EventBus()
    conductor = Conductor(bus=bus, db_path=tmp_path / "test.db")

    inv_id = uuid.uuid4().hex
    run = _make_phased_run(inv_id, "mock://target")

    # Register so is_recon_active() can find the run (kick_off does this)
    _RUNS[inv_id] = run

    import apps.conductor.shared as _shared
    original = _shared._conductor
    _shared._conductor = conductor

    # Exploitation phase is operator-driven; auto-complete it in the test
    async def _auto_complete_exploitation(event: dict) -> None:
        if (event.get("event_type") == "phase_started"
                and event.get("payload", {}).get("phase") == "exploitation"):
            eid = event.get("investigation_id")
            if eid:
                await conductor.operator_complete_exploitation(eid)

    handle = bus.subscribe(_auto_complete_exploitation)
    try:
        task = asyncio.create_task(
            _run_all_probes_via_conductor(run, "mock://target", None)
        )

        # Within 500ms: recon stub must be live (completed_at=None)
        active = await _wait_for(lambda: is_recon_active(inv_id), timeout=0.5)
        assert active, (
            "is_recon_active() was not True within 500ms of parallel-track start; "
            f"run.recon_run={run.recon_run}"
        )

        await asyncio.wait_for(task, timeout=15.0)

        # After completion: recon stub must be marked done
        assert not is_recon_active(inv_id), (
            "is_recon_active() still True after _run_all_probes_via_conductor returned; "
            "run.recon_run.completed_at="
            + str(run.recon_run.completed_at if run.recon_run else None)
        )
    finally:
        handle.cancel()
        _shared._conductor = original
        _RUNS.pop(inv_id, None)


# ── Test 2: PhaseRun fields populated correctly throughout ──────────────────


@pytest.mark.asyncio
async def test_phased_run_fields_populated_correctly_throughout(tmp_path):
    """recon_run.completed_at=None mid-run; all fields set after completion."""
    from apps.conductor.conductor import Conductor
    from apps.conductor.events.bus import EventBus
    from apps.investigation_workspace.bootstrap.runtime import (
        _RUNS,
        _run_all_probes_via_conductor,
    )

    bus = EventBus()
    conductor = Conductor(bus=bus, db_path=tmp_path / "test.db")

    inv_id = uuid.uuid4().hex
    run = _make_phased_run(inv_id, "mock://target")
    _RUNS[inv_id] = run

    import apps.conductor.shared as _shared
    original = _shared._conductor
    _shared._conductor = conductor

    # Exploitation phase is operator-driven; auto-complete it in the test
    async def _auto_complete_exploitation(event: dict) -> None:
        if (event.get("event_type") == "phase_started"
                and event.get("payload", {}).get("phase") == "exploitation"):
            eid = event.get("investigation_id")
            if eid:
                await conductor.operator_complete_exploitation(eid)

    handle = bus.subscribe(_auto_complete_exploitation)
    try:
        task = asyncio.create_task(
            _run_all_probes_via_conductor(run, "mock://target", None)
        )

        # Mid-investigation: stub is live, completed_at is None
        mid_run_ok = await _wait_for(
            lambda: run.recon_run is not None and run.recon_run.completed_at is None,
            timeout=0.5,
        )
        assert mid_run_ok, (
            "Mid-run: run.recon_run was not live (completed_at=None) within 500ms; "
            f"recon_run={run.recon_run}"
        )

        await asyncio.wait_for(task, timeout=15.0)

        # Post-completion: all three fields must be non-None timestamps
        assert run.recon_run is not None, "run.recon_run is None after completion"
        assert run.recon_run.completed_at is not None, (
            "run.recon_run.completed_at is None after completion"
        )
        assert run.enumeration_run is not None, "run.enumeration_run is None after completion"
        assert run.enumeration_run.completed_at is not None, (
            "run.enumeration_run.completed_at is None after completion"
        )
        assert run.completed_at is not None, "run.completed_at is None after completion"
    finally:
        handle.cancel()
        _shared._conductor = original
        _RUNS.pop(inv_id, None)
