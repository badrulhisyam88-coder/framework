"""Bootstrap runtime — Conductor-path execution.

Lifecycle:
    kick_off(inv_id, target)     → PhasedRun created
    All bootstrap probes dispatched via shared Conductor singleton
    completed_at set when investigation completes

In-memory, module-level state. Single uvicorn worker. Restart wipes
in-flight runs; persisted findings survive.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from apps.investigation_workspace.probe.events import FindingEvent


# ── Run records ─────────────────────────────────────────────────────────


@dataclass
class StageState:
    """A reasoning node in the bootstrap timeline.

    Phase 43 — stages now carry their reasoning record so the context
    panel can render `actions / tools / detected / confidence / spawned`
    when the operator expands the node. spawned is a list of node ids
    this stage caused (e.g., a finding's node_id once it persists).

    Item 7/8 — probe_name identifies which parallel probe emitted this
    stage so the workspace data builder can group stages into columns.
    """
    label:        str
    started_at:   float
    completed_at: float | None = None
    actions:      tuple[str, ...] = ()
    tools:        tuple[str, ...] = ()
    detected:     tuple[str, ...] = ()
    confidence:   str             = "—"
    spawned:      list[str]       = field(default_factory=list)
    probe_name:   str             = ""  # which probe emitted this stage


@dataclass
class DiscoveryState:
    """A finding the bootstrap persisted, kept here for overlay display.

    Phase 44 — the spec is now the FindingEvent emitted by the live probe.
    """
    spec:        FindingEvent
    finding_id:  str
    emitted_at:  float


@dataclass
class PhaseRun:
    """One execution phase (Recon or Enumeration)."""
    run_id:       str
    phase:        str   # "recon" | "enumeration"
    started_at:   float
    completed_at: float | None = None
    stages:       list[StageState]     = field(default_factory=list)
    discoveries:  list[DiscoveryState] = field(default_factory=list)


@dataclass
class PhasedRun:
    """Per-investigation phased bootstrap run.

    recon_run is set when Recon phase begins.
    enumeration_run is set when Enumeration phase begins.
    exploitation_run is set when Exploitation phase begins (V2.1 Step 3 fix).
    completed_at is set when all phases complete.
    """
    investigation_id: str
    target:          str
    started_at:      float
    completed_at:    float | None = None
    recon_run:       PhaseRun | None = None
    enumeration_run: PhaseRun | None = None
    exploitation_run: PhaseRun | None = None


_RUNS: dict[str, PhasedRun] = {}


# ── Public API ──────────────────────────────────────────────────────────


def get_run(investigation_id: str) -> PhasedRun | None:
    return _RUNS.get(investigation_id)


def is_active(investigation_id: str) -> bool:
    """True while any phase is still running."""
    run = _RUNS.get(investigation_id)
    if run is None:
        return False
    if run.recon_run and run.recon_run.completed_at is None:
        return True
    if run.enumeration_run and run.enumeration_run.completed_at is None:
        return True
    if run.exploitation_run and run.exploitation_run.completed_at is None:
        return True
    return False


def is_visible(investigation_id: str) -> bool:
    """True while PhasedRun exists in memory."""
    return _RUNS.get(investigation_id) is not None


def is_recon_active(investigation_id: str) -> bool:
    """True while the Recon phase is running."""
    run = _RUNS.get(investigation_id)
    return (run is not None and run.recon_run is not None
            and run.recon_run.completed_at is None)


def is_enumeration_active(investigation_id: str) -> bool:
    """True while the Enumeration phase is running."""
    run = _RUNS.get(investigation_id)
    return (run is not None and run.enumeration_run is not None
            and run.enumeration_run.completed_at is None)


def is_exploitation_active(investigation_id: str) -> bool:
    """True while the Exploitation phase is running (operator has not yet marked done)."""
    run = _RUNS.get(investigation_id)
    return (run is not None and run.exploitation_run is not None
            and run.exploitation_run.completed_at is None)


async def kick_off(
    *,
    investigation_id: str,
    target:           str,
    persist_finding:  Callable[[FindingEvent], Awaitable[str | None]] | None = None,
    lifecycle_fn:     Callable[[bool], Awaitable[None]] | None = None,
) -> PhasedRun:
    existing = _RUNS.get(investigation_id)
    if existing is not None:
        return existing

    from sdk import Logger
    Logger.info(
        "bootstrap.kick_off",
        extra={
            "investigation_id": investigation_id,
            "canonical_target": target,
            "stage":            "bootstrap",
        },
    )

    run = PhasedRun(
        investigation_id = investigation_id,
        target           = target,
        started_at       = time.time(),
    )
    _RUNS[investigation_id] = run
    asyncio.create_task(_runner(run, target, persist_finding, lifecycle_fn))
    return run


# ── Internal driver ─────────────────────────────────────────────────────


def _apply_phase_event(run: PhasedRun, event_type: str, phase: str) -> None:
    """Apply a phase bus event to PhasedRun in-memory state.

    Extracted at module level so Pattern 13 seam tests can call it directly
    without requiring a full Conductor integration. `_on_event` delegates here
    for all phase_started / phase_completed events.

    phase_started(enumeration)  → creates enumeration_run (completed_at=None)
    phase_started(exploitation) → creates exploitation_run (completed_at=None)
    phase_completed(recon)       → writes recon_run.completed_at (idempotent)
    phase_completed(enumeration) → writes enumeration_run.completed_at (idempotent)
    phase_completed(exploitation)→ writes exploitation_run.completed_at (idempotent)
    """
    now = time.time()
    if event_type == "phase_started":
        if phase == "enumeration":
            run.enumeration_run = PhaseRun(
                run_id=uuid.uuid4().hex[:12],
                phase="enumeration",
                started_at=now,
                completed_at=None,
            )
        elif phase == "exploitation":
            run.exploitation_run = PhaseRun(
                run_id=uuid.uuid4().hex[:12],
                phase="exploitation",
                started_at=now,
                completed_at=None,
            )
    elif event_type == "phase_completed":
        if phase == "recon" and run.recon_run is not None:
            if run.recon_run.completed_at is None:
                run.recon_run.completed_at = now
        elif phase == "enumeration" and run.enumeration_run is not None:
            if run.enumeration_run.completed_at is None:
                run.enumeration_run.completed_at = now
        elif phase == "exploitation" and run.exploitation_run is not None:
            if run.exploitation_run.completed_at is None:
                run.exploitation_run.completed_at = now


async def _runner(
    run:             PhasedRun,
    target:          str,
    persist_finding: Callable[[FindingEvent], Awaitable[str | None]] | None,
    lifecycle_fn:    Callable[[bool], Awaitable[None]] | None = None,
) -> None:
    """Dispatch all bootstrap probes via the shared Conductor singleton."""
    await _run_all_probes_via_conductor(run, target, persist_finding, lifecycle_fn)


async def _run_all_probes_via_conductor(
    run: PhasedRun,
    target: str,
    persist_finding: Callable[[FindingEvent], Awaitable[str | None]] | None,
    lifecycle_fn: Callable[[bool], Awaitable[None]] | None = None,
) -> None:
    """Dispatch all bootstrap probes via the shared Conductor and await completion.

    Uses the module-level Conductor singleton (same instance the admin UI reads)
    so investigations appear in /admin/conductor while running. Findings are bridged
    back to the existing persist_finding callback via StorageBridge.

    Importing apps.conductor.engines registers all five probe engines (passive_probe,
    sqli_recon, cmdi_recon, auth_recon, api_recon). Mock engines are not registered
    here; they are only registered in test fixtures that import mock.py explicitly.
    """
    import apps.conductor.engines  # noqa: F401 — registers all five probe engines
    from apps.conductor.findings.storage_bridge import StorageBridge
    from apps.conductor.shared import get_shared_conductor

    conductor = get_shared_conductor()
    bridge = StorageBridge(persist_finding)

    done = asyncio.Event()
    inv_id: str | None = None
    _completed_successfully = False

    def _on_event(event: dict) -> None:
        nonlocal _completed_successfully
        if event.get("investigation_id") != inv_id:
            return
        etype = event.get("event_type")
        if etype in ("phase_started", "phase_completed"):
            payload = event.get("payload", {})
            _apply_phase_event(run, etype, payload.get("phase", ""))
        elif etype == "investigation_completed":
            _completed_successfully = True
            if run.exploitation_run is not None and run.exploitation_run.completed_at is None:
                run.exploitation_run.completed_at = time.time()
            done.set()
        elif etype == "investigation_cancelled":
            if run.exploitation_run is not None and run.exploitation_run.completed_at is None:
                run.exploitation_run.completed_at = time.time()
            done.set()
        elif (event.get("orchestrator") == "phase"
              and etype == "phase_failed"):
            done.set()

    handle = conductor._bus.subscribe(_on_event)

    # Open the polling window BEFORE Conductor starts so is_recon_active()
    # returns True while the investigation runs. completed_at=None is what
    # is_recon_active() checks — set it to a real timestamp only after done.
    run.recon_run = PhaseRun(
        run_id=uuid.uuid4().hex[:12],
        phase="recon",
        started_at=run.started_at,
        completed_at=None,
    )

    try:
        inv_id = await conductor.start_investigation(
            target, {"max_chain_depth": 3},
            storage_bridge=bridge,
            investigation_id=run.investigation_id,
        )
        try:
            await asyncio.wait_for(done.wait(), timeout=3600.0)
        except TimeoutError:
            from sdk import Logger
            Logger.warning(
                "bootstrap_runtime.all_probes_conductor_timeout",
                extra={"investigation_id": run.investigation_id, "target": target},
            )
        now = time.time()
        # Idempotent teardown — bus-event subscribers may have already written
        # these timestamps; do not overwrite them.
        if run.recon_run is not None and run.recon_run.completed_at is None:
            run.recon_run.completed_at = now
        if run.enumeration_run is None:
            run.enumeration_run = PhaseRun(
                run_id=uuid.uuid4().hex[:12],
                phase="enumeration",
                started_at=run.started_at,
                completed_at=now,
            )
        elif run.enumeration_run.completed_at is None:
            run.enumeration_run.completed_at = now
        run.completed_at = now
        if lifecycle_fn is not None:
            try:
                await lifecycle_fn(_completed_successfully)
            except Exception as _lc_exc:
                import logging as _logging
                _logging.getLogger("bootstrap_runtime").error(
                    "lifecycle_fn raised for %s: %s",
                    run.investigation_id,
                    _lc_exc,
                )
    finally:
        handle.cancel()
