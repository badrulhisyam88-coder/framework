"""Phase Orchestrator — investigation phase state machine.

States per docs/architecture/orchestration.md lifecycle diagram:
  CREATED → RECON_RUNNING → RECON_COMPLETE → ENUM_RUNNING → ENUM_COMPLETE
  → EXPLOIT_RUNNING → EXPLOIT_COMPLETE → COMPLETED

Any state can transition to FAILED or CANCELLED.

Phase transitions are triggered when ExecutionOrchestrator reports all
engines for the current phase are done.
"""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from apps.conductor.events.bus import EventBus
from apps.conductor.storage.db import init_db

if TYPE_CHECKING:
    from apps.conductor.orchestrators.execution import ExecutionOrchestrator

logger = logging.getLogger("conductor.orchestrators.phase")

_PHASE_SEQUENCE = ("recon", "enumeration", "exploitation")

# Phases whose completion is driven by operator action, not engine count.
# Per clarification C3: PhaseOrchestrator tracks exploitation state but does
# NOT auto-complete it. No phase-initial engine count, no quiescence detection.
_OPERATOR_DRIVEN_PHASES = frozenset({"exploitation"})

# Map phase name → investigation lifecycle state when running
_PHASE_RUNNING_STATE = {
    "recon": "RECON_RUNNING",
    "enumeration": "ENUM_RUNNING",
    "exploitation": "EXPLOIT_RUNNING",
}
_PHASE_COMPLETE_STATE = {
    "recon": "RECON_COMPLETE",
    "enumeration": "ENUM_COMPLETE",
    "exploitation": "EXPLOIT_COMPLETE",
}


class PhaseOrchestrator:
    def __init__(
        self,
        investigation_id: str,
        bus: EventBus,
        db_path=None,
    ) -> None:
        self._investigation_id = investigation_id
        self._bus = bus
        self._exec_orch: ExecutionOrchestrator | None = None

        from pathlib import Path

        self._db = init_db(db_path or Path("data/orchestration.db"))

        # Current phase index into _PHASE_SEQUENCE
        self._phase_index = -1
        self._current_phase: str | None = None
        # Counts how many engines completed in the current phase
        self._engines_completed_this_phase = 0
        # How many engines were dispatched for the current phase
        self._engines_expected_this_phase = 0
        # Guard: only complete a phase once (chain dispatches call on_engine_completed too)
        self._phase_already_completed = False

    def wire_execution(self, exec_orch: ExecutionOrchestrator) -> None:
        self._exec_orch = exec_orch

    # ── Phase progression ─────────────────────────────────────────────────────

    async def start_next_phase(self) -> str | None:
        """Advance to the next phase in sequence and dispatch engines. Returns phase name."""
        self._phase_index += 1
        if self._phase_index >= len(_PHASE_SEQUENCE):
            # All phases done
            await self._bus.emit(
                orchestrator="phase",
                event_type="investigation_completed",
                investigation_id=self._investigation_id,
                payload={},
            )
            logger.info("phase: investigation %s completed all phases", self._investigation_id)
            return None

        phase = _PHASE_SEQUENCE[self._phase_index]
        self._current_phase = phase
        self._engines_completed_this_phase = 0
        self._phase_already_completed = False

        from apps.conductor.engines.base import engine_registry
        from apps.conductor.gates import engine_is_visible

        engines = engine_registry.engines_for_phase(phase)

        # Apply the same visibility-gate filter as ExecutionOrchestrator.dispatch_phase
        # so _engines_expected_this_phase matches the count that will actually run.
        visible_count = sum(1 for e in engines if engine_is_visible(e))

        self._engines_expected_this_phase = visible_count

        logger.info(
            "phase: starting phase=%s expecting %d engine(s)",
            phase,
            self._engines_expected_this_phase,
        )

        # Persist phase state
        self._db.execute(
            "INSERT OR REPLACE INTO phase_state "
            "(investigation_id, phase, status, started_at) VALUES (?, ?, ?, ?)",
            (self._investigation_id, phase, "running", time.time()),
        )
        self._db.commit()

        running_state = _PHASE_RUNNING_STATE[phase]
        await self._bus.emit(
            orchestrator="phase",
            event_type="phase_started",
            investigation_id=self._investigation_id,
            payload={"phase": phase, "investigation_state": running_state},
        )

        if self._exec_orch is not None:
            # C6: operator-driven phases (exploitation) must not be auto-dispatched.
            # Engines run only on explicit operator Arm → Execute. Recon and
            # enumeration remain fully automatic.
            if phase not in _OPERATOR_DRIVEN_PHASES:
                await self._exec_orch.dispatch_phase(phase)
        else:
            logger.error("phase: no ExecutionOrchestrator wired — cannot dispatch phase %s", phase)
            if phase not in _OPERATOR_DRIVEN_PHASES:
                await self._complete_phase(phase)

        # If no engines were expected AND this is not operator-driven, complete immediately.
        # Operator-driven phases (exploitation) stay active regardless of engine count.
        if self._engines_expected_this_phase == 0 and phase not in _OPERATOR_DRIVEN_PHASES:
            await self._complete_phase(phase)

        return phase

    async def on_engine_completed(self, engine_id: str) -> None:
        """Called by ExecutionOrchestrator each time an engine finishes.

        Phase completion is gated only on the N engines expected for the phase,
        not on chain-dispatched engines that run afterward. Calling all_done()
        would block completion whenever a chain dispatch is still in flight.

        For operator-driven phases (exploitation), engine completion never triggers
        phase completion — the operator calls operator_complete_exploitation().
        """
        if self._current_phase is None:
            return
        if self._phase_already_completed:
            return
        if self._current_phase in _OPERATOR_DRIVEN_PHASES:
            self._engines_completed_this_phase += 1
            logger.debug(
                "phase: engine %s done (%d completed in operator-driven phase %s)",
                engine_id,
                self._engines_completed_this_phase,
                self._current_phase,
            )
            return  # no auto-complete; operator drives completion

        self._engines_completed_this_phase += 1
        logger.debug(
            "phase: engine %s done (%d/%d for phase %s)",
            engine_id,
            self._engines_completed_this_phase,
            self._engines_expected_this_phase,
            self._current_phase,
        )

        if self._engines_completed_this_phase >= self._engines_expected_this_phase:
            await self._complete_phase(self._current_phase)

    async def _complete_phase(self, phase: str) -> None:
        self._phase_already_completed = True
        logger.info("phase: phase=%s completed for investigation %s", phase, self._investigation_id)
        complete_state = _PHASE_COMPLETE_STATE[phase]

        self._db.execute(
            "UPDATE phase_state SET status=?, completed_at=? "
            "WHERE investigation_id=? AND phase=?",
            ("completed", time.time(), self._investigation_id, phase),
        )
        self._db.commit()

        await self._bus.emit(
            orchestrator="phase",
            event_type="phase_completed",
            investigation_id=self._investigation_id,
            payload={"phase": phase, "investigation_state": complete_state},
        )

    async def operator_complete_exploitation(self) -> None:
        """Operator-driven exploitation phase completion (clarification C3).

        Called when the operator clicks "Mark exploitation complete" in the admin
        UI. Emits phase_completed, which unblocks the Conductor's _run_phases loop
        to advance to investigation_completed → COMPLETED.

        No-op if the current phase is not exploitation, or if it is already completed.
        """
        if self._current_phase != "exploitation":
            logger.warning(
                "phase: operator_complete_exploitation called but current phase is %s — ignored",
                self._current_phase,
            )
            return
        if self._phase_already_completed:
            logger.info("phase: operator_complete_exploitation called but already completed — ignored")
            return
        logger.info("phase: operator completing exploitation for investigation %s", self._investigation_id)
        await self._complete_phase("exploitation")

    async def reenter_exploitation(self) -> None:
        """Re-enter the exploitation phase from EXPLOIT_COMPLETE (V2.5 re-entry pipe).

        Shipped in V2 so the mechanism exists. V2.5 Qwen loop calls this when
        proposing a new exploration branch. Resets phase counters and emits
        phase_started so downstream V2.5 dispatch logic can proceed.

        Callers MUST dispatch engines afterward; this method only resets state.
        Only valid when current phase is already 'exploitation'.
        """
        if self._current_phase != "exploitation":
            logger.warning(
                "phase: reenter_exploitation called but current phase is %s — ignored",
                self._current_phase,
            )
            return
        logger.info("phase: re-entering exploitation for investigation %s", self._investigation_id)
        self._phase_already_completed = False
        self._engines_completed_this_phase = 0
        self._engines_expected_this_phase = 0

        self._db.execute(
            "INSERT OR REPLACE INTO phase_state "
            "(investigation_id, phase, status, started_at) VALUES (?, ?, ?, ?)",
            (self._investigation_id, "exploitation", "running", time.time()),
        )
        self._db.commit()

        await self._bus.emit(
            orchestrator="phase",
            event_type="phase_started",
            investigation_id=self._investigation_id,
            payload={"phase": "exploitation", "investigation_state": "EXPLOIT_RUNNING"},
        )

    async def fail(self, reason: str) -> None:
        logger.error(
            "phase: investigation %s failed — %s", self._investigation_id, reason
        )
        await self._bus.emit(
            orchestrator="phase",
            event_type="phase_failed",
            investigation_id=self._investigation_id,
            payload={"reason": reason},
        )

    async def cancel(self) -> None:
        await self._bus.emit(
            orchestrator="phase",
            event_type="investigation_cancelled",
            investigation_id=self._investigation_id,
            payload={"phase": self._current_phase},
        )

    # ── Queries ───────────────────────────────────────────────────────────────

    def current_phase(self) -> str | None:
        return self._current_phase

    def phase_history(self) -> list[dict]:
        rows = self._db.execute(
            "SELECT phase, status, started_at, completed_at FROM phase_state "
            "WHERE investigation_id=? ORDER BY started_at",
            (self._investigation_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_state(self) -> dict:
        return {
            "orchestrator": "phase",
            "investigation_id": self._investigation_id,
            "current_phase": self._current_phase,
            "phase_index": self._phase_index,
            "engines_expected": self._engines_expected_this_phase,
            "engines_completed": self._engines_completed_this_phase,
        }
