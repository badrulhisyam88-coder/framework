"""Conductor — top-level investigation coordinator (Level 3).

Per docs/architecture/orchestration.md:
  - Receives operator intent (start_investigation)
  - Instantiates the five orchestrators and wires them together
  - Transitions investigation through lifecycle states
  - Handles operator cancel signal
  - Persists investigation lifecycle to SQLite

The Conductor knows nothing about individual engine names. All engine
knowledge lives in the Execution Orchestrator and the engine registry.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from uuid import uuid4

from apps.conductor.events.bus import EventBus
from apps.conductor.events.bus import bus as _default_bus
from apps.conductor.orchestrators.chain import ChainOrchestrator
from apps.conductor.orchestrators.execution import ExecutionOrchestrator
from apps.conductor.orchestrators.filter import FilterOrchestrator
from apps.conductor.orchestrators.findings import FindingsOrchestrator
from apps.conductor.orchestrators.phase import PhaseOrchestrator
from apps.conductor.orchestrators.session import SessionOrchestrator
from apps.conductor.storage.db import init_db

logger = logging.getLogger("conductor.conductor")

_DEFAULT_DB = Path("data/orchestration.db")


class _InvestigationContext:
    """Runtime context for one active investigation — holds all five orchestrators."""

    def __init__(
        self,
        investigation_id: str,
        target: str,
        config: dict,
        bus: EventBus,
        db_path: Path,
    ) -> None:
        self.investigation_id = investigation_id
        self.target = target
        self.config = config
        self.state = "CREATED"

        # Instantiate all five orchestrators + FilterOrchestrator (V1.7)
        self.session_orch = SessionOrchestrator(bus=bus)
        self.findings_orch = FindingsOrchestrator(investigation_id=investigation_id, bus=bus)
        self.chain_orch = ChainOrchestrator(
            investigation_id=investigation_id,
            bus=bus,
            max_depth=config.get("max_chain_depth", 5),
        )
        self.exec_orch = ExecutionOrchestrator(
            investigation_id=investigation_id,
            target=target,
            config=config,
            bus=bus,
        )
        self.phase_orch = PhaseOrchestrator(
            investigation_id=investigation_id,
            bus=bus,
            db_path=db_path,
        )
        self.filter_orch = FilterOrchestrator(
            investigation_id=investigation_id,
            bus=bus,
        )

        # Wire orchestrators per design doc communication graph
        self.findings_orch.wire_chain(self.chain_orch)
        self.chain_orch.wire_execution(self.exec_orch)
        self.chain_orch.wire_session(self.session_orch)
        self.exec_orch.wire_findings(self.findings_orch)
        self.exec_orch.wire_session(self.session_orch)
        self.exec_orch.wire_phase(self.phase_orch)
        self.phase_orch.wire_execution(self.exec_orch)
        self.filter_orch.wire_findings(self.findings_orch)

        # Wire FilterOrchestrator re-invocation dispatcher to ExecutionOrchestrator.
        # dispatch_engine is fire-and-forget; findings arrive asynchronously and
        # will be available for the second filter pass if dispatched engines are fast.
        _exec = self.exec_orch

        async def _reinvoke_dispatch(engine_id: str, config: dict) -> None:
            await _exec.dispatch_engine(engine_id, extra_config=config)

        self.filter_orch.wire_reinvocation_dispatcher(_reinvoke_dispatch)

        # Wire FilterOrchestrator DB writers for validation persistence.
        # Must target validation.db (normalized_findings lives there), NOT
        # the conductor's orchestration.db which has no normalized_findings table.

        async def _validation_update(
            finding_id: str,
            status: str,
            reason: str | None,
            gaps_json: str | None,
            validated_at: str | None,
        ) -> None:
            import aiosqlite as _aiosqlite

            from apps.scanner_orchestration.storage.finding_repo import (
                NormalizedFindingRepository as _FindingRepo,
            )
            from apps.validation.database import (
                DB_PATH as _VALIDATION_DB,
            )
            async with _aiosqlite.connect(_VALIDATION_DB) as _db:
                _db.row_factory = _aiosqlite.Row
                await _FindingRepo(_db).update_validation_status(
                    finding_id, status, reason, gaps_json, validated_at
                )

        self.filter_orch.wire_db_writer(_validation_update)

        async def _block_reason_update(finding_id: str, reason: str) -> None:
            import aiosqlite as _aiosqlite

            from apps.scanner_orchestration.storage.finding_repo import (
                NormalizedFindingRepository as _FindingRepo,
            )
            from apps.validation.database import (
                DB_PATH as _VALIDATION_DB,
            )
            async with _aiosqlite.connect(_VALIDATION_DB) as _db:
                await _FindingRepo(_db).update_block_reason(finding_id, reason)

        self.filter_orch.wire_block_reason_writer(_block_reason_update)

    def get_state(self) -> dict:
        return {
            "investigation_id": self.investigation_id,
            "target": self.target,
            "state": self.state,
            "orchestrators": {
                "session": self.session_orch.get_state(),
                "findings": self.findings_orch.get_state(),
                "chain": self.chain_orch.get_state(),
                "execution": self.exec_orch.get_state(),
                "phase": self.phase_orch.get_state(),
                "filter": self.filter_orch.get_state(),
            },
        }


class Conductor:
    """Top-level investigation coordinator.

    Usage:
        conductor = Conductor()
        inv_id = await conductor.start_investigation("http://target", {})
    """

    def __init__(
        self,
        bus: EventBus | None = None,
        db_path: Path | None = None,
    ) -> None:
        self._bus = bus or _default_bus
        self._db_path = db_path or _DEFAULT_DB
        self._db = init_db(self._db_path)
        # investigation_id → _InvestigationContext
        self._active: dict[str, _InvestigationContext] = {}

    async def start_investigation(
        self,
        target: str,
        config: dict,
        storage_bridge=None,
        investigation_id: str | None = None,
    ) -> str:
        """Start a new investigation. Returns investigation_id immediately.

        storage_bridge — optional StorageBridge; when provided, findings are
        forwarded to the investigation workspace persistence layer in addition
        to being stored in the conductor's in-memory state.

        investigation_id — when provided (e.g. the workspace investigation UUID),
        that ID is used as the key in _active so get_context(workspace_id) works.
        When omitted, a new UUID is generated (existing callers unaffected).
        """
        investigation_id = investigation_id or str(uuid4())
        now = time.time()

        # 1. Persist investigation row
        self._db.execute(
            "INSERT INTO investigations (id, target, config_json, state, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (investigation_id, target, json.dumps(config), "CREATED", now, now),
        )
        self._db.commit()

        # 2. Build context with all five orchestrators wired
        ctx = _InvestigationContext(
            investigation_id=investigation_id,
            target=target,
            config=config,
            bus=self._bus,
            db_path=self._db_path,
        )
        if storage_bridge is not None:
            ctx.findings_orch.wire_bridge(storage_bridge)
        self._active[investigation_id] = ctx

        await self._bus.emit(
            orchestrator="conductor",
            event_type="investigation_started",
            investigation_id=investigation_id,
            payload={"target": target},
        )
        logger.info("conductor: started investigation %s target=%s", investigation_id, target)

        # 3. Start health monitoring
        await ctx.exec_orch.start_health_monitor()

        # 4. Kick off phase progression in background
        asyncio.create_task(
            self._run_phases(ctx),
            name=f"phases-{investigation_id}",
        )

        return investigation_id

    async def _run_phases(self, ctx: _InvestigationContext) -> None:
        """Drive phase progression through all phases sequentially.

        Listens for phase_completed events (filtered to this investigation) and
        calls start_next_phase() to advance the state machine until all phases
        are exhausted and start_next_phase() returns None.

        Emits "investigation_completed" on normal completion.
        Emits "investigation_failed" if an unexpected exception escapes the loop.
        """
        phase_done = asyncio.Event()

        def _on_phase_event(event: dict) -> None:
            if (event.get("investigation_id") == ctx.investigation_id
                    and event.get("event_type") == "phase_completed"):
                phase_done.set()

        handle = self._bus.subscribe(_on_phase_event)

        # Map phase name → investigation lifecycle state while that phase runs.
        # Must stay in sync with PhaseOrchestrator._PHASE_RUNNING_STATE.
        _phase_running_state = {
            "recon": "RECON_RUNNING",
            "enumeration": "ENUM_RUNNING",
            "exploitation": "EXPLOIT_RUNNING",
        }

        try:
            ctx.state = "RECON_RUNNING"
            self._update_state(ctx.investigation_id, "RECON_RUNNING")

            while True:
                phase_done.clear()
                phase = await ctx.phase_orch.start_next_phase()
                if phase is None:
                    break

                # Update the investigation lifecycle state to match the current
                # running phase so the admin UI Mark Done button renders correctly.
                if phase in _phase_running_state:
                    ctx.state = _phase_running_state[phase]
                    self._update_state(ctx.investigation_id, _phase_running_state[phase])

                # Exploitation phase is operator-driven (clarification C3) — no timeout.
                # Recon and enumeration use a 300s watchdog to catch hung engines.
                if phase == "exploitation":
                    await phase_done.wait()
                else:
                    try:
                        await asyncio.wait_for(phase_done.wait(), timeout=300.0)
                    except TimeoutError:
                        logger.error(
                            "conductor: phase %s timed out for investigation %s",
                            phase,
                            ctx.investigation_id,
                        )
                        break

                # After enumeration phase, run FilterOrchestrator so chain-dispatched
                # enumeration engines (auth_recon, api_recon, sqli_recon) have finished
                # emitting findings before filtering begins.
                if phase == "enumeration":
                    await ctx.filter_orch.run_filter()

            await self._bus.emit(
                orchestrator="conductor",
                event_type="investigation_completed",
                investigation_id=ctx.investigation_id,
                payload={"completed_at": time.time()},
            )
            ctx.state = "COMPLETED"
            self._update_state(ctx.investigation_id, "COMPLETED")
        except Exception as exc:
            logger.error(
                "conductor: investigation %s _run_phases raised: %s",
                ctx.investigation_id, exc, exc_info=True,
            )
            await self._bus.emit(
                orchestrator="conductor",
                event_type="investigation_failed",
                investigation_id=ctx.investigation_id,
                payload={"failed_at": time.time(), "error": str(exc)},
            )
            ctx.state = "FAILED"
            self._update_state(ctx.investigation_id, "FAILED")
        finally:
            handle.cancel()

    def _update_state(self, investigation_id: str, state: str) -> None:
        self._db.execute(
            "UPDATE investigations SET state=?, updated_at=? WHERE id=?",
            (state, time.time(), investigation_id),
        )
        self._db.commit()
        if investigation_id in self._active:
            self._active[investigation_id].state = state

    async def cancel_investigation(self, investigation_id: str) -> None:
        """Cancel an active investigation. Broadcasts cancel to all orchestrators."""
        ctx = self._active.get(investigation_id)
        if ctx is None:
            logger.warning("conductor: cancel for unknown investigation %s", investigation_id)
            return

        logger.info("conductor: cancelling investigation %s", investigation_id)

        await ctx.exec_orch.cancel_all()
        await ctx.phase_orch.cancel()

        ctx.state = "CANCELLED"
        self._update_state(investigation_id, "CANCELLED")

        await self._bus.emit(
            orchestrator="conductor",
            event_type="investigation_cancelled",
            investigation_id=investigation_id,
            payload={},
        )

    async def get_investigation_status(self, investigation_id: str) -> dict:
        ctx = self._active.get(investigation_id)
        if ctx:
            return ctx.get_state()

        # Fall back to SQLite
        row = self._db.execute(
            "SELECT id, target, state, created_at, updated_at FROM investigations WHERE id=?",
            (investigation_id,),
        ).fetchone()
        if row is None:
            return {"error": "not_found"}
        return dict(row)

    async def list_active_investigations(self) -> list[dict]:
        terminal = {"COMPLETED", "FAILED", "CANCELLED"}
        return [ctx.get_state() for ctx in self._active.values() if ctx.state not in terminal]

    async def operator_complete_exploitation(self, investigation_id: str) -> bool:
        """Operator-driven exploitation phase completion (clarification C3).

        Delegates to the investigation's PhaseOrchestrator. Returns True if
        the signal was delivered, False if the investigation is not active or
        not in the exploitation phase.
        """
        ctx = self._active.get(investigation_id)
        if ctx is None:
            logger.warning(
                "conductor: operator_complete_exploitation for unknown investigation %s",
                investigation_id,
            )
            return False
        await ctx.phase_orch.operator_complete_exploitation()
        return True

    def refresh_target_auth(self, target_base: str, auth: dict) -> int:
        """Operator-driven refresh across all active investigations with this target.

        Clears the expired flag and stores new auth in every active investigation
        whose session_orch has a cached entry for target_base. Returns the count
        of investigations updated.
        """
        count = 0
        for ctx in self._active.values():
            if ctx.session_orch.get_target_auth(target_base) is not None:
                ctx.session_orch.refresh_target_auth(target_base, auth)
                count += 1
        return count

    def get_context(self, investigation_id: str) -> _InvestigationContext | None:
        return self._active.get(investigation_id)
