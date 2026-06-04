"""Execution Orchestrator — engine lifecycle, dispatch, concurrency policy.

Owns the engine roster (registered at startup). Dispatches engines for a phase
subject to mutex and rate limit checks. Health monitoring polls every 10s.

Concurrency policy: the mutex_with field in EngineCapabilities defines which
pairs cannot run concurrently. Conflicting requests are queued and retried when
the blocking engine finishes.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import uuid4

from apps.conductor.engines.base import Engine, OutputChannel, engine_registry
from apps.conductor.events.bus import EventBus
from apps.conductor.exploitation.branch_store import BranchWriter

if TYPE_CHECKING:
    from apps.conductor.orchestrators.findings import FindingsOrchestrator
    from apps.conductor.orchestrators.phase import PhaseOrchestrator
    from apps.conductor.orchestrators.session import SessionOrchestrator

logger = logging.getLogger("conductor.orchestrators.execution")

_HEALTH_INTERVAL       = 10.0   # seconds between health poll cycles
_HUNG_THRESHOLD_LIGHT  = 30.0   # light engines: single-HTTP-request probes
_HUNG_THRESHOLD_MEDIUM = 120.0  # medium engines: credential-iterating / timing-based probes
_HUNG_THRESHOLD_HEAVY  = 600.0  # heavy engines: long-running subprocess scanners (nmap, nuclei, zap)


@dataclass
class RunRecord:
    run_id: str
    engine_id: str
    target: str
    started_at: float
    task: asyncio.Task
    status: str = "running"
    ended_at: float | None = None


class ExecutionOrchestrator:
    def __init__(
        self,
        investigation_id: str,
        target: str,
        config: dict,
        bus: EventBus,
    ) -> None:
        self._investigation_id = investigation_id
        self._target = target
        self._config = config
        self._bus = bus

        self._findings_orch: FindingsOrchestrator | None = None
        self._session_orch: SessionOrchestrator | None = None
        self._phase_orch: PhaseOrchestrator | None = None
        self._branch_writer: BranchWriter = BranchWriter()

        # run_id → RunRecord
        self._running: dict[str, RunRecord] = {}
        # Queued dispatch requests: list of (engine_id, correlation_id)
        self._queued: list[tuple[str, str]] = []

        self._cancelled = False
        self._health_task: asyncio.Task | None = None

    # ── Wiring ────────────────────────────────────────────────────────────────

    def wire_findings(self, findings_orch: FindingsOrchestrator) -> None:
        self._findings_orch = findings_orch

    def wire_session(self, session_orch: SessionOrchestrator) -> None:
        self._session_orch = session_orch

    def wire_phase(self, phase_orch: PhaseOrchestrator) -> None:
        self._phase_orch = phase_orch

    # ── Phase dispatch ────────────────────────────────────────────────────────

    async def dispatch_phase(self, phase: str) -> None:
        """Find and dispatch all engines registered for *phase*.

        Engines with a gate_id attribute whose gate is OFF are silently skipped —
        they are visibility-gated and must not appear in operator output.
        """
        engines = engine_registry.engines_for_phase(phase)
        if not engines:
            logger.warning("execution: no engines registered for phase %s", phase)
            return  # PhaseOrchestrator handles the 0-engine case via _engines_expected == 0

        # Filter visibility-gated engines whose gate is currently OFF.
        from apps.conductor.gates import engine_is_visible
        visible_engines = []
        for engine in engines:
            if not engine_is_visible(engine):
                logger.debug(
                    "execution: engine %s gated off for phase %s",
                    engine.engine_id, phase,
                )
                continue
            visible_engines.append(engine)

        if not visible_engines:
            logger.debug("execution: all engines for phase %s are gated off", phase)
            return

        logger.info(
            "execution: dispatching %d engine(s) for phase %s", len(visible_engines), phase
        )
        tasks = [
            asyncio.create_task(self._dispatch_one(engine, phase))
            for engine in visible_engines
        ]
        # Wait for all initial dispatches to fire (engines run in background tasks)
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _dispatch_one(self, engine: Engine, phase: str) -> None:
        """Fire a single engine, subject to mutex and rate limit checks."""
        if self._cancelled:
            return

        # Mutex check
        blocked_by = self._mutex_blocked_by(engine)
        if blocked_by:
            logger.info(
                "execution: %s blocked by mutex with %s — queuing",
                engine.engine_id,
                blocked_by,
            )
            self._queued.append((engine.engine_id, phase))
            return

        # Rate limit check
        if self._session_orch:
            allowed, wait = self._session_orch.can_dispatch(self._target)
            if not allowed:
                logger.warning(
                    "execution: rate limit blocks %s (wait %.1fs) — queuing",
                    engine.engine_id,
                    wait,
                )
                self._queued.append((engine.engine_id, phase))
                return

        await self._launch(engine, correlation_id=phase)

    async def dispatch_engine(
        self,
        engine_id: str,
        correlation_id: str = "",
        extra_config: dict | None = None,
    ) -> None:
        """Dispatch a single engine by ID (used by Chain Orchestrator).

        extra_config is merged over self._config before the engine run()
        call. Used to pass service-specific info (port, scheme) from nmap
        next_action dicts to plugin engines.
        """
        engine = engine_registry.get(engine_id)
        if engine is None:
            logger.error("execution: unknown engine_id %s", engine_id)
            return
        if self._cancelled:
            # ── DIAGNOSTIC: silent-return on cancelled executor ───────────────
            import traceback as _tb
            logger.warning(
                "DIAG dispatch_engine SILENT-RETURN: engine=%s exec_id=%s CANCELLED=True | "
                "caller: %s",
                engine_id, id(self),
                "".join(_tb.format_stack(limit=5)[-2:]).strip().replace("\n", " | "),
            )
            # ── END DIAGNOSTIC ────────────────────────────────────────────────
            return

        blocked_by = self._mutex_blocked_by(engine)
        if blocked_by:
            logger.info(
                "execution: chain dispatch of %s blocked by %s — queuing",
                engine_id,
                blocked_by,
            )
            self._queued.append((engine_id, correlation_id))
            return

        await self._launch(engine, correlation_id=correlation_id, extra_config=extra_config)

    async def _launch(
        self, engine: Engine, correlation_id: str, extra_config: dict | None = None
    ) -> None:
        run_id = str(uuid4())
        assert self._findings_orch is not None
        assert self._session_orch is not None

        # Fix 3: inject correlation_id into config so GenericHTTPEngine.run() can read it
        # via config.get("correlation_id"). Specialized engines ignore this key (they
        # query the DB directly for their finding_id), so this is safe to add universally.
        config = {**self._config, **(extra_config or {}), "correlation_id": correlation_id}

        channel = OutputChannel(
            investigation_id=self._investigation_id,
            engine_id=engine.engine_id,
            findings_orch=self._findings_orch,
            session_orch=self._session_orch,
            branch_writer=self._branch_writer,
        )

        await self._bus.emit(
            orchestrator="execution",
            event_type="engine_started",
            investigation_id=self._investigation_id,
            payload={"engine_id": engine.engine_id, "run_id": run_id, "target": self._target},
            correlation_id=correlation_id,
        )

        task = asyncio.create_task(
            self._run_engine(engine, run_id, channel, correlation_id, config=config)
        )
        self._running[run_id] = RunRecord(
            run_id=run_id,
            engine_id=engine.engine_id,
            target=self._target,
            started_at=time.time(),
            task=task,
        )
        logger.info(
            "execution: launched %s run_id=%s correlation=%s",
            engine.engine_id,
            run_id,
            correlation_id,
        )

    async def _run_engine(
        self,
        engine: Engine,
        run_id: str,
        channel: OutputChannel,
        correlation_id: str,
        config: dict | None = None,
    ) -> None:
        result = None
        effective_config = config if config is not None else self._config
        try:
            # Pass investigation_id only when the engine accepts it.
            # Recon/phase engines (nmap, passive_probe) don't declare
            # investigation_id; exploitation engines do. Introspect to avoid
            # TypeError on engines that don't accept the kwarg.
            import inspect as _inspect
            _run_sig = _inspect.signature(engine.run)
            _run_kwargs: dict = {
                "target":         self._target,
                "config":         effective_config,
                "session_store":  self._session_orch,
                "output_channel": channel,
            }
            if ("investigation_id" in _run_sig.parameters or
                    any(
                        p.kind == _inspect.Parameter.VAR_KEYWORD
                        for p in _run_sig.parameters.values()
                    )):
                _run_kwargs["investigation_id"] = self._investigation_id
            result = await engine.run(**_run_kwargs)
            self._running[run_id].status = result.status

            # V2.9B — fire-and-forget failure export on exhausted/failed runs
            if result and result.status != "success" and channel._active_branch_id and channel._last_exhaustion:
                try:
                    from apps.conductor.qwen import vault_writer as _vw
                    _finding_types = engine.capabilities.finding_types
                    _ft = _finding_types[0] if _finding_types else ""
                    asyncio.create_task(
                        _vw.export_failure(
                            investigation_id=self._investigation_id,
                            engine_id=engine.engine_id,
                            finding_type=_ft,
                            target_url=self._target,
                            exhaustion_record=channel._last_exhaustion,
                            branch_id=channel._active_branch_id,
                        )
                    )
                except Exception:
                    pass

            # V2.7 — fire-and-forget vault export on successful engine run
            if result and result.status == "success" and channel._active_branch_id:
                try:
                    from apps.conductor.qwen import vault_writer as _vw
                    _finding_types = engine.capabilities.finding_types
                    _ft = _finding_types[0] if _finding_types else ""
                    asyncio.create_task(
                        _vw.export_finding(
                            investigation_id=self._investigation_id,
                            engine_id=engine.engine_id,
                            finding_type=_ft,
                            target_url=self._target,
                            artifact=channel._last_artifact or {},
                            branch_id=channel._active_branch_id,
                        )
                    )
                except Exception:
                    pass

            # Phase C+E scope extension — fire-and-forget verdict → STATE wire for MANUAL
            # execution path (Execute button).  The autonomous path already has this wire
            # in autonomous_orchestrator.execute_work_order.  Without this, STATE never
            # accumulates during operator-triggered executions (only autonomous runs).
            # Fire-and-forget: never raises; mirrors the vault-export pattern above.
            try:
                from apps.conductor.leaf_evaluator import evaluate_verdict
                from apps.conductor.agent_state import apply_verdict_to_state_async
                from apps.conductor.constants import CONCEPT_ENGINE_MAP as _verd_CEM
                _verd_e2c = {v: k for k, v in _verd_CEM.items() if v}
                _verd_concept = _verd_e2c.get(engine.engine_id, "")
                if _verd_concept:
                    _verd_state = result.status if result else "failed"
                    _verd_art   = channel._last_artifact or {}
                    _verd_v     = evaluate_verdict(
                        engine_id  = engine.engine_id,
                        concept_id = _verd_concept,
                        artifact   = _verd_art,
                        state      = _verd_state,
                    )
                    if _verd_v.match_kind == "known":
                        asyncio.create_task(
                            apply_verdict_to_state_async(
                                investigation_id = self._investigation_id,
                                verdict          = _verd_v,
                                concept_id       = _verd_concept,
                                engine_id        = engine.engine_id,
                                exec_state       = _verd_state,
                            )
                        )
                    elif _verd_v.match_kind == "no_concept_match":
                        from apps.conductor.unknown_store import park_unknown_async
                        asyncio.create_task(
                            park_unknown_async(
                                investigation_id = self._investigation_id,
                                context = (
                                    f"exploitation (manual), engine={engine.engine_id}"
                                ),
                                raw_result       = _verd_art,
                                expected_concept = _verd_concept or None,
                                evidence         = {
                                    "engine_id":  engine.engine_id,
                                    "exec_state": _verd_state,
                                },
                            )
                        )
            except Exception:
                pass  # verdict wire must never interrupt execution
        except asyncio.CancelledError:
            self._running[run_id].status = "cancelled"
            await channel.fail_active_branch()
            raise
        except Exception as exc:
            logger.error(
                "execution: engine %s crashed: %s", engine.engine_id, exc, exc_info=True
            )
            self._running[run_id].status = "failed"
            await channel.fail_active_branch()
            await self._bus.emit(
                orchestrator="execution",
                event_type="engine_failed",
                investigation_id=self._investigation_id,
                payload={
                    "engine_id": engine.engine_id,
                    "run_id": run_id,
                    "error": str(exc),
                },
                correlation_id=correlation_id,
            )
            return
        finally:
            if run_id in self._running:
                self._running[run_id].ended_at = time.time()

        status = result.status if result else "failed"
        event_type = "engine_completed" if status == "success" else "engine_failed"

        await self._bus.emit(
            orchestrator="execution",
            event_type=event_type,
            investigation_id=self._investigation_id,
            payload={
                "engine_id": engine.engine_id,
                "run_id": run_id,
                "status": status,
                "findings_count": result.findings_count if result else 0,
            },
            correlation_id=correlation_id,
        )
        logger.info(
            "execution: %s finished run_id=%s status=%s", engine.engine_id, run_id, status
        )

        # Drain queued dispatches that may now be unblocked
        await self._drain_queue()

        # js_spider is no longer auto-dispatched here.
        # After credential_brute succeeds, apply_verdict_to_state_async adds
        # CONCEPT-JS-SPIDER to agent_state.pending via the unlocks path
        # (concept-credential-brute.md unlocks: CONCEPT-JS-SPIDER@75).
        # The planner then selects it when current_position.authentication != "none".
        # This keeps ONE selection authority (plan_next_step) and respects the
        # precondition gate (js_spider requires an authenticated session).

        # Notify phase orchestrator
        if self._phase_orch:
            await self._phase_orch.on_engine_completed(engine.engine_id)

    # ── Mutex enforcement ─────────────────────────────────────────────────────

    def _mutex_blocked_by(self, engine: Engine) -> str | None:
        """Return engine_id of a currently running engine that conflicts, or None."""
        running_engine_ids = {r.engine_id for r in self._running.values() if r.status == "running"}
        for conflict_id in engine.capabilities.mutex_with:
            if conflict_id in running_engine_ids:
                return conflict_id
        return None

    async def _drain_queue(self) -> None:
        """Attempt to dispatch all queued engine requests."""
        if not self._queued:
            return
        still_queued: list[tuple[str, str]] = []
        for engine_id, correlation_id in list(self._queued):
            engine = engine_registry.get(engine_id)
            if engine is None:
                continue
            if self._mutex_blocked_by(engine):
                still_queued.append((engine_id, correlation_id))
                continue
            await self._launch(engine, correlation_id=correlation_id)
        self._queued = still_queued

    # ── Cancellation ──────────────────────────────────────────────────────────

    async def cancel_all(self) -> None:
        # ── DIAGNOSTIC: log when cancel_all fires with caller stack ──────────
        import time as _diag_tc, traceback as _tbc
        logger.warning(
            "DIAG cancel_all FIRED: exec_id=%s inv=%s ts=%.3f running_engines=%s | "
            "caller: %s",
            id(self), self._investigation_id, _diag_tc.monotonic(),
            [r.engine_id for r in self._running.values()],
            "".join(_tbc.format_stack(limit=6)[-3:]).strip().replace("\n", " | "),
        )
        # ── END DIAGNOSTIC ────────────────────────────────────────────────────
        self._cancelled = True
        if self._health_task:
            self._health_task.cancel()

        engines_by_id = {
            r.engine_id: engine_registry.get(r.engine_id) for r in self._running.values()
        }
        cancel_tasks = []
        for engine in engines_by_id.values():
            if engine:
                cancel_tasks.append(asyncio.create_task(engine.cancel()))

        if cancel_tasks:
            await asyncio.gather(*cancel_tasks, return_exceptions=True)

        for task in [r.task for r in self._running.values()]:
            task.cancel()

        await asyncio.sleep(0)  # allow cancellation to propagate

    # ── Health monitoring ─────────────────────────────────────────────────────

    async def start_health_monitor(self) -> None:
        self._health_task = asyncio.create_task(self._health_loop())

    async def _health_loop(self) -> None:
        try:
            while not self._cancelled:
                await asyncio.sleep(_HEALTH_INTERVAL)
                self._check_health()
        except asyncio.CancelledError:
            pass

    def _check_health(self) -> None:
        now = time.time()
        for record in list(self._running.values()):
            if record.status != "running":
                continue
            engine = engine_registry.get(record.engine_id)
            if engine is None:
                continue
            health = engine.health_check()
            resource_cost = engine.capabilities.resource_cost
            if resource_cost == "heavy":
                threshold = _HUNG_THRESHOLD_HEAVY
            elif resource_cost == "medium":
                threshold = _HUNG_THRESHOLD_MEDIUM
            else:
                threshold = _HUNG_THRESHOLD_LIGHT
            # Use the later of engine heartbeat and run start time as the
            # effective last-alive timestamp. A run started within the current
            # threshold window inherits the engine singleton's stale heartbeat
            # from a previous (now-dead) run, which would cause a false-positive
            # hung detection and cancel the new run immediately.
            effective_heartbeat = max(health.last_heartbeat, record.started_at)
            if health.status == "hung" or (now - effective_heartbeat) > threshold:
                logger.error(
                    "execution: engine %s hung (%.0fs ago, threshold=%.0fs) — killing",
                    record.engine_id,
                    now - effective_heartbeat,
                    threshold,
                )
                record.task.cancel()
                record.status = "killed"

    # ── Queries ───────────────────────────────────────────────────────────────

    def running_engines(self) -> list[dict]:
        return [
            {
                "run_id": r.run_id,
                "engine_id": r.engine_id,
                "status": r.status,
                "started_at": r.started_at,
            }
            for r in self._running.values()
        ]

    def all_done(self) -> bool:
        """True when no engine is in running status."""
        return all(r.status != "running" for r in self._running.values())

    def get_state(self) -> dict:
        return {
            "orchestrator": "execution",
            "investigation_id": self._investigation_id,
            "running": self.running_engines(),
            "queued": len(self._queued),
            "cancelled": self._cancelled,
        }

