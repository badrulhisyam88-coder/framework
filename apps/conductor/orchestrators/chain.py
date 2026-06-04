"""Chain Orchestrator — evaluates next_actions on findings and dispatches auto-fires.

Chain depth is tracked per (investigation_id, root_finding_id) branch.
Max depth default is 5 (configurable via config dict).
Cycle finding IDs are caught by dedup in FindingsOrchestrator; depth limit
catches infinite engine dispatch cycles.
"""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING
from uuid import uuid4

from apps.conductor.events.bus import EventBus

if TYPE_CHECKING:
    from apps.conductor.orchestrators.execution import ExecutionOrchestrator
    from apps.conductor.orchestrators.session import SessionOrchestrator

logger = logging.getLogger("conductor.orchestrators.chain")

_DEFAULT_MAX_DEPTH = 5


class ChainOrchestrator:
    def __init__(
        self,
        investigation_id: str,
        bus: EventBus,
        max_depth: int = _DEFAULT_MAX_DEPTH,
    ) -> None:
        self._investigation_id = investigation_id
        self._bus = bus
        self._max_depth = max_depth
        self._exec_orch: ExecutionOrchestrator | None = None
        self._session_orch: SessionOrchestrator | None = None

        # { branch_id: depth }  where branch_id is a root finding id or chain key
        self._chain_depth: dict[str, int] = {}
        # { action_id: action_dict } — pending operator-armed actions
        self._pending_actions: dict[str, dict] = {}

    def wire_execution(self, exec_orch: ExecutionOrchestrator) -> None:
        self._exec_orch = exec_orch

    def wire_session(self, session_orch: SessionOrchestrator) -> None:
        self._session_orch = session_orch

    # ── Main evaluation ───────────────────────────────────────────────────────

    async def evaluate_finding(self, finding: dict) -> None:
        """Classify and act on each next_action in the finding."""
        next_actions = finding.get("next_actions") or []
        finding_id = finding.get("id", "unknown")

        for action in next_actions:
            trigger = action.get("trigger")
            engine_id = action.get("engine_id", "")

            if trigger == "auto_fire":
                await self._handle_auto_fire(finding_id, engine_id, action)

            elif trigger in ("operator_arm_required", "operator_confirm_required"):
                action_id = str(uuid4())
                self._pending_actions[action_id] = {
                    "action_id": action_id,
                    "finding_id": finding_id,
                    "engine_id": engine_id,
                    "trigger": trigger,
                    "description": action.get("description", ""),
                    "pending_since": time.time(),
                }
                event_type = (
                    "chain_operator_arm_pending"
                    if trigger == "operator_arm_required"
                    else "chain_operator_confirm_pending"
                )
                await self._bus.emit(
                    orchestrator="chain",
                    event_type=event_type,
                    investigation_id=self._investigation_id,
                    payload={
                        "action_id": action_id,
                        "finding_id": finding_id,
                        "engine_id": engine_id,
                    },
                )
                logger.info(
                    "chain: %s — finding %s wants %s (pending operator)",
                    trigger,
                    finding_id,
                    engine_id,
                )

    async def _handle_auto_fire(
        self, finding_id: str, engine_id: str, action: dict
    ) -> None:
        # Visibility gate check: if the engine is gated off, suppress auto-fire.
        from apps.conductor.engines.base import engine_registry
        from apps.conductor.gates import engine_is_visible
        engine = engine_registry.get(engine_id)
        if engine is not None and not engine_is_visible(engine):
            logger.debug(
                "chain: engine %s gated off — suppressing auto-fire", engine_id,
            )
            return

        # Depth is tracked per dispatched engine_id so cycles (A→A→A) accumulate
        # correctly even when the trigger finding has a unique ID each run.
        branch_id = engine_id
        depth = self._chain_depth.get(branch_id, 0)

        if depth >= self._max_depth:
            logger.warning(
                "chain: depth limit %d reached for branch %s — halting auto-fire of %s",
                self._max_depth,
                branch_id,
                engine_id,
            )
            await self._bus.emit(
                orchestrator="chain",
                event_type="chain_depth_exceeded",
                investigation_id=self._investigation_id,
                payload={
                    "finding_id": finding_id,
                    "engine_id": engine_id,
                    "depth": depth,
                    "max_depth": self._max_depth,
                },
            )
            return

        if self._exec_orch is None:
            logger.error("chain: no ExecutionOrchestrator wired — cannot auto-fire %s", engine_id)
            return

        # Session check
        if self._session_orch is not None:
            allowed, wait = self._session_orch.can_dispatch("mock://test")
            if not allowed:
                logger.warning(
                    "chain: session rate limit blocks auto-fire of %s (wait %.1fs)",
                    engine_id,
                    wait,
                )
                return

        self._chain_depth[branch_id] = depth + 1
        logger.info(
            "chain: auto-firing %s from finding %s (depth %d→%d)",
            engine_id,
            finding_id,
            depth,
            depth + 1,
        )
        await self._bus.emit(
            orchestrator="chain",
            event_type="chain_auto_fired",
            investigation_id=self._investigation_id,
            payload={
                "finding_id": finding_id,
                "engine_id": engine_id,
                "depth": depth + 1,
            },
        )
        # Pass service_info from the action so plugin engines know which port/scheme to use.
        service_info = action.get("service_info")
        extra_config = {"service_info": service_info} if service_info else None
        await self._exec_orch.dispatch_engine(
            engine_id, correlation_id=finding_id, extra_config=extra_config
        )

    # ── Operator actions ──────────────────────────────────────────────────────

    async def operator_arm(self, action_id: str) -> None:
        action = self._pending_actions.pop(action_id, None)
        if action is None:
            logger.warning("chain: operator_arm for unknown action_id %s", action_id)
            return
        await self._exec_orch.dispatch_engine(action["engine_id"], correlation_id=action_id)

    async def operator_confirm(self, action_id: str) -> None:
        action = self._pending_actions.pop(action_id, None)
        if action is None:
            logger.warning("chain: operator_confirm for unknown action_id %s", action_id)
            return
        await self._exec_orch.dispatch_engine(action["engine_id"], correlation_id=action_id)

    def chain_depth(self, branch_id: str) -> int:
        return self._chain_depth.get(branch_id, 0)

    def get_state(self) -> dict:
        return {
            "orchestrator": "chain",
            "investigation_id": self._investigation_id,
            "chain_depths": dict(self._chain_depth),
            "pending_actions": len(self._pending_actions),
            "max_depth": self._max_depth,
        }
