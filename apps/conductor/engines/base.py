"""Engine ABC and supporting types for the conductor orchestration layer.

All engines must subclass Engine and implement run(), cancel(),
health_check(), and the capabilities property. See the conformance rules
in docs/architecture/orchestration.md#conformance-rules.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apps.conductor.orchestrators.findings import FindingsOrchestrator
    from apps.conductor.orchestrators.session import SessionOrchestrator
    from apps.conductor.exploitation.branch_store import BranchWriter

logger = logging.getLogger("conductor.engines.base")


# ── Capability / health / result dataclasses ─────────────────────────────────


@dataclass(frozen=True)
class EngineCapabilities:
    phases: tuple[str, ...]               # phases this engine serves
    finding_types: tuple[str, ...]        # finding category strings produced
    target_types: tuple[str, ...]         # "http" | "tcp" | "any"
    resource_cost: str                    # "light" | "medium" | "heavy"
    concurrency_safe_with: tuple[str, ...] = ()   # engine_ids safe to run alongside
    mutex_with: tuple[str, ...] = ()              # engine_ids that must not run concurrently


@dataclass
class EngineHealth:
    status: str              # "healthy" | "slow" | "hung" | "crashed" | "idle"
    last_heartbeat: float    # epoch seconds
    message: str = ""


@dataclass
class EngineResult:
    status: str              # "success" | "failed" | "cancelled" | "skipped"
    findings_count: int
    error: str | None = None


# ── SessionStore — engines read auth from here ────────────────────────────────


class SessionStore:
    """Auth read interface. SessionOrchestrator is the canonical implementation.

    Engines call get_auth() / has_auth() before making authenticated requests.
    They NEVER call login endpoints themselves.
    """

    def get_auth(self, investigation_id: str) -> dict | None:
        """Return cookies/token dict if auth has been captured, else None."""
        return None

    def has_auth(self, investigation_id: str) -> bool:
        return self.get_auth(investigation_id) is not None


# ── OutputChannel — engines push output through this ─────────────────────────


class OutputChannel:
    """Concrete channel wiring engine output to Findings and Session orchestrators.

    Constructed by ExecutionOrchestrator before each engine.run() call with refs
    to both orchestrators. OutputChannel.record_request() calls directly into
    SessionOrchestrator (no event bus) to keep the hot-path rate limiting lean.
    """

    def __init__(
        self,
        investigation_id: str,
        engine_id: str,
        findings_orch: FindingsOrchestrator,
        session_orch: SessionOrchestrator,
        branch_writer: BranchWriter | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.engine_id = engine_id
        self._findings_orch = findings_orch
        self._session_orch = session_orch
        self._branch_writer = branch_writer
        self._active_branch_id: str | None = None
        self._last_artifact: dict = {}         # V2.7: captured on emit_stage("succeeded")
        self._last_exhaustion: dict = {}       # V2.9B: captured on emit_stage("exhausted")

    async def emit_finding(self, finding: dict) -> None:
        """Push a finding dict to FindingsOrchestrator ingress."""
        await self._findings_orch.ingest(finding, self.engine_id)

    async def record_request(self, target: str) -> None:
        """Account for an outbound request in SessionOrchestrator's rate limiter."""
        self._session_orch.record_request(target)

    async def record_response(self, target: str, status_code: int) -> None:
        """Notify SessionOrchestrator of a response status (e.g. 429 detection)."""
        self._session_orch.record_response(target, status_code)

    async def create_branch(
        self,
        branch_id: str,
        finding_id: str,
        technique_class: str,
        operator_params: dict | None = None,
    ) -> None:
        """Create a new exploitation branch record in pending state.

        No-op if no branch_writer is wired — V1 phase engines are unaffected.
        """
        if self._branch_writer is not None:
            from apps.conductor.exploitation.branch_store import BranchRecord
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat()
            record = BranchRecord(
                branch_id=branch_id,
                investigation_id=self.investigation_id,
                finding_id=finding_id,
                engine_id=self.engine_id,
                technique_class=technique_class,
                operator_params=operator_params or {},
                state="pending",
                artifact=None,
                artifact_type=None,
                exhaustion_record=None,
                stage_log=[],
                created_at=now,
                updated_at=now,
            )
            await self._branch_writer.create(record)
            self._active_branch_id = branch_id

    async def emit_stage(
        self, branch_id: str, state: str, payload: dict | None = None
    ) -> None:
        """Update branch state in exploitation_branches (V2 exploitation phase).

        No-op if no branch_writer is wired — V1 phase engines are unaffected.
        ExploitationOrchestrator wires branch_writer before dispatching V2 engines.

        V2.7: captures artifact from succeeded payloads into _last_artifact so
        ExecutionOrchestrator can pass it to vault_writer.export_finding().
        """
        if state == "succeeded" and payload and isinstance(payload.get("artifact"), dict):
            self._last_artifact = payload["artifact"]
        if state == "exhausted" and payload:
            raw = payload.get("exhaustion_record")
            if isinstance(raw, str):
                try:
                    import json as _json
                    self._last_exhaustion = _json.loads(raw)
                except Exception:
                    pass
            elif isinstance(raw, dict):
                self._last_exhaustion = raw
        if self._branch_writer is not None:
            await self._branch_writer.transition(branch_id, state, payload)

    async def fail_active_branch(self) -> None:
        """Transition the active branch to 'failed'. Called by ExecutionOrchestrator
        on engine crash or watchdog kill. No-op if no branch was created or no writer."""
        if self._branch_writer is not None and self._active_branch_id is not None:
            await self._branch_writer.transition(self._active_branch_id, "failed")

    def store_auth(self, investigation_id: str, auth: dict) -> None:
        """Persist obtained auth credentials to the investigation-scoped
        SessionOrchestrator store, making them available to downstream engines.

        Used by engines that produce auth state as their exploitation outcome
        (e.g., DefaultCredsEngine). Engines read existing auth via
        session_store.get_auth(); they write back via this method.
        """
        self._session_orch.store_auth(investigation_id, auth)


# ── Engine ABC ────────────────────────────────────────────────────────────────


class Engine(ABC):
    """Base class all engines must implement.

    Conformance rules (from docs/architecture/orchestration.md):
    - Stateless across run() calls.
    - Read auth from session_store; never re-authenticate.
    - Push findings via output_channel.emit_finding() as they emerge.
    - Respond to cancel() within 5 seconds.
    - Report capabilities truthfully.
    """

    engine_id: str  # class-level constant; must be unique across registry

    @property
    @abstractmethod
    def capabilities(self) -> EngineCapabilities:
        ...

    @abstractmethod
    async def run(
        self,
        target: str,
        config: dict,
        session_store: SessionStore,
        output_channel: OutputChannel,
        extended_payloads: list | None = None,
        extended_wordlists: list | None = None,
    ) -> EngineResult:
        ...

    @abstractmethod
    async def cancel(self) -> None:
        ...

    @abstractmethod
    def health_check(self) -> EngineHealth:
        ...


# ── Engine registry ───────────────────────────────────────────────────────────


class _EngineRegistry:
    """Maps engine_id → Engine instance. Populated via @engine_registry.register."""

    def __init__(self) -> None:
        self._engines: dict[str, Engine] = {}

    def register(self, cls: type[Engine]) -> type[Engine]:
        """Class decorator that instantiates and registers an Engine subclass."""
        instance = cls()
        self._engines[instance.engine_id] = instance
        logger.debug("registered engine %s", instance.engine_id)
        return cls

    def get(self, engine_id: str) -> Engine | None:
        return self._engines.get(engine_id)

    def all_engines(self) -> list[Engine]:
        return list(self._engines.values())

    def engines_for_phase(self, phase: str) -> list[Engine]:
        return [e for e in self._engines.values() if phase in e.capabilities.phases]

    def __len__(self) -> int:
        return len(self._engines)


engine_registry = _EngineRegistry()
