"""Mock engines for wiring verification (PR A).

MockEngineSimple — emits 3 plain findings; no next_actions.
MockEngineChained — emits 2 findings:
  - one with next_actions=[auto_fire → mock_simple]  (chain dispatch test)
  - one with next_actions=[auto_fire → mock_chained] (cycle/depth-limit test)

Both respond to cancel() within 1 second and record every outbound
"request" via output_channel.record_request() using target "mock://test".

Design note: _cancel_event is created fresh at the top of run() — not in
__init__ — because asyncio.Event binds to the event loop at creation time.
Since engines are registered as singletons at module import (before any test
event loop exists), creating the Event in __init__ would bind it to the wrong
loop and raise "bound to a different event loop" when run() is called.
"""
from __future__ import annotations

import asyncio
import logging
import time
from uuid import uuid4

from apps.conductor.engines.base import (
    Engine,
    EngineCapabilities,
    EngineHealth,
    EngineResult,
    OutputChannel,
    SessionStore,
    engine_registry,
)

logger = logging.getLogger("conductor.engines.mock")

_MOCK_TARGET = "mock://test"


@engine_registry.register
class MockEngineSimple(Engine):
    """Emits 3 plain findings, no chains, no cycles."""

    engine_id = "mock_simple"

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(
            phases=("recon",),
            finding_types=("mock_finding",),
            target_types=("any",),
            resource_cost="light",
            concurrency_safe_with=("mock_chained",),
            mutex_with=(),
        )

    def __init__(self) -> None:
        # Cancel event created per-run (see module docstring)
        self._cancel_event: asyncio.Event | None = None
        self._last_heartbeat = time.time()
        self._running = False

    async def run(
        self,
        target: str,
        config: dict,
        session_store: SessionStore,
        output_channel: OutputChannel,
    ) -> EngineResult:
        self._cancel_event = asyncio.Event()  # bound to the current loop
        self._running = True
        self._last_heartbeat = time.time()
        logger.info("mock_simple: starting against %s", target)

        await output_channel.record_request(_MOCK_TARGET)

        try:
            await asyncio.wait_for(self._cancel_event.wait(), timeout=2.0)
            logger.info("mock_simple: cancelled during sleep")
            self._running = False
            return EngineResult(status="cancelled", findings_count=0)
        except TimeoutError:
            pass  # normal path — sleep elapsed

        self._last_heartbeat = time.time()
        emitted = 0
        for i in range(3):
            if self._cancel_event.is_set():
                break
            finding = {
                "id": f"fnd_mock_simple_{i:02d}",
                "phase": "recon",
                "category": "mock_finding",
                "title": f"Mock Simple Finding {i}",
                "severity": "info",
                "description": f"Synthetic finding {i} from mock_simple",
                "evidence": {"index": i, "engine": "mock_simple"},
                "next_actions": None,
            }
            await output_channel.emit_finding(finding)
            emitted += 1
            self._last_heartbeat = time.time()

        self._running = False
        logger.info("mock_simple: completed, emitted %d findings", emitted)
        return EngineResult(status="success", findings_count=emitted)

    async def cancel(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()
        for _ in range(10):
            if not self._running:
                return
            await asyncio.sleep(0.1)

    def health_check(self) -> EngineHealth:
        return EngineHealth(
            status="healthy" if self._running else "idle",
            last_heartbeat=self._last_heartbeat,
        )


class MockEngineFailing(Engine):
    """Raises RuntimeError in run() to simulate a catastrophic engine failure.

    NOT registered with @engine_registry.register — direct instantiation only.
    Used in tests that need to exercise error-handling paths without adding
    a permanently failing engine to the shared registry.
    """

    engine_id = "mock_failing"

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(
            phases=("recon",),
            finding_types=(),
            target_types=("any",),
            resource_cost="light",
            concurrency_safe_with=("*",),
            mutex_with=(),
        )

    def __init__(self) -> None:
        self._last_heartbeat = time.time()

    async def run(
        self,
        target: str,
        config: dict,
        session_store: SessionStore,
        output_channel: OutputChannel,
    ) -> EngineResult:
        raise RuntimeError("MockEngineFailing: intentional run() exception")

    async def cancel(self) -> None:
        pass

    def health_check(self) -> EngineHealth:
        return EngineHealth(status="idle", last_heartbeat=self._last_heartbeat)


@engine_registry.register
class MockEngineChained(Engine):
    """Emits 2 findings with next_actions for chain dispatch and cycle tests."""

    engine_id = "mock_chained"

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(
            phases=("recon",),
            finding_types=("mock_finding",),
            target_types=("any",),
            resource_cost="light",
            concurrency_safe_with=("mock_simple",),
            mutex_with=(),
        )

    def __init__(self) -> None:
        self._cancel_event: asyncio.Event | None = None
        self._last_heartbeat = time.time()
        self._running = False

    async def run(
        self,
        target: str,
        config: dict,
        session_store: SessionStore,
        output_channel: OutputChannel,
    ) -> EngineResult:
        self._cancel_event = asyncio.Event()  # bound to the current loop
        self._running = True
        self._last_heartbeat = time.time()
        logger.info("mock_chained: starting against %s", target)

        await output_channel.record_request(_MOCK_TARGET)

        try:
            await asyncio.wait_for(self._cancel_event.wait(), timeout=2.0)
            logger.info("mock_chained: cancelled during sleep")
            self._running = False
            return EngineResult(status="cancelled", findings_count=0)
        except TimeoutError:
            pass

        self._last_heartbeat = time.time()

        # Finding 1: triggers a chain dispatch to mock_simple (linear chain)
        chain_finding = {
            "id": "fnd_mock_chained_chain",
            "phase": "recon",
            "category": "mock_finding",
            "title": "Mock Chained Finding — triggers mock_simple",
            "severity": "info",
            "description": "Synthetic finding that auto-fires mock_simple",
            "evidence": {"engine": "mock_chained", "type": "chain"},
            "next_actions": [
                {
                    "engine_id": "mock_simple",
                    "trigger": "auto_fire",
                    "description": "Auto-fire mock_simple from chain",
                }
            ],
        }

        # Finding 2: triggers a chain back to itself (cycle — depth limit test).
        # ID is unique per run so dedup does not swallow the cycle — the depth
        # limit in ChainOrchestrator is what stops infinite dispatch.
        cycle_finding = {
            "id": f"fnd_mock_chained_cycle_{uuid4().hex[:8]}",
            "phase": "recon",
            "category": "mock_finding",
            "title": "Mock Chained Finding — self-referential cycle",
            "severity": "info",
            "description": "Synthetic finding that auto-fires mock_chained (cycle)",
            "evidence": {"engine": "mock_chained", "type": "cycle"},
            "next_actions": [
                {
                    "engine_id": "mock_chained",
                    "trigger": "auto_fire",
                    "description": "Auto-fire mock_chained (cycle test)",
                }
            ],
        }

        emitted = 0
        for finding in (chain_finding, cycle_finding):
            if self._cancel_event.is_set():
                break
            await output_channel.emit_finding(finding)
            emitted += 1
            self._last_heartbeat = time.time()

        self._running = False
        logger.info("mock_chained: completed, emitted %d findings", emitted)
        return EngineResult(status="success", findings_count=emitted)

    async def cancel(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()
        for _ in range(10):
            if not self._running:
                return
            await asyncio.sleep(0.1)

    def health_check(self) -> EngineHealth:
        return EngineHealth(
            status="healthy" if self._running else "idle",
            last_heartbeat=self._last_heartbeat,
        )
