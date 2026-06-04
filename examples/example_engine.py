"""Example engine — contract reference for conductor-framework adopters.

This file demonstrates the minimal Engine ABC implementation. It has no real
behavior: it emits one synthetic finding and returns success. Copy and adapt
this as the starting point for your domain engines.

See docs/productization/layer-contracts.md §4 for the full Engine contract.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from apps.conductor.engines.base import (
    Engine,
    EngineCapabilities,
    EngineHealth,
    EngineResult,
    engine_registry,
)

if TYPE_CHECKING:
    from apps.conductor.exploitation.branch_store import BranchWriter
    from apps.conductor.orchestrators.findings import FindingsOrchestrator
    from apps.conductor.orchestrators.session import SessionOrchestrator

logger = logging.getLogger("conductor.engines.example")


@engine_registry.register
class ExampleEngine(Engine):
    """Minimal engine — emits one synthetic finding, then returns success.

    Replace the run() body with your domain logic. The signature and
    OutputChannel calls are the contract that must be preserved.
    """

    engine_id: str = "example_event"  # unique ID; used by ExecutionOrchestrator.dispatch_engine()

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(
            phases=("enumeration",),         # which phases this engine runs in
            finding_types=("example_event",), # finding_type strings this engine emits
            target_types=("any",),            # "http" | "tcp" | "any"
            resource_cost="light",            # "light" | "medium" | "heavy"
        )

    async def run(
        self,
        target: str,
        config: dict,
        session_store,                        # SessionOrchestrator (read auth here)
        output_channel,                       # OutputChannel (emit findings here)
        *,
        extended_payloads: list | None = None,   # Seam 16 stub — reserved for re-invocation
        extended_wordlists: list | None = None,  # Seam 16 stub — reserved for re-invocation
    ) -> EngineResult:
        """Run the engine against target and emit findings via output_channel.

        Conformance rules (do not break these):
        1. Stateless — do not store state in self between invocations.
        2. Auth read-only — read from session_store; never call login endpoints.
        3. Stream findings immediately — call emit_finding() as they emerge.
        4. Respect cancel() within 5 s — check self._cancel_event regularly.
        5. Never create asyncio primitives in __init__ — create inside run().
        """
        self._cancel_event = asyncio.Event()

        logger.info("ExampleEngine.run: target=%s", target)

        # Emit one synthetic finding — replace with your domain logic
        finding = {
            "id": f"fnd_example_{target[:8]}",
            "category": "example",
            "title": "Example finding from ExampleEngine",
            "severity": "info",
            "evidence": {"target": target, "note": "synthetic — replace with real evidence"},
            "probe_id": "example_event",
            "phase": "enumeration",
        }
        await output_channel.emit_finding(finding)

        return EngineResult(status="success", findings_count=1, error=None)

    async def cancel(self) -> None:
        """Signal the engine to stop. Must complete within 5 s."""
        if hasattr(self, "_cancel_event"):
            self._cancel_event.set()

    def health_check(self) -> EngineHealth:
        return EngineHealth(healthy=True, reason="example engine always healthy")
