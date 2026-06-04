"""Findings Orchestrator — single ingress for all engine output.

Ingestion pipeline per docs/architecture/orchestration.md:
  1. Validate required fields
  2. Generate finding_id if absent
  3. Translate (stub in PR A — mock engines emit in target schema already)
  4. Dedup by finding_id (in-memory per investigation, PR A)
  5. Correlation stub (store only, no linking logic in PR A)
  6. Emit finding_ingested event to bus
  7. Notify ChainOrchestrator to evaluate next_actions
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apps.conductor.events.bus import EventBus
from apps.investigation_workspace.probe.finding_id import generate_finding_id

if TYPE_CHECKING:
    from apps.conductor.orchestrators.chain import ChainOrchestrator

logger = logging.getLogger("conductor.orchestrators.findings")

_REQUIRED_FIELDS = ("phase", "category", "title", "severity")


class FindingsOrchestrator:
    def __init__(self, investigation_id: str, bus: EventBus) -> None:
        self._investigation_id = investigation_id
        self._bus = bus
        self._chain_orch: ChainOrchestrator | None = None
        self._bridge = None  # StorageBridge | None — wired by Conductor when persist path is active

        # { finding_id: finding_dict } — in-memory store for PR A
        self._findings: dict[str, dict] = {}

    def wire_chain(self, chain_orch: ChainOrchestrator) -> None:
        self._chain_orch = chain_orch

    def wire_bridge(self, bridge) -> None:
        self._bridge = bridge

    # ── Ingress ───────────────────────────────────────────────────────────────

    async def ingest(self, finding: dict, engine_id: str) -> str | None:
        """Process one raw finding from an engine.

        Returns finding_id if a new/updated finding was emitted; None on dedup.
        """
        finding = dict(finding)  # shallow copy — don't mutate caller's dict

        # 1. Validate
        missing = [f for f in _REQUIRED_FIELDS if not finding.get(f)]
        if missing:
            logger.warning(
                "findings: dropping malformed finding from %s — missing fields: %s",
                engine_id,
                missing,
            )
            return None

        # 2. Generate ID if absent
        if not finding.get("id"):
            finding["id"] = generate_finding_id(
                probe_id=engine_id,
                target=finding.get("endpoint", "unknown"),
                path=finding.get("phase", "unknown"),
                finding_type=finding.get("category", "unknown"),
            )

        finding_id = finding["id"]

        # 3. Translation — stub; mock engines already conform to schema

        # 4. Dedup
        if finding_id in self._findings:
            existing = self._findings[finding_id]
            # Merge evidence dicts if present
            if "evidence" in finding and "evidence" in existing:
                existing["evidence"].update(finding["evidence"])
            logger.debug("findings: deduped %s from engine %s", finding_id, engine_id)
            await self._bus.emit(
                orchestrator="findings",
                event_type="finding_updated",
                investigation_id=self._investigation_id,
                payload={"finding_id": finding_id, "engine_id": engine_id},
            )
            return None  # deduped — don't re-evaluate next_actions

        # 5. Store (correlation stub — just persist; linking deferred to later PR)
        self._findings[finding_id] = finding

        # 6. Emit to bus
        await self._bus.emit(
            orchestrator="findings",
            event_type="finding_ingested",
            investigation_id=self._investigation_id,
            payload={"finding_id": finding_id, "engine_id": engine_id, "finding": finding},
        )

        # 7. Notify Chain Orchestrator
        if self._chain_orch is not None:
            await self._chain_orch.evaluate_finding(finding)

        # 8. Forward to StorageBridge (persist to investigation workspace DB)
        if self._bridge is not None:
            try:
                await self._bridge.persist(finding, self._investigation_id)
            except Exception as exc:
                logger.error("findings: storage_bridge.persist failed: %s", exc)

        logger.info(
            "findings: ingested %s (%s) from %s",
            finding_id,
            finding.get("title", "?"),
            engine_id,
        )
        return finding_id

    # ── Queries ───────────────────────────────────────────────────────────────

    def get_finding(self, finding_id: str) -> dict | None:
        return self._findings.get(finding_id)

    def list_findings(self) -> list[dict]:
        return list(self._findings.values())

    def count(self) -> int:
        return len(self._findings)

    def get_state(self) -> dict:
        return {
            "orchestrator": "findings",
            "investigation_id": self._investigation_id,
            "finding_count": len(self._findings),
        }
