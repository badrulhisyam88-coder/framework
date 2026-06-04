"""StorageBridge — routes conductor findings to the existing persistence path.

Translates a raw finding dict (conductor schema) into a FindingEvent and
calls the existing persist_fn callback set up by the investigation workspace
API routes.

All imports of investigation_workspace.probe.events are deferred to avoid
pulling aiosqlite at module load time (not installed in all environments).
"""
from __future__ import annotations

import logging
from collections.abc import Callable

logger = logging.getLogger("conductor.findings.storage_bridge")


class StorageBridge:
    """Translates conductor finding dicts → FindingEvent → persist_fn call."""

    def __init__(self, persist_fn: Callable | None = None) -> None:
        self._persist_fn = persist_fn

    async def persist(self, finding: dict, investigation_id: str) -> str | None:
        if self._persist_fn is None:
            return None

        from apps.investigation_workspace.probe.events import FindingEvent

        fe = FindingEvent(
            after_stage_index=0,
            finding_type=finding.get("category", "unknown"),
            title=finding.get("title", ""),
            severity=finding.get("severity", "info"),
            description=finding.get("description", ""),
            endpoint=finding.get("path"),
            port=None,
            evidence=finding.get("evidence", {}),
            phase=finding.get("phase", "recon"),
            id=finding.get("id"),
            confidence=finding.get("confidence"),
            next_actions=finding.get("next_actions"),
            source_scanner=finding.get("probe_id", "unknown"),
        )
        try:
            return await self._persist_fn(fe)
        except Exception as exc:
            logger.error("storage_bridge: persist_fn raised: %s", exc)
            return None
