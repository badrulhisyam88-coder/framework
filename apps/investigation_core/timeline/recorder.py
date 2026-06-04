"""TimelineRecorder — thin wrapper over TimelineRepository with typed factory methods."""

from __future__ import annotations

from typing import Any

import aiosqlite

from apps.investigation_core.models.timeline import TimelineEvent
from apps.investigation_core.storage.timeline_repo import TimelineRepository
from apps.investigation_core.taxonomy.stages import EventType


class TimelineRecorder:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._repo = TimelineRepository(db)

    async def record(
        self,
        investigation_id: str,
        event_type: EventType,
        summary: str,
        detail: dict[str, Any] | None = None,
        actor: str = "system",
    ) -> TimelineEvent:
        event = TimelineEvent(
            investigation_id=investigation_id,
            event_type=event_type,
            summary=summary,
            detail=detail or {},
            actor=actor,
        )
        await self._repo.insert(event)
        return event

    async def investigation_created(self, investigation_id: str, title: str) -> TimelineEvent:
        return await self.record(
            investigation_id,
            EventType.INVESTIGATION_CREATED,
            f"Investigation '{title}' created",
            {"title": title},
        )

    async def scan_started(self, investigation_id: str, target: str) -> TimelineEvent:
        return await self.record(
            investigation_id,
            EventType.SCAN_STARTED,
            f"Scan started on {target}",
            {"target": target},
        )

    async def finding_detected(
        self,
        investigation_id: str,
        finding_id: str,
        finding_type: str,
        severity: str,
    ) -> TimelineEvent:
        return await self.record(
            investigation_id,
            EventType.FINDING_DETECTED,
            f"{severity.capitalize()} {finding_type} finding detected",
            {"finding_id": finding_id, "finding_type": finding_type, "severity": severity},
        )

    async def finding_validated(
        self,
        investigation_id: str,
        finding_id: str,
        validation_status: str,
    ) -> TimelineEvent:
        return await self.record(
            investigation_id,
            EventType.FINDING_VALIDATED,
            f"Finding validated: {validation_status}",
            {"finding_id": finding_id, "validation_status": validation_status},
        )

    async def learning_path_started(
        self,
        investigation_id: str,
        path_id: str,
        path_title: str,
        actor: str = "user",
    ) -> TimelineEvent:
        return await self.record(
            investigation_id,
            EventType.LEARNING_PATH_STARTED,
            f"Learning path started: {path_title}",
            {"path_id": path_id, "path_title": path_title},
            actor=actor,
        )

    async def learning_step_completed(
        self,
        investigation_id: str,
        path_id: str,
        step_id: str,
        step_title: str,
        actor: str = "user",
    ) -> TimelineEvent:
        return await self.record(
            investigation_id,
            EventType.LEARNING_STEP_COMPLETED,
            f"Completed step: {step_title}",
            {"path_id": path_id, "step_id": step_id, "step_title": step_title},
            actor=actor,
        )

    async def evidence_attached(
        self,
        investigation_id: str,
        ref: str,
        actor: str = "user",
    ) -> TimelineEvent:
        return await self.record(
            investigation_id,
            EventType.EVIDENCE_ATTACHED,
            f"Evidence attached: {ref}",
            {"ref": ref},
            actor=actor,
        )

    async def knowledge_exported(
        self,
        investigation_id: str,
        export_path: str,
    ) -> TimelineEvent:
        return await self.record(
            investigation_id,
            EventType.KNOWLEDGE_EXPORTED,
            "Knowledge exported to vault",
            {"export_path": export_path},
        )

    async def stage_advanced(
        self,
        investigation_id: str,
        from_stage: str,
        to_stage: str,
    ) -> TimelineEvent:
        return await self.record(
            investigation_id,
            EventType.STAGE_ADVANCED,
            f"Stage advanced: {from_stage} → {to_stage}",
            {"from_stage": from_stage, "to_stage": to_stage},
        )
