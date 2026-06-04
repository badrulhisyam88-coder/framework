"""EvidenceService — persist and retrieve evidence artifacts with timeline integration."""

from __future__ import annotations

from typing import Any

import aiosqlite

from apps.investigation_core.evidence.models.artifact import ArtifactType, EvidenceArtifact
from apps.investigation_core.evidence.storage.artifact_repo import ArtifactRepository
from apps.investigation_core.evidence.validation.rules import (
    validate_artifact,
)
from apps.investigation_core.storage.timeline_repo import TimelineRepository
from apps.investigation_core.taxonomy.stages import EventType
from apps.investigation_core.timeline.recorder import TimelineRecorder
from sdk import Logger


class EvidenceService:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db
        self._repo = ArtifactRepository(db)
        self._recorder = TimelineRecorder(db)
        self._tl_repo = TimelineRepository(db)

    async def capture(
        self,
        investigation_id: str,
        artifact_type: ArtifactType,
        title: str,
        content: str,
        *,
        description: str = "",
        finding_id: str | None = None,
        learning_path_id: str | None = None,
        guided_action_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        actor: str = "user",
    ) -> EvidenceArtifact:
        artifact = EvidenceArtifact(
            investigation_id=investigation_id,
            finding_id=finding_id,
            learning_path_id=learning_path_id,
            guided_action_id=guided_action_id,
            artifact_type=artifact_type,
            title=title,
            description=description,
            content=content,
            created_by=actor,
            metadata=metadata or {},
            tags=tags or [],
        )
        validate_artifact(artifact)
        await self._repo.insert(artifact)

        # Timeline event
        await self._recorder.record(
            investigation_id,
            EventType.EVIDENCE_CAPTURED,
            f"Evidence captured: {title}",
            detail={
                "evidence_id": artifact.evidence_id,
                "artifact_type": str(artifact_type),
                "finding_id": finding_id,
                "guided_action_id": guided_action_id,
            },
            actor=actor,
        )
        Logger.info(
            "evidence.captured",
            extra={
                "evidence_id": artifact.evidence_id,
                "investigation_id": investigation_id,
                "artifact_type": str(artifact_type),
            },
        )

        # Progression resync — captured evidence is the strongest progression signal
        try:
            from apps.investigation_core.progression.triggers.progression_trigger import (
                ProgressionTrigger,
            )
            await ProgressionTrigger(self._db).resync(investigation_id)
        except Exception as exc:
            Logger.info(
                "evidence.progression_resync_error",
                extra={"investigation_id": investigation_id, "error": str(exc)},
            )

        return artifact

    async def get_by_id(self, evidence_id: str) -> EvidenceArtifact | None:
        return await self._repo.get_by_id(evidence_id)

    async def list_for_investigation(
        self, investigation_id: str, limit: int = 200
    ) -> list[EvidenceArtifact]:
        return await self._repo.list_for_investigation(investigation_id, limit=limit)

    async def list_for_finding(self, finding_id: str) -> list[EvidenceArtifact]:
        return await self._repo.list_for_finding(finding_id)

    async def list_for_guided_action(
        self, investigation_id: str, guided_action_id: str
    ) -> list[EvidenceArtifact]:
        return await self._repo.list_for_guided_action(investigation_id, guided_action_id)

    async def delete(self, evidence_id: str, actor: str = "user") -> None:
        artifact = await self._repo.get_by_id(evidence_id)
        if artifact:
            await self._repo.delete(evidence_id)
            Logger.info(
                "evidence.deleted",
                extra={"evidence_id": evidence_id, "actor": actor},
            )

    async def count(self, investigation_id: str) -> int:
        return await self._repo.count_for_investigation(investigation_id)
