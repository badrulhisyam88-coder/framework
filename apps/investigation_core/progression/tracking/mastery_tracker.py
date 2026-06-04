"""MasteryTracker — orchestrates mastery scoring, unlocks, and timeline events."""

from __future__ import annotations

import aiosqlite

from apps.investigation_core.progression.models.mastery import MasteryStatus, SkillMastery
from apps.investigation_core.progression.storage.mastery_repo import MasteryRepository
from apps.investigation_core.progression.unlocks.unlock_engine import UnlockEngine
from apps.investigation_core.progression.validation.mastery_validator import MasteryValidator
from apps.investigation_core.skills.graph.skill_graph import skill_graph
from apps.investigation_core.taxonomy.stages import EventType
from apps.investigation_core.timeline.recorder import TimelineRecorder
from sdk import Logger


class MasteryTracker:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db
        self._repo = MasteryRepository(db)
        self._recorder = TimelineRecorder(db)
        self._unlock = UnlockEngine(skill_graph)

    async def sync_investigation(
        self,
        investigation_id: str,
        finding_types: list[str],
        evidence_artifact_types: list[str],
        completed_learning_path_ids: list[str],
        completed_action_ids: list[str],
    ) -> list[SkillMastery]:
        """Sync mastery state for all relevant skills in one pass.

        1. Ensure skill_mastery rows exist for relevant skills
        2. Unlock newly available skills
        3. Recompute confidence scores
        4. Advance statuses
        5. Record timeline events for transitions
        Returns the updated mastery list.
        """
        existing = await self._repo.list_for_investigation(investigation_id)
        mastery_map: dict[str, SkillMastery] = {m.skill_id: m for m in existing}

        # Unlock newly available skills
        newly_available_ids = self._unlock.compute_available_skills(
            finding_types, existing
        )
        for skill_id in newly_available_ids:
            if skill_id not in mastery_map:
                m = SkillMastery(
                    skill_id=skill_id,
                    investigation_id=investigation_id,
                    status=MasteryStatus.AVAILABLE,
                )
                await self._repo.upsert(m)
                mastery_map[skill_id] = m
                skill = skill_graph.get(skill_id)
                await self._recorder.record(
                    investigation_id,
                    EventType.SKILL_UNLOCKED,
                    f"Skill unlocked: {skill.title if skill else skill_id}",
                    detail={"skill_id": skill_id},
                )
                Logger.info(
                    "skill.unlocked",
                    extra={"investigation_id": investigation_id, "skill_id": skill_id},
                )
            elif mastery_map[skill_id].status == MasteryStatus.LOCKED:
                mastery_map[skill_id].status = MasteryStatus.AVAILABLE
                await self._repo.upsert(mastery_map[skill_id])

        # Recompute scores for all non-locked skills
        updated: list[SkillMastery] = []
        for m in list(mastery_map.values()):
            if m.status == MasteryStatus.LOCKED:
                updated.append(m)
                continue

            skill = skill_graph.get(m.skill_id)
            if not skill:
                updated.append(m)
                continue

            score = MasteryValidator.score(
                skill,
                evidence_artifact_types,
                completed_learning_path_ids,
                completed_action_ids,
                current_status=m.status,
            )

            old_status = m.status
            m.confidence_score = score.confidence
            m.status = score.derived_status
            if score.derived_status == MasteryStatus.IN_PROGRESS and not m.started_at:
                from datetime import datetime
                m.started_at = datetime.utcnow()

            if old_status != m.status:
                await self._repo.upsert(m)
                if m.status == MasteryStatus.MASTERED:
                    await self._recorder.record(
                        investigation_id,
                        EventType.SKILL_MASTERED,
                        f"Skill mastered: {skill.title}",
                        detail={"skill_id": m.skill_id, "confidence": score.confidence},
                    )
                    Logger.info(
                        "skill.mastered",
                        extra={"investigation_id": investigation_id,
                               "skill_id": m.skill_id},
                    )
            elif m.confidence_score != score.confidence:
                await self._repo.upsert(m)

            updated.append(m)

        return updated

    async def get_mastery(
        self, investigation_id: str
    ) -> list[SkillMastery]:
        return await self._repo.list_for_investigation(investigation_id)

    async def manual_validate(
        self,
        investigation_id: str,
        skill_id: str,
    ) -> SkillMastery:
        """Manually mark a skill as mastered (operator override)."""
        from datetime import datetime
        m = await self._repo.get(investigation_id, skill_id)
        if not m:
            m = SkillMastery(
                skill_id=skill_id,
                investigation_id=investigation_id,
                status=MasteryStatus.MASTERED,
                confidence_score=1.0,
                validated_at=datetime.utcnow(),
            )
        else:
            m.status = MasteryStatus.MASTERED
            m.confidence_score = 1.0
            m.validated_at = datetime.utcnow()
        await self._repo.upsert(m)
        skill = skill_graph.get(skill_id)
        await self._recorder.record(
            investigation_id,
            EventType.SKILL_MASTERED,
            f"Skill mastered (manual): {skill.title if skill else skill_id}",
            detail={"skill_id": skill_id, "manual": True},
            actor="user",
        )
        return m
