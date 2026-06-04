"""InvestigationService — business logic tying all investigation_core sub-systems."""

from __future__ import annotations

from typing import Any

import aiosqlite

from apps.investigation_core.learning.recommendation_engine import RecommendationEngine
from apps.investigation_core.lifecycle.state_machine import InvestigationStateMachine
from apps.investigation_core.models.investigation import Investigation
from apps.investigation_core.models.learning import (
    LearningPathProgress,
    LearningPathStatus,
    PathRecommendation,
)
from apps.investigation_core.models.timeline import TimelineEvent
from apps.investigation_core.storage.investigation_repo import InvestigationRepository
from apps.investigation_core.storage.learning_repo import LearningProgressRepository
from apps.investigation_core.storage.timeline_repo import TimelineRepository
from apps.investigation_core.taxonomy.stages import EventType, WorkflowStage
from apps.investigation_core.timeline.recorder import TimelineRecorder
from sdk import Logger


class InvestigationService:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db
        self._inv_repo = InvestigationRepository(db)
        self._tl_repo = TimelineRepository(db)
        self._lr_repo = LearningProgressRepository(db)
        self._recorder = TimelineRecorder(db)
        self._recommender = RecommendationEngine()

    # -------------------------------------------------------------------------
    # Investigation lifecycle
    # -------------------------------------------------------------------------

    async def get_or_create(
        self,
        target: str,
        *,
        title: str | None = None,
    ) -> tuple[Investigation, bool]:
        """Return (investigation, created). Creates a new investigation if none exists.

        Phase 46 — the operator-typed target is normalized HERE, at the single
        intake point, before anything stores or queries it. Downstream code
        reads inv.targets[0] and trusts it as canonical. The normalization
        action trail is logged so any future "wrong target" report can be
        traced from intake forward without guessing.
        """
        # Lazy import — workspace lives above core in the dep graph, but the
        # normalize helper is pure (no further imports) so the cycle is fine.
        from apps.investigation_workspace.probe.normalize import normalize_target

        canonical, norm_actions = normalize_target(target)
        if canonical and canonical != target:
            Logger.info(
                "investigation.target_canonicalized",
                extra={
                    "raw_target":       target,
                    "canonical_target": canonical,
                    "actions":          norm_actions,
                },
            )
        # If normalization rejected the input, fall back to the raw target —
        # we'd rather create a flagged investigation than 500 on intake.
        # Downstream code (probe, scanners) will see and report the issue.
        canonical = canonical or target

        # Guard: reject blank targets so investigations with targets=[""]
        # are never created (they produce unfindable branches and stale state).
        if not canonical or not canonical.strip():
            Logger.warning(
                "investigation.blank_target_rejected",
                extra={"raw_target": target},
            )
            raise ValueError(
                "Cannot create an investigation with a blank target. "
                "Provide a valid URL or hostname."
            )

        existing = await self._inv_repo.get_by_target(canonical)
        if existing:
            return existing, False

        inv_title = title or f"Investigation: {canonical}"
        inv = Investigation(
            title=inv_title,
            targets=[canonical],
            workflow_stage=WorkflowStage.DISCOVERY,
        )
        await self._inv_repo.insert(inv)
        await self._recorder.investigation_created(inv.investigation_id, inv_title)
        Logger.info(
            "investigation.created",
            extra={
                "investigation_id": inv.investigation_id,
                "canonical_target": canonical,
                "raw_target":       target if target != canonical else None,
            },
        )
        return inv, True

    async def get_by_id(self, investigation_id: str) -> Investigation | None:
        return await self._inv_repo.get_by_id(investigation_id)

    async def list_all(self, limit: int = 200) -> list[Investigation]:
        return await self._inv_repo.list_all(limit=limit)

    # -------------------------------------------------------------------------
    # Event recording
    # -------------------------------------------------------------------------

    async def record_scan_started(
        self, investigation_id: str, target: str
    ) -> TimelineEvent:
        event = await self._recorder.scan_started(investigation_id, target)
        Logger.info(
            "investigation.scan_started",
            extra={"investigation_id": investigation_id, "target": target},
        )
        return event

    async def record_finding_detected(
        self,
        investigation_id: str,
        finding_id: str,
        finding_type: str,
        severity: str,
    ) -> TimelineEvent:
        await self._inv_repo.add_finding(investigation_id, finding_id)
        event = await self._recorder.finding_detected(
            investigation_id, finding_id, finding_type, severity
        )
        await self._maybe_advance_stage(investigation_id)
        Logger.info(
            "investigation.finding_detected",
            extra={
                "investigation_id": investigation_id,
                "finding_id": finding_id,
                "severity": severity,
            },
        )
        return event

    async def record_finding_validated(
        self,
        investigation_id: str,
        finding_id: str,
        validation_status: str,
    ) -> TimelineEvent:
        event = await self._recorder.finding_validated(
            investigation_id, finding_id, validation_status
        )
        await self._maybe_advance_stage(investigation_id)
        return event

    async def record_knowledge_exported(
        self, investigation_id: str, export_path: str
    ) -> TimelineEvent:
        event = await self._recorder.knowledge_exported(investigation_id, export_path)
        inv = await self._inv_repo.get_by_id(investigation_id)
        if inv and inv.workflow_stage != WorkflowStage.KNOWLEDGE_EXPORT:
            await self._set_stage(inv, WorkflowStage.KNOWLEDGE_EXPORT)
        if export_path not in (inv.evidence_refs if inv else []):
            if inv:
                inv.evidence_refs.append(export_path)
                await self._inv_repo.update(inv)
        return event

    # -------------------------------------------------------------------------
    # Learning paths
    # -------------------------------------------------------------------------

    async def get_recommendations(
        self, investigation_id: str
    ) -> list[PathRecommendation]:
        inv = await self._inv_repo.get_by_id(investigation_id)
        if not inv:
            return []
        progress_list = await self._lr_repo.list_for_investigation(investigation_id)
        active_ids = [p.path_id for p in progress_list if p.status == LearningPathStatus.ACTIVE]
        completed_ids = [
            p.path_id for p in progress_list if p.status == LearningPathStatus.COMPLETED
        ]
        finding_types = await self._finding_types_for_investigation(inv)
        return self._recommender.recommend(
            finding_types,
            active_path_ids=active_ids,
            completed_path_ids=completed_ids,
        )

    async def start_learning_path(
        self,
        investigation_id: str,
        path_id: str,
        actor: str = "user",
    ) -> LearningPathProgress:
        existing = await self._lr_repo.get(investigation_id, path_id)
        if existing:
            return existing

        from apps.investigation_core.learning.path_registry import registry

        path = registry.get(path_id)
        path_title = path.title if path else path_id

        progress = LearningPathProgress(
            investigation_id=investigation_id,
            path_id=path_id,
        )
        await self._lr_repo.insert(progress)
        await self._inv_repo.set_active_learning_path(investigation_id, path_id)
        await self._recorder.learning_path_started(
            investigation_id, path_id, path_title, actor=actor
        )
        await self._maybe_advance_stage(investigation_id)
        return progress

    async def complete_step(
        self,
        investigation_id: str,
        path_id: str,
        step_id: str,
        actor: str = "user",
    ) -> LearningPathProgress:
        from apps.investigation_core.learning.path_registry import registry

        progress = await self._lr_repo.get(investigation_id, path_id)
        if not progress:
            raise ValueError(
                f"Learning path {path_id!r} not started for investigation {investigation_id!r}"
            )

        path = registry.get(path_id)
        step = path.step_by_id(step_id) if path else None
        step_title = step.title if step else step_id

        steps = path.guided_steps if path else []
        current_idx = next(
            (i for i, s in enumerate(steps) if s.step_id == step_id),
            progress.current_step_index,
        )
        next_index = current_idx + 1

        await self._lr_repo.advance_step(investigation_id, path_id, step_id, next_index)
        await self._recorder.learning_step_completed(
            investigation_id, path_id, step_id, step_title, actor=actor
        )

        # Mark path completed when all steps done.
        if path and next_index >= len(path.guided_steps):
            await self._lr_repo.mark_completed(investigation_id, path_id)
            await self._inv_repo.mark_learning_path_completed(investigation_id, path_id)
            Logger.info(
                "investigation.learning_path_completed",
                extra={"investigation_id": investigation_id, "path_id": path_id},
            )

        updated = await self._lr_repo.get(investigation_id, path_id)
        return updated or progress

    async def get_progress(
        self, investigation_id: str
    ) -> list[LearningPathProgress]:
        return await self._lr_repo.list_for_investigation(investigation_id)

    # -------------------------------------------------------------------------
    # Timeline
    # -------------------------------------------------------------------------

    async def get_timeline(
        self, investigation_id: str, limit: int = 200
    ) -> list[TimelineEvent]:
        return await self._tl_repo.list_for_investigation(investigation_id, limit=limit)

    async def record_raw_event(
        self,
        investigation_id: str,
        event_type: EventType,
        summary: str,
        detail: dict[str, Any] | None = None,
        actor: str = "system",
    ) -> TimelineEvent:
        return await self._recorder.record(
            investigation_id, event_type, summary, detail=detail, actor=actor
        )

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    async def _finding_types_for_investigation(self, inv: Investigation) -> list[str]:
        """Derive finding types from finding IDs via a raw DB query."""
        if not inv.findings:
            return []
        placeholders = ",".join("?" * len(inv.findings))
        async with self._db.execute(
            f"SELECT DISTINCT finding_type FROM findings WHERE id IN ({placeholders})",
            tuple(inv.findings),
        ) as cur:
            rows = await cur.fetchall()
        return [r[0] for r in rows]

    async def _maybe_advance_stage(self, investigation_id: str) -> None:
        inv = await self._inv_repo.get_by_id(investigation_id)
        if not inv:
            return

        progress_list = await self._lr_repo.list_for_investigation(investigation_id)
        learning_started = any(
            p.status == LearningPathStatus.ACTIVE for p in progress_list
        )
        has_knowledge_export = await self._tl_repo.has_event_type(
            investigation_id, EventType.KNOWLEDGE_EXPORTED
        )
        has_validated = await self._tl_repo.has_event_type(
            investigation_id, EventType.FINDING_VALIDATED
        )
        has_findings = len(inv.findings) > 0

        new_stage = InvestigationStateMachine.auto_advance(
            inv.workflow_stage,
            has_findings=has_findings,
            has_validated=has_validated,
            learning_started=learning_started,
            knowledge_exported=has_knowledge_export,
        )
        if new_stage != inv.workflow_stage:
            await self._set_stage(inv, new_stage)

    async def _set_stage(self, inv: Investigation, new_stage: WorkflowStage) -> None:
        old_stage = inv.workflow_stage
        await self._inv_repo.set_stage(inv.investigation_id, new_stage)
        await self._recorder.stage_advanced(inv.investigation_id, str(old_stage), str(new_stage))
        Logger.info(
            "investigation.stage_advanced",
            extra={
                "investigation_id": inv.investigation_id,
                "from": str(old_stage),
                "to": str(new_stage),
            },
        )
