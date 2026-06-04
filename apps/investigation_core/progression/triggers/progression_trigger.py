"""ProgressionTrigger — single entry point to recompute mastery from real activity.

Called from:
  - ApprovalService.complete()        (after explicit user action completion)
  - EvidenceService.capture()         (after evidence artifact captured)

Phase 59a — MilestoneService.achieve() removed alongside the milestone
subsystem; it was a third trigger entry point but is gone.

NOT called from scan completion. Passive scanning never advances mastery —
it only unlocks AVAILABLE skills via the existing MasteryTracker.sync flow.
This trigger always passes the freshest evidence/action/path lists so the
mastery score reflects actual investigation activity, not scan output.
"""

from __future__ import annotations

import aiosqlite

from apps.investigation_core.progression.models.mastery import SkillMastery
from sdk import Logger


class ProgressionTrigger:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def resync(self, investigation_id: str) -> list[SkillMastery]:
        """Recompute mastery using the latest evidence + actions + paths."""
        from apps.investigation_core.evidence.storage.artifact_repo import (
            ArtifactRepository,
        )
        from apps.investigation_core.guided_actions.approvals.approval_service import (
            ApprovalService,
        )
        from apps.investigation_core.guided_actions.models.approval import ApprovalStatus
        from apps.investigation_core.progression.tracking.mastery_tracker import (
            MasteryTracker,
        )
        from apps.investigation_core.services.investigation_service import (
            InvestigationService,
        )
        from apps.investigation_core.storage.learning_repo import (
            LearningProgressRepository,
        )
        from apps.scanner_orchestration.storage.finding_repo import (
            NormalizedFindingRepository,
        )

        try:
            inv_svc = InvestigationService(self._db)
            inv = await inv_svc.get_by_id(investigation_id)
            if not inv:
                return []

            finding_types = await inv_svc._finding_types_for_investigation(inv)
            norm_repo = NormalizedFindingRepository(self._db)
            norm_types = await norm_repo.distinct_finding_types(investigation_id)
            all_types = list(set(finding_types + norm_types))

            lr_repo = LearningProgressRepository(self._db)
            all_progress = await lr_repo.list_for_investigation(investigation_id)
            completed_paths = [
                p.path_id for p in all_progress if str(p.status) == "completed"
            ]

            art_repo = ArtifactRepository(self._db)
            artifacts = await art_repo.list_for_investigation(investigation_id)
            artifact_types = [str(a.artifact_type) for a in artifacts]

            approval_svc = ApprovalService(self._db)
            approvals = await approval_svc.list_approvals(investigation_id)
            completed_actions = [
                a.action_id for a in approvals if a.status == ApprovalStatus.COMPLETED
            ]

            tracker = MasteryTracker(self._db)
            return await tracker.sync_investigation(
                investigation_id,
                all_types,
                artifact_types,
                completed_paths,
                completed_actions,
            )
        except Exception as exc:
            Logger.info(
                "progression.resync_error",
                extra={"investigation_id": investigation_id, "error": str(exc)},
            )
            return []
