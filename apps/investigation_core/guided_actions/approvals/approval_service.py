"""ApprovalService — manage the human-approval gate for guided actions."""

from __future__ import annotations

import json
from datetime import datetime

import aiosqlite

from apps.investigation_core.guided_actions.models.action import GuidedAction
from apps.investigation_core.guided_actions.models.approval import (
    ActionApproval,
    ApprovalStatus,
)
from apps.investigation_core.guided_actions.registry.action_registry import (
    ActionRegistry,
)
from apps.investigation_core.guided_actions.registry.action_registry import (
    action_registry as _global_registry,
)
from apps.investigation_core.taxonomy.stages import EventType
from apps.investigation_core.timeline.recorder import TimelineRecorder
from sdk import Logger


def _row_to_approval(row: aiosqlite.Row) -> ActionApproval:
    return ActionApproval(
        approval_id=row["approval_id"],
        investigation_id=row["investigation_id"],
        action_id=row["action_id"],
        finding_id=row["finding_id"],
        status=ApprovalStatus(row["status"]),
        requested_at=datetime.fromisoformat(row["requested_at"]),
        reviewed_at=(
            datetime.fromisoformat(row["reviewed_at"]) if row["reviewed_at"] else None
        ),
        completed_at=(
            datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None
        ),
        notes=row["notes"],
        evidence_refs=json.loads(row["evidence_refs"] or "[]"),
    )


class ApprovalService:
    def __init__(
        self,
        db: aiosqlite.Connection,
        registry: ActionRegistry | None = None,
    ) -> None:
        self._db = db
        self._registry = registry or _global_registry
        self._recorder = TimelineRecorder(db)

    # -------------------------------------------------------------------------
    # Recommendation
    # -------------------------------------------------------------------------

    async def recommend_actions(
        self, investigation_id: str, finding_types: list[str]
    ) -> list[tuple[GuidedAction, ActionApproval | None]]:
        """Return [(action, approval_or_None)] sorted by risk level ascending.

        Approval is None when no request exists yet for this investigation+action.
        """
        existing = await self._list_approvals(investigation_id)
        approval_by_action: dict[str, ActionApproval] = {
            a.action_id: a for a in existing
        }

        seen: set[str] = set()
        results: list[tuple[GuidedAction, ActionApproval | None]] = []
        for ft in finding_types:
            for action in self._registry.actions_for_finding_type(ft):
                if action.action_id in seen:
                    continue
                seen.add(action.action_id)
                approval = approval_by_action.get(action.action_id)
                results.append((action, approval))

        # Sort: incomplete actions first, then by risk (low → high)
        _risk_order = {"informational": 0, "low": 1, "medium": 2, "high": 3}
        results.sort(
            key=lambda t: (
                1 if (t[1] and t[1].status == ApprovalStatus.COMPLETED) else 0,
                _risk_order.get(str(t[0].risk_level), 5),
            )
        )

        if results:
            await self._record_recommendations(investigation_id, [a for a, _ in results])

        return results

    # -------------------------------------------------------------------------
    # Approval CRUD
    # -------------------------------------------------------------------------

    async def request_approval(
        self,
        investigation_id: str,
        action_id: str,
        finding_id: str | None = None,
    ) -> ActionApproval:
        existing = await self.get_approval(investigation_id, action_id)
        if existing and existing.status != ApprovalStatus.REJECTED:
            return existing

        action = self._registry.get(action_id)
        if not action:
            raise ValueError(f"Unknown action_id: {action_id!r}")

        approval = ActionApproval(
            investigation_id=investigation_id,
            action_id=action_id,
            finding_id=finding_id,
            status=ApprovalStatus.PENDING,
        )
        await self._insert_approval(approval)
        return approval

    async def approve(
        self,
        investigation_id: str,
        action_id: str,
        notes: str | None = None,
        actor: str = "user",
    ) -> ActionApproval:
        approval = await self.get_approval(investigation_id, action_id)
        if not approval:
            approval = await self.request_approval(investigation_id, action_id)

        now = datetime.utcnow()
        await self._db.execute(
            "UPDATE guided_action_approvals SET status=?, reviewed_at=?, notes=?"
            " WHERE approval_id=?",
            (str(ApprovalStatus.APPROVED), now.isoformat(), notes, approval.approval_id),
        )
        await self._db.commit()

        action = self._registry.get(action_id)
        await self._recorder.record(
            investigation_id,
            EventType.GUIDED_ACTION_APPROVED,
            f"Approved action: {action.title if action else action_id}",
            detail={"action_id": action_id, "notes": notes},
            actor=actor,
        )
        await self._recorder.record(
            investigation_id,
            EventType.ACTION_STARTED,
            f"Investigation step started: {action.title if action else action_id}",
            detail={"action_id": action_id, "finding_id": approval.finding_id},
            actor=actor,
        )
        Logger.info(
            "guided_action.approved",
            extra={"investigation_id": investigation_id, "action_id": action_id},
        )
        approval.status = ApprovalStatus.APPROVED
        approval.reviewed_at = now
        approval.notes = notes
        return approval

    async def reject(
        self,
        investigation_id: str,
        action_id: str,
        notes: str | None = None,
        actor: str = "user",
    ) -> ActionApproval:
        approval = await self.get_approval(investigation_id, action_id)
        if not approval:
            raise ValueError(f"No approval found for action {action_id!r}")
        now = datetime.utcnow()
        await self._db.execute(
            "UPDATE guided_action_approvals SET status=?, reviewed_at=?, notes=?"
            " WHERE approval_id=?",
            (str(ApprovalStatus.REJECTED), now.isoformat(), notes, approval.approval_id),
        )
        await self._db.commit()
        approval.status = ApprovalStatus.REJECTED
        approval.reviewed_at = now
        return approval

    async def complete(
        self,
        investigation_id: str,
        action_id: str,
        evidence_ids: list[str] | None = None,
        actor: str = "user",
    ) -> ActionApproval:
        approval = await self.get_approval(investigation_id, action_id)
        if not approval or approval.status != ApprovalStatus.APPROVED:
            raise ValueError(
                f"Action {action_id!r} must be approved before marking complete."
            )
        now = datetime.utcnow()
        refs = json.dumps(evidence_ids or [])
        await self._db.execute(
            "UPDATE guided_action_approvals SET status=?, completed_at=?, evidence_refs=?"
            " WHERE approval_id=?",
            (str(ApprovalStatus.COMPLETED), now.isoformat(), refs, approval.approval_id),
        )
        await self._db.commit()

        action = self._registry.get(action_id)
        await self._recorder.record(
            investigation_id,
            EventType.GUIDED_ACTION_COMPLETED,
            f"Completed action: {action.title if action else action_id}",
            detail={"action_id": action_id, "evidence_refs": evidence_ids or []},
            actor=actor,
        )
        Logger.info(
            "guided_action.completed",
            extra={"investigation_id": investigation_id, "action_id": action_id},
        )
        approval.status = ApprovalStatus.COMPLETED
        approval.completed_at = now
        approval.evidence_refs = evidence_ids or []

        # Progression resync — action completion is an explicit activity signal
        try:
            from apps.investigation_core.progression.triggers.progression_trigger import (
                ProgressionTrigger,
            )
            await ProgressionTrigger(self._db).resync(investigation_id)
        except Exception as exc:
            Logger.info(
                "guided_action.progression_resync_error",
                extra={"investigation_id": investigation_id, "error": str(exc)},
            )

        return approval

    async def get_approval(
        self, investigation_id: str, action_id: str
    ) -> ActionApproval | None:
        async with self._db.execute(
            "SELECT * FROM guided_action_approvals"
            " WHERE investigation_id=? AND action_id=? ORDER BY requested_at DESC LIMIT 1",
            (investigation_id, action_id),
        ) as cur:
            row = await cur.fetchone()
        return _row_to_approval(row) if row else None

    async def list_approvals(
        self, investigation_id: str
    ) -> list[ActionApproval]:
        return await self._list_approvals(investigation_id)

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    async def _list_approvals(self, investigation_id: str) -> list[ActionApproval]:
        async with self._db.execute(
            "SELECT * FROM guided_action_approvals"
            " WHERE investigation_id=? ORDER BY requested_at DESC",
            (investigation_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_approval(r) for r in rows]

    async def _insert_approval(self, approval: ActionApproval) -> None:
        await self._db.execute(
            """INSERT INTO guided_action_approvals
               (approval_id, investigation_id, action_id, finding_id, status,
                requested_at, reviewed_at, completed_at, notes, evidence_refs)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                approval.approval_id,
                approval.investigation_id,
                approval.action_id,
                approval.finding_id,
                str(approval.status),
                approval.requested_at.isoformat(),
                None,
                None,
                approval.notes,
                json.dumps(approval.evidence_refs),
            ),
        )
        await self._db.commit()

    async def _record_recommendations(
        self, investigation_id: str, actions: list[GuidedAction]
    ) -> None:
        """Record a timeline event for newly surfaced recommendations (idempotent)."""
        # Only record once per investigation (check if already recorded)
        async with self._db.execute(
            "SELECT 1 FROM timeline_events WHERE investigation_id=? AND event_type=? LIMIT 1",
            (investigation_id, str(EventType.GUIDED_ACTION_RECOMMENDED)),
        ) as cur:
            already = await cur.fetchone()
        if already:
            return
        await self._recorder.record(
            investigation_id,
            EventType.GUIDED_ACTION_RECOMMENDED,
            f"{len(actions)} guided action(s) recommended",
            detail={"action_ids": [a.action_id for a in actions]},
        )
