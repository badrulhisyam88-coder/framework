"""SQLite repository for Investigation records."""

from __future__ import annotations

import json
from datetime import datetime

import aiosqlite

from apps.investigation_core.models.investigation import Investigation, InvestigationStatus
from apps.investigation_core.taxonomy.stages import WorkflowStage


def _row_to_investigation(row: aiosqlite.Row) -> Investigation:
    return Investigation(
        investigation_id=row["investigation_id"],
        title=row["title"],
        status=InvestigationStatus(row["status"]),
        workflow_stage=WorkflowStage(row["workflow_stage"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        targets=json.loads(row["targets"] or "[]"),
        findings=json.loads(row["findings"] or "[]"),
        evidence_refs=json.loads(row["evidence_refs"] or "[]"),
        active_learning_paths=json.loads(row["active_learning_paths"] or "[]"),
        completed_learning_paths=json.loads(row["completed_learning_paths"] or "[]"),
        notes=row["notes"],
    )


class InvestigationRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def get_by_id(self, investigation_id: str) -> Investigation | None:
        async with self._db.execute(
            "SELECT * FROM investigations WHERE investigation_id = ?",
            (investigation_id,),
        ) as cur:
            row = await cur.fetchone()
        return _row_to_investigation(row) if row else None

    async def get_by_target(self, target: str) -> Investigation | None:
        """Return the most recently updated investigation that includes this target."""
        async with self._db.execute(
            "SELECT * FROM investigations WHERE targets LIKE ? ORDER BY updated_at DESC LIMIT 1",
            (f"%{target}%",),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        inv = _row_to_investigation(row)
        # Exact-match guard: the LIKE query is a coarse filter.
        return inv if target in inv.targets else None

    async def list_all(self, limit: int = 500) -> list[Investigation]:
        async with self._db.execute(
            "SELECT * FROM investigations ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_investigation(r) for r in rows]

    async def insert(self, inv: Investigation) -> None:
        now = datetime.utcnow().isoformat()
        await self._db.execute(
            """INSERT INTO investigations
               (investigation_id, title, status, workflow_stage, created_at, updated_at,
                targets, findings, evidence_refs, active_learning_paths,
                completed_learning_paths, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                inv.investigation_id,
                inv.title,
                str(inv.status),
                str(inv.workflow_stage),
                inv.created_at.isoformat(),
                now,
                json.dumps(inv.targets),
                json.dumps(inv.findings),
                json.dumps(inv.evidence_refs),
                json.dumps(inv.active_learning_paths),
                json.dumps(inv.completed_learning_paths),
                inv.notes,
            ),
        )
        await self._db.commit()

    async def update(self, inv: Investigation) -> None:
        now = datetime.utcnow().isoformat()
        await self._db.execute(
            """UPDATE investigations SET
               title = ?, status = ?, workflow_stage = ?, updated_at = ?,
               targets = ?, findings = ?, evidence_refs = ?,
               active_learning_paths = ?, completed_learning_paths = ?, notes = ?
               WHERE investigation_id = ?""",
            (
                inv.title,
                str(inv.status),
                str(inv.workflow_stage),
                now,
                json.dumps(inv.targets),
                json.dumps(inv.findings),
                json.dumps(inv.evidence_refs),
                json.dumps(inv.active_learning_paths),
                json.dumps(inv.completed_learning_paths),
                inv.notes,
                inv.investigation_id,
            ),
        )
        await self._db.commit()

    async def delete(self, investigation_id: str) -> bool:
        """Hard-delete an investigation and all its dependent rows.

        Cascades through every table that carries an investigation_id FK
        (or a soft reference) so the row removals don't violate foreign
        keys. Returns True if the investigation existed, False otherwise.

        This is destructive and irreversible. Caller is responsible for
        confirming with the operator.
        """
        existing = await self.get_by_id(investigation_id)
        if not existing:
            return False

        # Order matters — children first, parent last. Tables with no
        # explicit FK to investigations (campaign_memberships, learning
        # progress) are included for completeness.
        # Phase 59a — "investigation_milestones" removed from cascade
        # list. The table itself was dropped; including it here would
        # raise on SQLite.
        # Phase 60 — "skill_mastery" added. Phase 59a investigation
        # surfaced the gap when a manual investigation delete returned
        # 500 on the FOREIGN KEY constraint from skill_mastery; this
        # close-out fixes it.
        cascade_tables = (
            "timeline_events",
            "evidence_artifacts",
            "guided_action_approvals",
            "posture_snapshots",
            "learning_path_progress",
            "export_records",
            "normalized_findings",
            "scan_executions",
            "campaign_memberships",
            "skill_mastery",
        )
        for table in cascade_tables:
            try:
                await self._db.execute(
                    f"DELETE FROM {table} WHERE investigation_id = ?",
                    (investigation_id,),
                )
            except aiosqlite.Error:
                # Table may not exist in older deployments — skip silently.
                # Other delete tables still run.
                continue

        await self._db.execute(
            "DELETE FROM investigations WHERE investigation_id = ?",
            (investigation_id,),
        )
        await self._db.commit()
        return True

    async def add_finding(self, investigation_id: str, finding_id: str) -> None:
        inv = await self.get_by_id(investigation_id)
        if inv and finding_id not in inv.findings:
            inv.findings.append(finding_id)
            await self.update(inv)

    async def set_stage(self, investigation_id: str, stage: WorkflowStage) -> None:
        now = datetime.utcnow().isoformat()
        await self._db.execute(
            "UPDATE investigations SET workflow_stage = ?, updated_at = ?"
            " WHERE investigation_id = ?",
            (str(stage), now, investigation_id),
        )
        await self._db.commit()

    async def set_active_learning_path(self, investigation_id: str, path_id: str) -> None:
        inv = await self.get_by_id(investigation_id)
        if inv and path_id not in inv.active_learning_paths:
            inv.active_learning_paths.append(path_id)
            await self.update(inv)

    async def mark_learning_path_completed(self, investigation_id: str, path_id: str) -> None:
        inv = await self.get_by_id(investigation_id)
        if inv:
            if path_id in inv.active_learning_paths:
                inv.active_learning_paths.remove(path_id)
            if path_id not in inv.completed_learning_paths:
                inv.completed_learning_paths.append(path_id)
            await self.update(inv)
