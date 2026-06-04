"""SQLite repository for SkillMastery records."""

from __future__ import annotations

import json
from datetime import datetime

import aiosqlite

from apps.investigation_core.progression.models.mastery import MasteryStatus, SkillMastery


def _row_to_mastery(row: aiosqlite.Row) -> SkillMastery:
    return SkillMastery(
        mastery_id=row["mastery_id"],
        skill_id=row["skill_id"],
        investigation_id=row["investigation_id"],
        status=MasteryStatus(row["status"]),
        evidence_refs=json.loads(row["evidence_refs"] or "[]"),
        completed_learning_paths=json.loads(row["completed_learning_paths"] or "[]"),
        completed_actions=json.loads(row["completed_actions"] or "[]"),
        confidence_score=float(row["confidence_score"] or 0.0),
        created_at=datetime.fromisoformat(row["created_at"]),
        started_at=(
            datetime.fromisoformat(row["started_at"]) if row["started_at"] else None
        ),
        validated_at=(
            datetime.fromisoformat(row["validated_at"]) if row["validated_at"] else None
        ),
    )


class MasteryRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def get(self, investigation_id: str, skill_id: str) -> SkillMastery | None:
        async with self._db.execute(
            "SELECT * FROM skill_mastery WHERE investigation_id=? AND skill_id=?",
            (investigation_id, skill_id),
        ) as cur:
            row = await cur.fetchone()
        return _row_to_mastery(row) if row else None

    async def list_for_investigation(
        self, investigation_id: str
    ) -> list[SkillMastery]:
        async with self._db.execute(
            "SELECT * FROM skill_mastery WHERE investigation_id=? ORDER BY created_at ASC",
            (investigation_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_mastery(r) for r in rows]

    async def upsert(self, mastery: SkillMastery) -> None:
        await self._db.execute(
            """INSERT INTO skill_mastery
               (mastery_id, skill_id, investigation_id, status, evidence_refs,
                completed_learning_paths, completed_actions, confidence_score,
                created_at, started_at, validated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(skill_id, investigation_id) DO UPDATE SET
               status=excluded.status,
               evidence_refs=excluded.evidence_refs,
               completed_learning_paths=excluded.completed_learning_paths,
               completed_actions=excluded.completed_actions,
               confidence_score=excluded.confidence_score,
               started_at=excluded.started_at,
               validated_at=excluded.validated_at""",
            (
                mastery.mastery_id,
                mastery.skill_id,
                mastery.investigation_id,
                str(mastery.status),
                json.dumps(mastery.evidence_refs),
                json.dumps(mastery.completed_learning_paths),
                json.dumps(mastery.completed_actions),
                mastery.confidence_score,
                mastery.created_at.isoformat(),
                mastery.started_at.isoformat() if mastery.started_at else None,
                mastery.validated_at.isoformat() if mastery.validated_at else None,
            ),
        )
        await self._db.commit()

    async def set_status(
        self,
        investigation_id: str,
        skill_id: str,
        status: MasteryStatus,
        validated_at: datetime | None = None,
    ) -> None:
        await self._db.execute(
            "UPDATE skill_mastery SET status=?, validated_at=?"
            " WHERE investigation_id=? AND skill_id=?",
            (
                str(status),
                validated_at.isoformat() if validated_at else None,
                investigation_id,
                skill_id,
            ),
        )
        await self._db.commit()
