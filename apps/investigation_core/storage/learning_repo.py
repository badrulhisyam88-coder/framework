"""SQLite repository for LearningPathProgress records."""

from __future__ import annotations

import json
from datetime import datetime

import aiosqlite

from apps.investigation_core.models.learning import LearningPathProgress, LearningPathStatus


def _row_to_progress(row: aiosqlite.Row) -> LearningPathProgress:
    return LearningPathProgress(
        id=row["id"],
        investigation_id=row["investigation_id"],
        path_id=row["path_id"],
        status=LearningPathStatus(row["status"]),
        started_at=datetime.fromisoformat(row["started_at"]),
        completed_at=(
            datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None
        ),
        current_step_index=row["current_step_index"],
        completed_steps=json.loads(row["completed_steps"] or "[]"),
    )


class LearningProgressRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def get(self, investigation_id: str, path_id: str) -> LearningPathProgress | None:
        async with self._db.execute(
            "SELECT * FROM learning_path_progress WHERE investigation_id = ? AND path_id = ?",
            (investigation_id, path_id),
        ) as cur:
            row = await cur.fetchone()
        return _row_to_progress(row) if row else None

    async def list_for_investigation(self, investigation_id: str) -> list[LearningPathProgress]:
        async with self._db.execute(
            "SELECT * FROM learning_path_progress"
            " WHERE investigation_id = ? ORDER BY started_at ASC",
            (investigation_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_progress(r) for r in rows]

    async def insert(self, progress: LearningPathProgress) -> None:
        await self._db.execute(
            """INSERT INTO learning_path_progress
               (id, investigation_id, path_id, status, started_at, completed_at,
                current_step_index, completed_steps)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                progress.id,
                progress.investigation_id,
                progress.path_id,
                str(progress.status),
                progress.started_at.isoformat(),
                progress.completed_at.isoformat() if progress.completed_at else None,
                progress.current_step_index,
                json.dumps(progress.completed_steps),
            ),
        )
        await self._db.commit()

    async def update(self, progress: LearningPathProgress) -> None:
        await self._db.execute(
            """UPDATE learning_path_progress SET
               status = ?, completed_at = ?, current_step_index = ?, completed_steps = ?
               WHERE investigation_id = ? AND path_id = ?""",
            (
                str(progress.status),
                progress.completed_at.isoformat() if progress.completed_at else None,
                progress.current_step_index,
                json.dumps(progress.completed_steps),
                progress.investigation_id,
                progress.path_id,
            ),
        )
        await self._db.commit()

    async def advance_step(
        self,
        investigation_id: str,
        path_id: str,
        step_id: str,
        next_index: int,
    ) -> None:
        progress = await self.get(investigation_id, path_id)
        if not progress:
            return
        if step_id not in progress.completed_steps:
            progress.completed_steps.append(step_id)
        progress.current_step_index = next_index
        await self.update(progress)

    async def mark_completed(self, investigation_id: str, path_id: str) -> None:
        now = datetime.utcnow().isoformat()
        await self._db.execute(
            """UPDATE learning_path_progress SET status = 'completed', completed_at = ?
               WHERE investigation_id = ? AND path_id = ?""",
            (now, investigation_id, path_id),
        )
        await self._db.commit()
