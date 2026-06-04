"""SQLite repository for EvidenceArtifact records."""

from __future__ import annotations

import json
from datetime import datetime

import aiosqlite

from apps.investigation_core.evidence.models.artifact import ArtifactType, EvidenceArtifact


def _row_to_artifact(row: aiosqlite.Row) -> EvidenceArtifact:
    return EvidenceArtifact(
        evidence_id=row["evidence_id"],
        investigation_id=row["investigation_id"],
        finding_id=row["finding_id"],
        learning_path_id=row["learning_path_id"],
        guided_action_id=row["guided_action_id"],
        artifact_type=ArtifactType(row["artifact_type"]),
        title=row["title"],
        description=row["description"] or "",
        content=row["content"] or "",
        created_at=datetime.fromisoformat(row["created_at"]),
        created_by=row["created_by"],
        metadata=json.loads(row["metadata"] or "{}"),
        tags=json.loads(row["tags"] or "[]"),
    )


class ArtifactRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def get_by_id(self, evidence_id: str) -> EvidenceArtifact | None:
        async with self._db.execute(
            "SELECT * FROM evidence_artifacts WHERE evidence_id = ?",
            (evidence_id,),
        ) as cur:
            row = await cur.fetchone()
        return _row_to_artifact(row) if row else None

    async def list_for_investigation(
        self,
        investigation_id: str,
        limit: int = 200,
    ) -> list[EvidenceArtifact]:
        async with self._db.execute(
            "SELECT * FROM evidence_artifacts"
            " WHERE investigation_id = ? ORDER BY created_at DESC LIMIT ?",
            (investigation_id, limit),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_artifact(r) for r in rows]

    async def list_for_finding(self, finding_id: str) -> list[EvidenceArtifact]:
        async with self._db.execute(
            "SELECT * FROM evidence_artifacts"
            " WHERE finding_id = ? ORDER BY created_at ASC",
            (finding_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_artifact(r) for r in rows]

    async def list_for_guided_action(
        self, investigation_id: str, guided_action_id: str
    ) -> list[EvidenceArtifact]:
        async with self._db.execute(
            "SELECT * FROM evidence_artifacts"
            " WHERE investigation_id = ? AND guided_action_id = ? ORDER BY created_at ASC",
            (investigation_id, guided_action_id),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_artifact(r) for r in rows]

    async def insert(self, artifact: EvidenceArtifact) -> None:
        await self._db.execute(
            """INSERT INTO evidence_artifacts
               (evidence_id, investigation_id, finding_id, learning_path_id,
                guided_action_id, artifact_type, title, description, content,
                created_at, created_by, metadata, tags)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                artifact.evidence_id,
                artifact.investigation_id,
                artifact.finding_id,
                artifact.learning_path_id,
                artifact.guided_action_id,
                str(artifact.artifact_type),
                artifact.title,
                artifact.description,
                artifact.content,
                artifact.created_at.isoformat(),
                artifact.created_by,
                json.dumps(artifact.metadata),
                json.dumps(artifact.tags),
            ),
        )
        await self._db.commit()

    async def delete(self, evidence_id: str) -> None:
        await self._db.execute(
            "DELETE FROM evidence_artifacts WHERE evidence_id = ?",
            (evidence_id,),
        )
        await self._db.commit()

    async def count_for_investigation(self, investigation_id: str) -> int:
        async with self._db.execute(
            "SELECT COUNT(*) FROM evidence_artifacts WHERE investigation_id = ?",
            (investigation_id,),
        ) as cur:
            row = await cur.fetchone()
        return row[0] if row else 0
