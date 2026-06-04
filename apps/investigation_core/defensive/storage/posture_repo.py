"""SQLite repository for PostureSnapshot records."""

from __future__ import annotations

import json
from datetime import datetime
from uuid import uuid4

import aiosqlite

from apps.investigation_core.defensive.models.posture import (
    PostureSnapshot,
    PostureSnapshotKind,
)


def _row_to_snapshot(row: aiosqlite.Row) -> PostureSnapshot:
    return PostureSnapshot(
        snapshot_id=row["snapshot_id"],
        investigation_id=row["investigation_id"],
        campaign_id=row["campaign_id"],
        label=row["label"],
        snapshot_kind=PostureSnapshotKind(row["snapshot_kind"]),
        captured_at=datetime.fromisoformat(row["captured_at"]),
        findings_count=int(row["findings_count"]),
        findings_by_severity=json.loads(row["findings_by_severity"] or "{}"),
        findings_by_type=json.loads(row["findings_by_type"] or "{}"),
        active_themes=json.loads(row["active_themes"] or "[]"),
        evidence_quality_score=int(row["evidence_quality_score"]),
        remediation_documented_themes=json.loads(row["remediation_documented"] or "[]"),
        captured_by=row["captured_by"],
        notes=row["notes"],
    )


class PostureRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def insert(self, snapshot: PostureSnapshot) -> None:
        await self._db.execute(
            """INSERT INTO posture_snapshots
               (snapshot_id, investigation_id, campaign_id, label, snapshot_kind,
                captured_at, findings_count, findings_by_severity, findings_by_type,
                active_themes, evidence_quality_score, remediation_documented,
                captured_by, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                snapshot.snapshot_id,
                snapshot.investigation_id,
                snapshot.campaign_id,
                snapshot.label,
                str(snapshot.snapshot_kind),
                snapshot.captured_at.isoformat(),
                snapshot.findings_count,
                json.dumps(snapshot.findings_by_severity),
                json.dumps(snapshot.findings_by_type),
                json.dumps(snapshot.active_themes),
                snapshot.evidence_quality_score,
                json.dumps(snapshot.remediation_documented_themes),
                snapshot.captured_by,
                snapshot.notes,
            ),
        )
        await self._db.commit()

    async def get_by_id(self, snapshot_id: str) -> PostureSnapshot | None:
        async with self._db.execute(
            "SELECT * FROM posture_snapshots WHERE snapshot_id=?",
            (snapshot_id,),
        ) as cur:
            row = await cur.fetchone()
        return _row_to_snapshot(row) if row else None

    async def list_for_investigation(
        self, investigation_id: str, limit: int = 50
    ) -> list[PostureSnapshot]:
        async with self._db.execute(
            "SELECT * FROM posture_snapshots"
            " WHERE investigation_id=? ORDER BY captured_at DESC LIMIT ?",
            (investigation_id, limit),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_snapshot(r) for r in rows]

    async def list_for_campaign(
        self, campaign_id: str, limit: int = 50
    ) -> list[PostureSnapshot]:
        async with self._db.execute(
            "SELECT * FROM posture_snapshots"
            " WHERE campaign_id=? ORDER BY captured_at DESC LIMIT ?",
            (campaign_id, limit),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_snapshot(r) for r in rows]

    async def delete(self, snapshot_id: str) -> None:
        await self._db.execute(
            "DELETE FROM posture_snapshots WHERE snapshot_id=?",
            (snapshot_id,),
        )
        await self._db.commit()


def new_snapshot_id() -> str:
    return str(uuid4())
