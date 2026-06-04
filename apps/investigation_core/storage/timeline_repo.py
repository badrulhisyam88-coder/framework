"""SQLite repository for TimelineEvent records."""

from __future__ import annotations

import json
from datetime import datetime

import aiosqlite

from apps.investigation_core.models.timeline import TimelineEvent
from apps.investigation_core.taxonomy.stages import EventType


def _row_to_event(row: aiosqlite.Row) -> TimelineEvent:
    return TimelineEvent(
        event_id=row["event_id"],
        investigation_id=row["investigation_id"],
        event_type=EventType(row["event_type"]),
        timestamp=datetime.fromisoformat(row["timestamp"]),
        actor=row["actor"],
        summary=row["summary"],
        detail=json.loads(row["detail"] or "{}"),
    )


class TimelineRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def insert(self, event: TimelineEvent) -> None:
        await self._db.execute(
            """INSERT INTO timeline_events
               (event_id, investigation_id, event_type, timestamp, actor, summary, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                event.event_id,
                event.investigation_id,
                str(event.event_type),
                event.timestamp.isoformat(),
                event.actor,
                event.summary,
                json.dumps(event.detail),
            ),
        )
        await self._db.commit()

    async def list_for_investigation(
        self,
        investigation_id: str,
        limit: int = 200,
    ) -> list[TimelineEvent]:
        async with self._db.execute(
            """SELECT * FROM timeline_events
               WHERE investigation_id = ?
               ORDER BY timestamp ASC
               LIMIT ?""",
            (investigation_id, limit),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_event(r) for r in rows]

    async def has_event_type(self, investigation_id: str, event_type: EventType) -> bool:
        async with self._db.execute(
            "SELECT 1 FROM timeline_events WHERE investigation_id = ? AND event_type = ? LIMIT 1",
            (investigation_id, str(event_type)),
        ) as cur:
            return await cur.fetchone() is not None

    async def list_for_scan(
        self,
        investigation_id: str,
        scan_id: str,
        limit: int = 50,
    ) -> list[TimelineEvent]:
        """Return only events whose detail.scan_id matches — filters at the DB level.

        Uses SQLite's json_extract so we don't have to fetch all investigation events
        and filter in Python (which fails when total events > limit).
        """
        async with self._db.execute(
            """SELECT * FROM timeline_events
               WHERE investigation_id = ?
                 AND json_extract(detail, '$.scan_id') = ?
               ORDER BY timestamp ASC
               LIMIT ?""",
            (investigation_id, scan_id, limit),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_event(r) for r in rows]
