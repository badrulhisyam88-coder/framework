"""SQLite repository for ScanExecution records."""

from __future__ import annotations

import json
from datetime import datetime

import aiosqlite

from apps.scanner_orchestration.execution.models import ScanExecution, ScanStatus


def _row_to_scan(row: aiosqlite.Row) -> ScanExecution:
    return ScanExecution(
        scan_id=row["scan_id"],
        investigation_id=row["investigation_id"],
        scanner_type=row["scanner_type"],
        target=row["target"],
        profile=row["profile"],
        status=ScanStatus(row["status"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        started_at=(
            datetime.fromisoformat(row["started_at"]) if row["started_at"] else None
        ),
        completed_at=(
            datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None
        ),
        findings_count=row["findings_count"] or 0,
        evidence_refs=json.loads(row["evidence_refs"] or "[]"),
        raw_result_ref=row["raw_result_ref"],
        config=json.loads(row["config"] or "{}"),
        error_message=row["error_message"],
        group_id=row["group_id"] if "group_id" in row.keys() else None,
    )


class ScanRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def get_by_id(self, scan_id: str) -> ScanExecution | None:
        async with self._db.execute(
            "SELECT * FROM scan_executions WHERE scan_id=?", (scan_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row_to_scan(row) if row else None

    async def list_for_investigation(
        self, investigation_id: str, limit: int = 50
    ) -> list[ScanExecution]:
        async with self._db.execute(
            "SELECT * FROM scan_executions"
            " WHERE investigation_id=? ORDER BY created_at DESC LIMIT ?",
            (investigation_id, limit),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_scan(r) for r in rows]

    async def insert(self, scan: ScanExecution) -> None:
        await self._db.execute(
            """INSERT INTO scan_executions
               (scan_id, investigation_id, scanner_type, target, profile, status,
                created_at, started_at, completed_at, findings_count, evidence_refs,
                raw_result_ref, config, error_message, group_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan.scan_id,
                scan.investigation_id,
                scan.scanner_type,
                scan.target,
                scan.profile,
                str(scan.status),
                scan.created_at.isoformat(),
                scan.started_at.isoformat() if scan.started_at else None,
                scan.completed_at.isoformat() if scan.completed_at else None,
                scan.findings_count,
                json.dumps(scan.evidence_refs),
                scan.raw_result_ref,
                json.dumps(scan.config),
                scan.error_message,
                scan.group_id,
            ),
        )
        await self._db.commit()

    async def list_by_group(self, group_id: str) -> list[ScanExecution]:
        async with self._db.execute(
            "SELECT * FROM scan_executions WHERE group_id=? ORDER BY created_at ASC",
            (group_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_scan(r) for r in rows]

    async def update_status(
        self,
        scan_id: str,
        status: ScanStatus,
        *,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        findings_count: int | None = None,
        error_message: str | None = None,
    ) -> None:
        fields = ["status=?"]
        values: list = [str(status)]
        if started_at is not None:
            fields.append("started_at=?")
            values.append(started_at.isoformat())
        if completed_at is not None:
            fields.append("completed_at=?")
            values.append(completed_at.isoformat())
        if findings_count is not None:
            fields.append("findings_count=?")
            values.append(findings_count)
        if error_message is not None:
            fields.append("error_message=?")
            values.append(error_message)
        values.append(scan_id)
        await self._db.execute(
            f"UPDATE scan_executions SET {', '.join(fields)} WHERE scan_id=?",
            tuple(values),
        )
        await self._db.commit()
