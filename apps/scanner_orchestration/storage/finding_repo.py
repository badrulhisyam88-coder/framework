"""SQLite repository for NormalizedFinding records."""

from __future__ import annotations

import json
from datetime import datetime

import aiosqlite

from apps.scanner_orchestration.normalization.models import NormalizedFinding


def _row_to_finding(row: aiosqlite.Row) -> NormalizedFinding:
    return NormalizedFinding(
        finding_id=row["finding_id"],
        scan_id=row["scan_id"],
        investigation_id=row["investigation_id"],
        source_scanner=row["source_scanner"],
        finding_type=row["finding_type"],
        severity=row["severity"],
        title=row["title"],
        description=row["description"] or "",
        target=row["target"],
        port=row["port"],
        endpoint=row["endpoint"],
        evidence_refs=json.loads(row["evidence_refs"] or "[]"),
        related_cves=json.loads(row["related_cves"] or "[]"),
        related_cwes=json.loads(row["related_cwes"] or "[]"),
        tags=json.loads(row["tags"] or "[]"),
        raw_data=json.loads(row["raw_data"] or "{}"),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


class NormalizedFindingRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def insert(self, finding: NormalizedFinding) -> None:
        await self._db.execute(
            """INSERT INTO normalized_findings
               (finding_id, scan_id, investigation_id, source_scanner,
                finding_type, severity, title, description, target, port, endpoint,
                evidence_refs, related_cves, related_cwes, tags, raw_data, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.finding_id,
                finding.scan_id,
                finding.investigation_id,
                finding.source_scanner,
                finding.finding_type,
                finding.severity,
                finding.title,
                finding.description,
                finding.target,
                finding.port,
                finding.endpoint,
                json.dumps(finding.evidence_refs),
                json.dumps(finding.related_cves),
                json.dumps(finding.related_cwes),
                json.dumps(finding.tags),
                json.dumps(finding.raw_data),
                finding.created_at.isoformat(),
            ),
        )
        await self._db.commit()

    async def get_by_id(self, finding_id: str) -> NormalizedFinding | None:
        async with self._db.execute(
            "SELECT * FROM normalized_findings WHERE finding_id=?",
            (finding_id,),
        ) as cur:
            row = await cur.fetchone()
        return _row_to_finding(row) if row else None

    async def list_for_scan(self, scan_id: str) -> list[NormalizedFinding]:
        async with self._db.execute(
            "SELECT * FROM normalized_findings WHERE scan_id=? ORDER BY severity DESC",
            (scan_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_finding(r) for r in rows]

    async def list_for_investigation(
        self, investigation_id: str, limit: int = 500
    ) -> list[NormalizedFinding]:
        async with self._db.execute(
            "SELECT * FROM normalized_findings"
            " WHERE investigation_id=? ORDER BY created_at DESC LIMIT ?",
            (investigation_id, limit),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_finding(r) for r in rows]

    async def distinct_finding_types(self, investigation_id: str) -> list[str]:
        async with self._db.execute(
            "SELECT DISTINCT finding_type FROM normalized_findings"
            " WHERE investigation_id=?",
            (investigation_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [r[0] for r in rows]

    async def list_with_empty_evidence_refs(
        self, investigation_id: str
    ) -> list[NormalizedFinding]:
        """Return findings whose evidence_refs are empty — candidates for backfill."""
        async with self._db.execute(
            "SELECT * FROM normalized_findings"
            " WHERE investigation_id=?"
            "   AND (evidence_refs IS NULL OR evidence_refs = '[]')"
            " ORDER BY created_at ASC",
            (investigation_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_finding(r) for r in rows]

    async def update_evidence_refs(
        self, finding_id: str, evidence_refs: list[str]
    ) -> None:
        """Overwrite evidence_refs for a single finding."""
        await self._db.execute(
            "UPDATE normalized_findings SET evidence_refs=? WHERE finding_id=?",
            (json.dumps(evidence_refs), finding_id),
        )
        await self._db.commit()

    async def update_validation_status(
        self,
        finding_id: str,
        status: str,
        reason: str | None,
        gaps_json: str | None,
        validated_at: str | None,
    ) -> None:
        """Set V1.7 validation fields for a finding. Idempotent — safe to call repeatedly."""
        await self._db.execute(
            "UPDATE normalized_findings"
            " SET validation_status=?, validation_reason=?,"
            "     enumeration_gaps=?, validated_at=?"
            " WHERE finding_id=?",
            (status, reason, gaps_json, validated_at, finding_id),
        )
        await self._db.commit()

    async def update_block_reason(self, finding_id: str, reason: str) -> None:
        """Set enumeration_block_reason on a finding."""
        try:
            await self._db.execute(
                "UPDATE normalized_findings SET enumeration_block_reason=?"
                " WHERE finding_id=?",
                (reason, finding_id),
            )
            await self._db.commit()
        except Exception:
            pass  # Column may not exist on pre-PR-J schema

    async def map_validation_status(self, investigation_id: str) -> dict[str, dict]:
        """Return {finding_id: {validation_status, validation_reason, enumeration_gaps}} for an investigation."""
        result: dict[str, dict] = {}
        try:
            async with self._db.execute(
                "SELECT finding_id, validation_status, validation_reason, enumeration_gaps"
                " FROM normalized_findings WHERE investigation_id=?",
                (investigation_id,),
            ) as cur:
                for row in await cur.fetchall():
                    result[row[0]] = {
                        "validation_status": row[1] or "pending",
                        "validation_reason": row[2],
                        "enumeration_gaps": json.loads(row[3]) if row[3] else [],
                    }
        except Exception:
            pass
        return result

    async def list_enumeration_gaps(self) -> list[dict]:
        """Aggregate enumeration_block_reason counts across all findings."""
        try:
            async with self._db.execute(
                "SELECT enumeration_block_reason, COUNT(*) as cnt,"
                " MIN(created_at) as first_seen, MAX(created_at) as last_seen"
                " FROM normalized_findings"
                " WHERE enumeration_block_reason IS NOT NULL"
                " GROUP BY enumeration_block_reason"
                " ORDER BY cnt DESC",
            ) as cur:
                rows = await cur.fetchall()
            return [
                {
                    "reason": r[0],
                    "count": r[1],
                    "first_seen": (r[2] or "")[:10],
                    "last_seen": (r[3] or "")[:10],
                }
                for r in rows
            ]
        except Exception:
            return []

    async def merge_raw_data(self, finding_id: str, updates: dict) -> None:
        """Merge updates into the finding's raw_data; existing keys are preserved."""
        async with self._db.execute(
            "SELECT raw_data FROM normalized_findings WHERE finding_id=?",
            (finding_id,),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return
        current = json.loads(row[0] or "{}")
        current.update(updates)
        await self._db.execute(
            "UPDATE normalized_findings SET raw_data=? WHERE finding_id=?",
            (json.dumps(current), finding_id),
        )
        await self._db.commit()
