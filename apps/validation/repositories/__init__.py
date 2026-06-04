"""
Repositories — all SQLite access for the validation module.

One class per table. No business logic here.
Only CRUD and queries. Models in, models out.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

import aiosqlite

from apps.validation.models import (
    CVE,
    Asset,
    Change,
    ChangeType,
    DCGroup,
    Evidence,
    Finding,
    FindingSeverity,
    FindingStatus,
    HistoryAction,
    HistoryEntry,
    Host,
    HostStatus,
    KnownIssue,
    KnownIssueMatchField,
    MsfRun,
    MsfRunMode,
    MsfRunStatus,
    QueueItem,
    QueueStatus,
    ReconResult,
    Service,
    ServiceProtocol,
    ValidationStatus,
    ValidationType,
    WatchlistEntry,
)


def _now() -> str:
    return datetime.utcnow().isoformat()


def _uuid() -> str:
    return str(uuid4())


class HostRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    async def upsert(self, host: Host) -> Host:
        existing = await self.get_by_ip(host.ip)
        if existing:
            await self.db.execute(
                "UPDATE hosts SET hostname=?, os_guess=?, last_seen=?, status=? WHERE ip=?",
                (host.hostname, host.os_guess, _now(), HostStatus.ACTIVE, host.ip),
            )
            await self.db.commit()
            return existing
        await self.db.execute(
            "INSERT INTO hosts (id, ip, hostname, os_guess, first_seen, last_seen, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (host.id, host.ip, host.hostname, host.os_guess, _now(), _now(), host.status),
        )
        await self.db.commit()
        return host

    async def get_by_ip(self, ip: str) -> Host | None:
        async with self.db.execute("SELECT * FROM hosts WHERE ip=?", (ip,)) as cur:
            row = await cur.fetchone()
        return _row_to_host(row) if row else None

    async def get_by_id(self, host_id: str) -> Host | None:
        async with self.db.execute("SELECT * FROM hosts WHERE id=?", (host_id,)) as cur:
            row = await cur.fetchone()
        return _row_to_host(row) if row else None

    async def list_all(self) -> list[Host]:
        async with self.db.execute("SELECT * FROM hosts ORDER BY last_seen DESC") as cur:
            rows = await cur.fetchall()
        return [_row_to_host(r) for r in rows]

    async def count(self) -> int:
        async with self.db.execute("SELECT COUNT(*) FROM hosts") as cur:
            row = await cur.fetchone()
        return row[0] if row else 0


def _row_to_host(row: Any) -> Host:
    return Host(
        id=row["id"], ip=row["ip"], hostname=row["hostname"],
        os_guess=row["os_guess"],
        first_seen=datetime.fromisoformat(row["first_seen"]),
        last_seen=datetime.fromisoformat(row["last_seen"]),
        status=HostStatus(row["status"]),
    )


class ServiceRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    async def upsert(self, service: Service) -> tuple[Service, bool]:
        existing = await self.get_by_host_port(service.host_id, service.port, service.protocol)
        if existing:
            await self.db.execute(
                "UPDATE services SET service_name=?, product=?, version=?, banner=?, last_seen=? "
                "WHERE host_id=? AND port=? AND protocol=?",
                (service.service_name, service.product, service.version,
                 service.banner, _now(),
                 service.host_id, service.port, service.protocol),
            )
            await self.db.commit()
            return existing, False
        await self.db.execute(
            "INSERT INTO services "
            "(id, host_id, port, protocol, service_name, product, version, banner, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (service.id, service.host_id, service.port, service.protocol,
             service.service_name, service.product, service.version,
             service.banner, _now(), _now()),
        )
        await self.db.commit()
        return service, True

    async def get_by_host_port(self, host_id: str, port: int, protocol: str = "tcp") -> Service | None:
        async with self.db.execute(
            "SELECT * FROM services WHERE host_id=? AND port=? AND protocol=?",
            (host_id, port, protocol),
        ) as cur:
            row = await cur.fetchone()
        return _row_to_service(row) if row else None

    async def get_by_id(self, service_id: str) -> Service | None:
        async with self.db.execute("SELECT * FROM services WHERE id=?", (service_id,)) as cur:
            row = await cur.fetchone()
        return _row_to_service(row) if row else None

    async def list_by_host(self, host_id: str) -> list[Service]:
        async with self.db.execute(
            "SELECT * FROM services WHERE host_id=? ORDER BY port", (host_id,)
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_service(r) for r in rows]

    async def count(self) -> int:
        async with self.db.execute("SELECT COUNT(*) FROM services") as cur:
            row = await cur.fetchone()
        return row[0] if row else 0

    async def count_by_host_all(self) -> dict[str, int]:
        """Return {host_id: open_service_count} for every host that has services."""
        async with self.db.execute(
            "SELECT host_id, COUNT(*) as cnt FROM services GROUP BY host_id"
        ) as cur:
            rows = await cur.fetchall()
        return {r["host_id"]: r["cnt"] for r in rows}


def _row_to_service(row: Any) -> Service:
    return Service(
        id=row["id"], host_id=row["host_id"], port=row["port"],
        protocol=ServiceProtocol(row["protocol"]),
        service_name=row["service_name"], product=row["product"],
        version=row["version"], banner=row["banner"],
        first_seen=datetime.fromisoformat(row["first_seen"]),
        last_seen=datetime.fromisoformat(row["last_seen"]),
    )


class CVERepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    async def upsert(self, cve: CVE) -> None:
        await self.db.execute(
            "INSERT OR REPLACE INTO cves "
            "(cve_id, description, cvss_score, cvss_vector, cvss_version, "
            "affected_products, published_date, last_modified, source_url) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (cve.cve_id, cve.description, cve.cvss_score, cve.cvss_vector,
             cve.cvss_version, json.dumps(cve.affected_products),
             cve.published_date.isoformat(), cve.last_modified.isoformat(),
             cve.source_url),
        )

    async def get_by_id(self, cve_id: str) -> CVE | None:
        async with self.db.execute("SELECT * FROM cves WHERE cve_id=?", (cve_id,)) as cur:
            row = await cur.fetchone()
        return _row_to_cve(row) if row else None

    async def search_by_product(self, product: str, version: str | None = None) -> list[CVE]:
        async with self.db.execute(
            "SELECT * FROM cves WHERE affected_products LIKE ? ORDER BY cvss_score DESC LIMIT 50",
            (f"%{product.lower()}%",),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_cve(r) for r in rows]

    async def count(self) -> int:
        async with self.db.execute("SELECT COUNT(*) FROM cves") as cur:
            row = await cur.fetchone()
        return row[0] if row else 0

    async def get_sync_meta(self, key: str) -> str | None:
        async with self.db.execute(
            "SELECT value FROM sync_meta WHERE key=?", (key,)
        ) as cur:
            row = await cur.fetchone()
        return row[0] if row else None

    async def set_sync_meta(self, key: str, value: str) -> None:
        await self.db.execute(
            "INSERT OR REPLACE INTO sync_meta (key, value, updated_at) VALUES (?, ?, ?)",
            (key, value, _now()),
        )


def _row_to_cve(row: Any) -> CVE:
    return CVE(
        cve_id=row["cve_id"], description=row["description"],
        cvss_score=row["cvss_score"], cvss_vector=row["cvss_vector"],
        cvss_version=row["cvss_version"],
        affected_products=json.loads(row["affected_products"]),
        published_date=datetime.fromisoformat(row["published_date"]),
        last_modified=datetime.fromisoformat(row["last_modified"]),
        source_url=row["source_url"],
    )


class QueueRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    async def insert(self, item: QueueItem) -> QueueItem:
        await self.db.execute(
            "INSERT INTO queue_items "
            "(id, host_id, service_id, cve_id, validation_type, plugin_name, profile_name, "
            "status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (item.id, item.host_id, item.service_id, item.cve_id,
             item.validation_type, item.plugin_name, item.profile_name,
             item.status, _now()),
        )
        await self.db.commit()
        return item

    async def get_by_id(self, item_id: str) -> QueueItem | None:
        async with self.db.execute(
            "SELECT * FROM queue_items WHERE id=?", (item_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row_to_queue_item(row) if row else None

    async def list_pending(self) -> list[QueueItem]:
        async with self.db.execute(
            "SELECT * FROM queue_items WHERE status='pending' ORDER BY created_at DESC"
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_queue_item(r) for r in rows]

    async def list_all(self, limit: int = 100) -> list[QueueItem]:
        async with self.db.execute(
            "SELECT * FROM queue_items ORDER BY created_at DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_queue_item(r) for r in rows]

    async def approve(self, item_id: str, notes: str | None = None) -> None:
        await self.db.execute(
            "UPDATE queue_items SET status='approved', approved_at=?, notes=? WHERE id=?",
            (_now(), notes, item_id),
        )
        await self.db.commit()

    async def reject(self, item_id: str, notes: str | None = None) -> None:
        await self.db.execute(
            "UPDATE queue_items SET status='rejected', notes=? WHERE id=?",
            (notes, item_id),
        )
        await self.db.commit()

    async def set_running(self, item_id: str) -> None:
        await self.db.execute(
            "UPDATE queue_items SET status='running', executed_at=? WHERE id=?",
            (_now(), item_id),
        )
        await self.db.commit()

    async def set_completed(self, item_id: str) -> None:
        await self.db.execute(
            "UPDATE queue_items SET status='completed', completed_at=? WHERE id=?",
            (_now(), item_id),
        )
        await self.db.commit()

    async def set_failed(self, item_id: str, notes: str) -> None:
        await self.db.execute(
            "UPDATE queue_items SET status='failed', completed_at=?, notes=? WHERE id=?",
            (_now(), notes, item_id),
        )
        await self.db.commit()

    async def count_by_status(self) -> dict[str, int]:
        async with self.db.execute(
            "SELECT status, COUNT(*) as cnt FROM queue_items GROUP BY status"
        ) as cur:
            rows = await cur.fetchall()
        return {r["status"]: r["cnt"] for r in rows}

    async def exists_pending(
        self, host_id: str, service_id: str, validation_type: str
    ) -> bool:
        """
        True if an item already exists for this host+service+validation_type
        in any non-terminal state (pending, approved, running). Used to
        suppress duplicates during re-correlation.
        """
        async with self.db.execute(
            "SELECT 1 FROM queue_items "
            "WHERE host_id=? AND service_id=? AND validation_type=? "
            "AND status IN ('pending', 'approved', 'running') LIMIT 1",
            (host_id, service_id, str(validation_type)),
        ) as cur:
            row = await cur.fetchone()
        return row is not None

    async def reject_all_pending(self, notes: str | None = None) -> int:
        """Mark every currently pending item as rejected. Returns count rejected."""
        async with self.db.execute(
            "SELECT COUNT(*) FROM queue_items WHERE status='pending'"
        ) as cur:
            row = await cur.fetchone()
        count = row[0] if row else 0
        if count:
            await self.db.execute(
                "UPDATE queue_items SET status='rejected', notes=? WHERE status='pending'",
                (notes,),
            )
            await self.db.commit()
        return count

    async def list_by_status(self, status: str) -> list[QueueItem]:
        """Flat list of queue items in a single status, newest first."""
        async with self.db.execute(
            "SELECT * FROM queue_items WHERE status=? ORDER BY created_at DESC",
            (status,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_queue_item(r) for r in rows]

    async def count_rejections(
        self, host_id: str, service_id: str, validation_type: str
    ) -> int:
        """Count items in the 'rejected' status for a (host, service, validation_type) triple."""
        async with self.db.execute(
            "SELECT COUNT(*) FROM queue_items "
            "WHERE host_id=? AND service_id=? AND validation_type=? AND status='rejected'",
            (host_id, service_id, str(validation_type)),
        ) as cur:
            row = await cur.fetchone()
        return row[0] if row else 0

    async def get_archivable(
        self,
        retain_exploitable: int,
        retain_not_exploitable: int,
        retain_rejected: int,
    ) -> list[QueueItem]:
        """
        Return queue items that have crossed their retention window.

        Rules:
          - completed items whose linked finding.validation_status =
            'validated_exploitable' use retain_exploitable.
          - completed items whose linked finding.validation_status =
            'validated_not_exploitable' OR has no linked finding use
            retain_not_exploitable.
          - rejected items use retain_rejected, measured from the latest
            completed_at if present otherwise created_at.
        """
        now = datetime.utcnow()
        cutoff_exploit = (now - timedelta(days=int(retain_exploitable))).isoformat()
        cutoff_not_exploit = (now - timedelta(days=int(retain_not_exploitable))).isoformat()
        cutoff_rejected = (now - timedelta(days=int(retain_rejected))).isoformat()

        # Pull completed items joined with their finding (if any).
        async with self.db.execute(
            "SELECT q.*, f.validation_status AS f_validation_status "
            "FROM queue_items q "
            "LEFT JOIN findings f ON f.queue_item_id = q.id "
            "WHERE q.status='completed'"
        ) as cur:
            completed_rows = await cur.fetchall()

        archivable: list[QueueItem] = []
        for row in completed_rows:
            ts_field = row["completed_at"] or row["created_at"]
            if not ts_field:
                continue
            fstatus = row["f_validation_status"]
            if fstatus == "validated_exploitable":
                cutoff = cutoff_exploit
            else:
                cutoff = cutoff_not_exploit
            if ts_field <= cutoff:
                archivable.append(_row_to_queue_item(row))

        # Rejected items past the rejected retention window.
        async with self.db.execute(
            "SELECT * FROM queue_items "
            "WHERE status='rejected' "
            "AND COALESCE(completed_at, created_at) <= ?",
            (cutoff_rejected,),
        ) as cur:
            rejected_rows = await cur.fetchall()

        for row in rejected_rows:
            archivable.append(_row_to_queue_item(row))

        return archivable

    async def archive_to_history(self, item_ids: list[str]) -> int:
        """
        Move each queue item into the history table and delete it.
        Single transaction. Returns count archived.
        """
        if not item_ids:
            return 0
        archived = 0
        try:
            for item_id in item_ids:
                async with self.db.execute(
                    "SELECT * FROM queue_items WHERE id=?", (item_id,)
                ) as cur:
                    row = await cur.fetchone()
                if not row:
                    continue
                summary = (
                    f"Archived queue item {item_id[:8]} "
                    f"({row['validation_type']}, status={row['status']})"
                )
                detail = {
                    "item_id": item_id,
                    "host_id": row["host_id"],
                    "service_id": row["service_id"],
                    "cve_id": row["cve_id"],
                    "validation_type": row["validation_type"],
                    "plugin_name": row["plugin_name"],
                    "profile_name": row["profile_name"],
                    "status": row["status"],
                    "created_at": row["created_at"],
                    "completed_at": row["completed_at"],
                    "notes": row["notes"],
                }
                await self.db.execute(
                    "INSERT INTO history (id, action, summary, detail, timestamp) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (_uuid(), "archive", summary, json.dumps(detail), _now()),
                )
                await self.db.execute(
                    "DELETE FROM queue_items WHERE id=?", (item_id,)
                )
                archived += 1
            await self.db.commit()
        except Exception:
            await self.db.rollback()
            raise
        return archived

    async def purge(self, item_ids: list[str]) -> int:
        """Delete queue items by id. No history entry. Returns count deleted."""
        if not item_ids:
            return 0
        placeholders = ",".join("?" for _ in item_ids)
        async with self.db.execute(
            f"SELECT COUNT(*) FROM queue_items WHERE id IN ({placeholders})",
            tuple(item_ids),
        ) as cur:
            row = await cur.fetchone()
        existing = row[0] if row else 0
        if existing:
            await self.db.execute(
                f"DELETE FROM queue_items WHERE id IN ({placeholders})",
                tuple(item_ids),
            )
            await self.db.commit()
        return existing

    async def purge_test_targets(self) -> int:
        """
        Delete any queue items whose host is a known test/loopback target.
        Returns the count purged. No history entry — these are not real targets.
        """
        loopback = ("127.0.0.1", "localhost", "::1")
        placeholders = ",".join("?" for _ in loopback)
        async with self.db.execute(
            f"SELECT COUNT(*) FROM queue_items "
            f"WHERE host_id IN (SELECT id FROM hosts WHERE ip IN ({placeholders}))",
            loopback,
        ) as cur:
            row = await cur.fetchone()
        count = row[0] if row else 0
        if count:
            await self.db.execute(
                f"DELETE FROM queue_items "
                f"WHERE host_id IN (SELECT id FROM hosts WHERE ip IN ({placeholders}))",
                loopback,
            )
            await self.db.commit()
        return count

    async def stats(self) -> dict[str, Any]:
        """
        Return high-level counts for the settings/health card:
            by_status: {status: count, ...}
            oldest_created_at: ISO string of the oldest queue_item row or None
            archivable_estimate: how many items currently meet retention cutoffs
            purgable_estimate: how many would be purged right now
                               (test targets + repeat-rejected triples)
        """
        from apps.validation.config import (
            RETAIN_EXPLOITABLE_DEFAULT,
            RETAIN_NOT_EXPLOITABLE_DEFAULT,
            RETAIN_REJECTED_DEFAULT,
            get_retention_days,
        )

        by_status = await self.count_by_status()

        async with self.db.execute(
            "SELECT MIN(created_at) FROM queue_items"
        ) as cur:
            row = await cur.fetchone()
        oldest = row[0] if row and row[0] else None

        retain_exploit = get_retention_days(
            "TOOL_RETAIN_EXPLOITABLE", RETAIN_EXPLOITABLE_DEFAULT
        )
        retain_not_exploit = get_retention_days(
            "TOOL_RETAIN_NOT_EXPLOITABLE", RETAIN_NOT_EXPLOITABLE_DEFAULT
        )
        retain_rejected = get_retention_days(
            "TOOL_RETAIN_REJECTED", RETAIN_REJECTED_DEFAULT
        )
        archivable = await self.get_archivable(
            retain_exploit, retain_not_exploit, retain_rejected
        )

        # Purgable = loopback/test target items + (host, service, validation_type)
        # triples with >= 3 rejections in the current queue.
        loopback = ("127.0.0.1", "localhost", "::1")
        ph = ",".join("?" for _ in loopback)
        async with self.db.execute(
            f"SELECT COUNT(*) FROM queue_items "
            f"WHERE host_id IN (SELECT id FROM hosts WHERE ip IN ({ph}))",
            loopback,
        ) as cur:
            r = await cur.fetchone()
        test_target_count = r[0] if r else 0

        async with self.db.execute(
            "SELECT host_id, service_id, validation_type, COUNT(*) AS cnt "
            "FROM queue_items WHERE status='rejected' "
            "GROUP BY host_id, service_id, validation_type "
            "HAVING cnt >= 3"
        ) as cur:
            triples = await cur.fetchall()
        repeat_reject_count = 0
        for t in triples:
            async with self.db.execute(
                "SELECT COUNT(*) FROM queue_items "
                "WHERE host_id=? AND service_id=? AND validation_type=? "
                "AND status IN ('pending', 'approved', 'rejected')",
                (t["host_id"], t["service_id"], t["validation_type"]),
            ) as cur:
                rr = await cur.fetchone()
            repeat_reject_count += rr[0] if rr else 0

        return {
            "by_status": by_status,
            "oldest_created_at": oldest,
            "archivable_estimate": len(archivable),
            "purgable_estimate": test_target_count + repeat_reject_count,
        }


def _row_to_queue_item(row: Any) -> QueueItem:
    return QueueItem(
        id=row["id"], host_id=row["host_id"], service_id=row["service_id"],
        cve_id=row["cve_id"],
        validation_type=ValidationType(row["validation_type"]),
        plugin_name=row["plugin_name"], profile_name=row["profile_name"],
        status=QueueStatus(row["status"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        approved_at=datetime.fromisoformat(row["approved_at"]) if row["approved_at"] else None,
        executed_at=datetime.fromisoformat(row["executed_at"]) if row["executed_at"] else None,
        completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
        notes=row["notes"],
    )


class FindingRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    async def insert(self, finding: Finding) -> Finding:
        await self.db.execute(
            "INSERT INTO findings "
            "(id, queue_item_id, host_id, service_id, cve_id, timestamp, finding_type, "
            "cvss_score, severity, validation_status, evidence, environment_context, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (finding.id, finding.queue_item_id, finding.host_id, finding.service_id,
             finding.cve_id, _now(), finding.finding_type, finding.cvss_score,
             finding.severity, finding.validation_status,
             json.dumps(finding.evidence.model_dump()),
             finding.environment_context, finding.status),
        )
        await self.db.commit()
        return finding

    async def get_by_id(self, finding_id: str) -> Finding | None:
        async with self.db.execute(
            "SELECT * FROM findings WHERE id=?", (finding_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row_to_finding(row) if row else None

    async def list_all(self, limit: int = 200) -> list[Finding]:
        async with self.db.execute(
            "SELECT * FROM findings ORDER BY timestamp DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_finding(r) for r in rows]

    async def list_open(self) -> list[Finding]:
        async with self.db.execute(
            "SELECT * FROM findings WHERE status='open' ORDER BY cvss_score DESC"
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_finding(r) for r in rows]

    async def update_status(self, finding_id: str, status: FindingStatus) -> None:
        await self.db.execute(
            "UPDATE findings SET status=? WHERE id=?", (status, finding_id)
        )
        await self.db.commit()

    async def set_suppressed(self, finding_id: str, reason: str) -> None:
        """Mark a finding suppressed and record why in environment_context."""
        await self.db.execute(
            "UPDATE findings SET status='suppressed', environment_context=? WHERE id=?",
            (f"Auto-suppressed: {reason}", finding_id),
        )
        await self.db.commit()

    async def count_by_severity(self) -> dict[str, int]:
        async with self.db.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
        ) as cur:
            rows = await cur.fetchall()
        return {r["severity"]: r["cnt"] for r in rows}

    async def count_by_validation_status(self) -> dict[str, int]:
        async with self.db.execute(
            "SELECT validation_status, COUNT(*) as cnt FROM findings GROUP BY validation_status"
        ) as cur:
            rows = await cur.fetchall()
        return {r["validation_status"]: r["cnt"] for r in rows}


def _row_to_finding(row: Any) -> Finding:
    evidence_data = json.loads(row["evidence"])
    return Finding(
        id=row["id"], queue_item_id=row["queue_item_id"],
        host_id=row["host_id"], service_id=row["service_id"], cve_id=row["cve_id"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
        finding_type=row["finding_type"], cvss_score=row["cvss_score"],
        severity=FindingSeverity(row["severity"]),
        validation_status=ValidationStatus(row["validation_status"]),
        evidence=Evidence(**evidence_data),
        environment_context=row["environment_context"],
        status=FindingStatus(row["status"]),
    )


class ChangeRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    async def insert(self, change: Change) -> Change:
        await self.db.execute(
            "INSERT INTO changes (id, host_id, service_id, change_type, detail, detected_at, acknowledged) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (change.id, change.host_id, change.service_id,
             change.change_type, json.dumps(change.detail),
             _now(), int(change.acknowledged)),
        )
        await self.db.commit()
        return change

    async def list_unacknowledged(self) -> list[Change]:
        async with self.db.execute(
            "SELECT * FROM changes WHERE acknowledged=0 ORDER BY detected_at DESC"
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_change(r) for r in rows]

    async def list_all(self, limit: int = 200) -> list[Change]:
        async with self.db.execute(
            "SELECT * FROM changes ORDER BY detected_at DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_change(r) for r in rows]

    async def acknowledge(self, change_id: str) -> None:
        await self.db.execute(
            "UPDATE changes SET acknowledged=1 WHERE id=?", (change_id,)
        )
        await self.db.commit()

    async def acknowledge_all(self) -> None:
        await self.db.execute("UPDATE changes SET acknowledged=1 WHERE acknowledged=0")
        await self.db.commit()

    async def count_unacknowledged(self) -> int:
        async with self.db.execute(
            "SELECT COUNT(*) FROM changes WHERE acknowledged=0"
        ) as cur:
            row = await cur.fetchone()
        return row[0] if row else 0


def _row_to_change(row: Any) -> Change:
    return Change(
        id=row["id"], host_id=row["host_id"], service_id=row["service_id"],
        change_type=ChangeType(row["change_type"]),
        detail=json.loads(row["detail"]),
        detected_at=datetime.fromisoformat(row["detected_at"]),
        acknowledged=bool(row["acknowledged"]),
    )


class KnownIssueRepository:
    """CRUD + matching for user-taught finding suppression rules."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    async def insert(self, rule: KnownIssue) -> KnownIssue:
        await self.db.execute(
            "INSERT INTO known_issues "
            "(id, finding_type, match_field, match_value, reason, created_at, "
            "created_by, hit_count, last_hit) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rule.id, rule.finding_type, rule.match_field, rule.match_value,
                rule.reason, _now(), rule.created_by, rule.hit_count,
                rule.last_hit.isoformat() if rule.last_hit else None,
            ),
        )
        await self.db.commit()
        return rule

    async def list_all(self) -> list[KnownIssue]:
        async with self.db.execute(
            "SELECT * FROM known_issues ORDER BY created_at DESC"
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_known_issue(r) for r in rows]

    async def get_by_id(self, rule_id: str) -> KnownIssue | None:
        async with self.db.execute(
            "SELECT * FROM known_issues WHERE id=?", (rule_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row_to_known_issue(row) if row else None

    async def delete(self, rule_id: str) -> bool:
        async with self.db.execute(
            "SELECT 1 FROM known_issues WHERE id=?", (rule_id,)
        ) as cur:
            existed = await cur.fetchone() is not None
        if existed:
            await self.db.execute("DELETE FROM known_issues WHERE id=?", (rule_id,))
            await self.db.commit()
        return existed

    async def record_hit(self, rule_id: str) -> None:
        await self.db.execute(
            "UPDATE known_issues SET hit_count=hit_count+1, last_hit=? WHERE id=?",
            (_now(), rule_id),
        )
        await self.db.commit()

    async def count(self) -> int:
        async with self.db.execute("SELECT COUNT(*) FROM known_issues") as cur:
            row = await cur.fetchone()
        return row[0] if row else 0


def _row_to_known_issue(row: Any) -> KnownIssue:
    return KnownIssue(
        id=row["id"],
        finding_type=row["finding_type"],
        match_field=KnownIssueMatchField(row["match_field"]),
        match_value=row["match_value"],
        reason=row["reason"],
        created_at=datetime.fromisoformat(row["created_at"]),
        created_by=row["created_by"],
        hit_count=row["hit_count"],
        last_hit=datetime.fromisoformat(row["last_hit"]) if row["last_hit"] else None,
    )


class HistoryRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    async def insert(self, entry: HistoryEntry) -> HistoryEntry:
        await self.db.execute(
            "INSERT INTO history (id, action, summary, detail, timestamp) VALUES (?, ?, ?, ?, ?)",
            (entry.id, entry.action, entry.summary,
             json.dumps(entry.detail) if entry.detail else None,
             _now()),
        )
        await self.db.commit()
        return entry

    async def list_all(self, limit: int = 200) -> list[HistoryEntry]:
        async with self.db.execute(
            "SELECT * FROM history ORDER BY timestamp DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_history(r) for r in rows]


def _row_to_history(row: Any) -> HistoryEntry:
    return HistoryEntry(
        id=row["id"], action=HistoryAction(row["action"]),
        summary=row["summary"],
        detail=json.loads(row["detail"]) if row["detail"] else None,
        timestamp=datetime.fromisoformat(row["timestamp"]),
    )


class DCGroupRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    async def list_all(self) -> list[DCGroup]:
        async with self.db.execute(
            "SELECT * FROM dc_groups ORDER BY created_at ASC"
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_dc_group(r) for r in rows]

    async def get_by_id(self, group_id: str) -> DCGroup | None:
        async with self.db.execute(
            "SELECT * FROM dc_groups WHERE id=?", (group_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row_to_dc_group(row) if row else None

    async def insert(self, group: DCGroup) -> DCGroup:
        await self.db.execute(
            "INSERT INTO dc_groups (id, name, location, notes, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (group.id, group.name, group.location, group.notes, _now()),
        )
        await self.db.commit()
        return group

    async def delete(self, group_id: str) -> None:
        # Delete child recon_results and assets first (no ON DELETE CASCADE).
        await self.db.execute(
            "DELETE FROM recon_results "
            "WHERE asset_id IN (SELECT id FROM assets WHERE dc_group_id=?)",
            (group_id,),
        )
        await self.db.execute("DELETE FROM assets WHERE dc_group_id=?", (group_id,))
        await self.db.execute("DELETE FROM dc_groups WHERE id=?", (group_id,))
        await self.db.commit()

    async def update_name(self, group_id: str, name: str) -> None:
        await self.db.execute(
            "UPDATE dc_groups SET name=? WHERE id=?", (name, group_id)
        )
        await self.db.commit()


def _row_to_dc_group(row: Any) -> DCGroup:
    return DCGroup(
        id=row["id"],
        name=row["name"],
        location=row["location"],
        notes=row["notes"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


class AssetRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    async def list_by_group(self, dc_group_id: str) -> list[Asset]:
        async with self.db.execute(
            "SELECT * FROM assets WHERE dc_group_id=? ORDER BY created_at ASC",
            (dc_group_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_asset(r) for r in rows]

    async def list_all(self) -> list[Asset]:
        async with self.db.execute(
            "SELECT * FROM assets ORDER BY created_at ASC"
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_asset(r) for r in rows]

    async def get_by_id(self, asset_id: str) -> Asset | None:
        async with self.db.execute(
            "SELECT * FROM assets WHERE id=?", (asset_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row_to_asset(row) if row else None

    async def insert(self, asset: Asset) -> Asset:
        await self.db.execute(
            "INSERT INTO assets "
            "(id, dc_group_id, name, target, notes, scan_type, workers, "
            "last_scanned_at, last_scan_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                asset.id, asset.dc_group_id, asset.name, asset.target,
                asset.notes, asset.scan_type, asset.workers,
                asset.last_scanned_at.isoformat() if asset.last_scanned_at else None,
                asset.last_scan_id, _now(),
            ),
        )
        await self.db.commit()
        return asset

    async def delete(self, asset_id: str) -> None:
        await self.db.execute("DELETE FROM recon_results WHERE asset_id=?", (asset_id,))
        await self.db.execute("DELETE FROM assets WHERE id=?", (asset_id,))
        await self.db.commit()

    async def update_last_scanned(
        self, asset_id: str, scanned_at: datetime, scan_id: str
    ) -> None:
        await self.db.execute(
            "UPDATE assets SET last_scanned_at=?, last_scan_id=? WHERE id=?",
            (scanned_at.isoformat(), scan_id, asset_id),
        )
        await self.db.commit()

    async def map_target_to_name(self) -> dict[str, str]:
        """Snapshot lookup of asset.target → asset.name for display joins."""
        async with self.db.execute("SELECT name, target FROM assets") as cur:
            rows = await cur.fetchall()
        return {r["target"]: r["name"] for r in rows}


def _row_to_asset(row: Any) -> Asset:
    return Asset(
        id=row["id"],
        dc_group_id=row["dc_group_id"],
        name=row["name"],
        target=row["target"],
        notes=row["notes"],
        scan_type=row["scan_type"] or "quick",
        workers=row["workers"] if row["workers"] is not None else 4,
        last_scanned_at=(
            datetime.fromisoformat(row["last_scanned_at"])
            if row["last_scanned_at"] else None
        ),
        last_scan_id=row["last_scan_id"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


class WatchlistRepository:
    """CRUD + hit tracking for the user-curated CVE watchlist."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    async def list_all(self) -> list[WatchlistEntry]:
        async with self.db.execute(
            "SELECT * FROM cve_watchlist ORDER BY added_at DESC"
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_watchlist(r) for r in rows]

    async def get_by_cve_id(self, cve_id: str) -> WatchlistEntry | None:
        async with self.db.execute(
            "SELECT * FROM cve_watchlist WHERE cve_id=?", (cve_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row_to_watchlist(row) if row else None

    async def get_by_id(self, entry_id: str) -> WatchlistEntry | None:
        async with self.db.execute(
            "SELECT * FROM cve_watchlist WHERE id=?", (entry_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row_to_watchlist(row) if row else None

    async def insert(self, entry: WatchlistEntry) -> WatchlistEntry:
        await self.db.execute(
            "INSERT INTO cve_watchlist "
            "(id, cve_id, description, cvss_score, severity, added_at, last_hit, hit_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry.id, entry.cve_id, entry.description, entry.cvss_score,
                entry.severity, _now(),
                entry.last_hit.isoformat() if entry.last_hit else None,
                entry.hit_count,
            ),
        )
        await self.db.commit()
        return entry

    async def delete(self, entry_id: str) -> None:
        await self.db.execute(
            "DELETE FROM cve_watchlist WHERE id=?", (entry_id,)
        )
        await self.db.commit()

    async def increment_hit(self, cve_id: str) -> None:
        await self.db.execute(
            "UPDATE cve_watchlist SET hit_count=hit_count+1, last_hit=? WHERE cve_id=?",
            (_now(), cve_id),
        )
        await self.db.commit()

    async def count(self) -> int:
        async with self.db.execute("SELECT COUNT(*) FROM cve_watchlist") as cur:
            row = await cur.fetchone()
        return row[0] if row else 0


def _row_to_watchlist(row: Any) -> WatchlistEntry:
    return WatchlistEntry(
        id=row["id"],
        cve_id=row["cve_id"],
        description=row["description"],
        cvss_score=row["cvss_score"],
        severity=row["severity"],
        added_at=datetime.fromisoformat(row["added_at"]),
        last_hit=datetime.fromisoformat(row["last_hit"]) if row["last_hit"] else None,
        hit_count=row["hit_count"] if row["hit_count"] is not None else 0,
    )


class ReconResultRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    async def upsert(self, result: ReconResult) -> ReconResult:
        await self.db.execute(
            "INSERT INTO recon_results "
            "(id, asset_id, hostname, ip, source, discovered_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(asset_id, hostname) DO UPDATE SET "
            "  ip=COALESCE(excluded.ip, ip), "
            "  source=excluded.source, "
            "  discovered_at=excluded.discovered_at",
            (
                result.id, result.asset_id, result.hostname, result.ip,
                result.source, _now(),
            ),
        )
        await self.db.commit()
        return result

    async def list_by_asset(self, asset_id: str) -> list[ReconResult]:
        async with self.db.execute(
            "SELECT * FROM recon_results WHERE asset_id=? ORDER BY hostname",
            (asset_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_recon(r) for r in rows]

    async def count_by_asset(self, asset_id: str) -> int:
        async with self.db.execute(
            "SELECT COUNT(*) FROM recon_results WHERE asset_id=?", (asset_id,)
        ) as cur:
            row = await cur.fetchone()
        return row[0] if row else 0

    async def delete_by_asset(self, asset_id: str) -> int:
        async with self.db.execute(
            "SELECT COUNT(*) FROM recon_results WHERE asset_id=?", (asset_id,)
        ) as cur:
            row = await cur.fetchone()
        count = row[0] if row else 0
        if count:
            await self.db.execute(
                "DELETE FROM recon_results WHERE asset_id=?", (asset_id,)
            )
            await self.db.commit()
        return count


def _row_to_recon(row: Any) -> ReconResult:
    return ReconResult(
        id=row["id"],
        asset_id=row["asset_id"],
        hostname=row["hostname"],
        ip=row["ip"],
        source=row["source"],
        discovered_at=datetime.fromisoformat(row["discovered_at"]),
    )


class MsfRunRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    async def insert(self, run: MsfRun) -> MsfRun:
        await self.db.execute(
            "INSERT INTO msf_runs "
            "(id, module_path, module_type, options_json, target, mode, "
            " status, output, started_at, completed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run.id, run.module_path, run.module_type,
                json.dumps(run.options), run.target,
                str(run.mode), str(run.status),
                run.output, _now(),
                run.completed_at.isoformat() if run.completed_at else None,
            ),
        )
        await self.db.commit()
        return run

    async def update_completion(
        self,
        run_id: str,
        status: MsfRunStatus,
        output: str | None,
    ) -> None:
        await self.db.execute(
            "UPDATE msf_runs SET status=?, output=?, completed_at=? WHERE id=?",
            (str(status), output, _now(), run_id),
        )
        await self.db.commit()

    async def get_by_id(self, run_id: str) -> MsfRun | None:
        async with self.db.execute(
            "SELECT * FROM msf_runs WHERE id=?", (run_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row_to_msf_run(row) if row else None

    async def list_recent(self, limit: int = 20) -> list[MsfRun]:
        async with self.db.execute(
            "SELECT * FROM msf_runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_msf_run(r) for r in rows]

    async def delete(self, run_id: str) -> None:
        await self.db.execute("DELETE FROM msf_runs WHERE id=?", (run_id,))
        await self.db.commit()


def _row_to_msf_run(row: Any) -> MsfRun:
    return MsfRun(
        id=row["id"],
        module_path=row["module_path"],
        module_type=row["module_type"],
        options=json.loads(row["options_json"]) if row["options_json"] else {},
        target=row["target"],
        mode=MsfRunMode(row["mode"]),
        status=MsfRunStatus(row["status"]),
        output=row["output"],
        started_at=datetime.fromisoformat(row["started_at"]),
        completed_at=(
            datetime.fromisoformat(row["completed_at"])
            if row["completed_at"] else None
        ),
    )
