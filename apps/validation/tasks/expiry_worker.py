"""
Queue lifecycle expiry worker.

Background hourly task that prunes the validation queue:
  * Permanently purges any (host, service, validation_type) triple that has
    accumulated 3 or more rejections (the operator has decided it's noise).
  * Archives completed / rejected items past their retention windows by
    writing a history row and deleting the queue_item.

Public surface (consumed by the orchestrator in core/api/app.py):
    start_expiry_worker()
    stop_expiry_worker()
    run_lifecycle_once(force=False)
"""

from __future__ import annotations

import asyncio
from typing import Any

from apps.validation.config import (
    RETAIN_EXPLOITABLE_DEFAULT,
    RETAIN_NOT_EXPLOITABLE_DEFAULT,
    RETAIN_REJECTED_DEFAULT,
    get_auto_archive,
    get_retention_days,
)
from apps.validation.database import get_db
from apps.validation.repositories import QueueRepository
from sdk import Logger

# Run cadence — once per hour.
LIFECYCLE_INTERVAL_SECONDS = 3600

# Threshold for "rejected too many times — operator has decided this isn't
# worth re-queuing". Items matching the (host, service, validation_type) of
# any triple with >= REJECT_REPEAT_THRESHOLD rejections are purged.
REJECT_REPEAT_THRESHOLD = 3

_task: asyncio.Task[None] | None = None
_lock = asyncio.Lock()


async def _collect_repeat_reject_ids(repo: QueueRepository) -> list[str]:
    """
    Find (host_id, service_id, validation_type) triples with >= 3 rejections,
    then collect every queue_item id (any non-terminal-or-rejected status)
    matching those triples for purging.
    """
    # We talk to the DB directly here because QueueRepository has no helper
    # for the GROUP BY ... HAVING pattern. Reuse the open connection.
    async with repo.db.execute(
        "SELECT host_id, service_id, validation_type, COUNT(*) AS cnt "
        "FROM queue_items WHERE status='rejected' "
        "GROUP BY host_id, service_id, validation_type "
        "HAVING cnt >= ?",
        (REJECT_REPEAT_THRESHOLD,),
    ) as cur:
        triples = await cur.fetchall()

    ids: list[str] = []
    for t in triples:
        async with repo.db.execute(
            "SELECT id FROM queue_items "
            "WHERE host_id=? AND service_id=? AND validation_type=? "
            "AND status IN ('pending', 'approved', 'rejected')",
            (t["host_id"], t["service_id"], t["validation_type"]),
        ) as cur:
            rows = await cur.fetchall()
        ids.extend(r["id"] for r in rows)
    return ids


async def run_lifecycle_once(force: bool = False) -> dict[str, Any]:
    """
    Run one queue-lifecycle pass.

    Args:
        force: If True, run even when get_auto_archive() is False. The HTTP
               "Archive Completed" button uses force=True.

    Returns a dict of counts:
        {"archived": int, "purged": int, "reactivated": int, "skipped": bool}
    """
    if not force and not get_auto_archive():
        Logger.info("expiry.lifecycle.skipped", extra={"reason": "auto_archive_off"})
        return {"archived": 0, "purged": 0, "reactivated": 0, "skipped": True}

    archived = 0
    purged = 0

    try:
        async with get_db() as db:
            repo = QueueRepository(db)

            # 1. Purge repeat-rejected triples.
            repeat_ids = await _collect_repeat_reject_ids(repo)
            if repeat_ids:
                purged = await repo.purge(repeat_ids)

            # 2. Archive items past their retention window.
            retain_exploit = get_retention_days(
                "TOOL_RETAIN_EXPLOITABLE", RETAIN_EXPLOITABLE_DEFAULT
            )
            retain_not_exploit = get_retention_days(
                "TOOL_RETAIN_NOT_EXPLOITABLE", RETAIN_NOT_EXPLOITABLE_DEFAULT
            )
            retain_rejected = get_retention_days(
                "TOOL_RETAIN_REJECTED", RETAIN_REJECTED_DEFAULT
            )
            archivable = await repo.get_archivable(
                retain_exploit, retain_not_exploit, retain_rejected
            )
            if archivable:
                archived = await repo.archive_to_history([a.id for a in archivable])

    except Exception as exc:
        # Never let an exception bubble out and kill the loop.
        Logger.error(
            "expiry.lifecycle.error",
            extra={"error": str(exc), "archived": archived, "purged": purged},
        )
        return {
            "archived": archived,
            "purged": purged,
            "reactivated": 0,
            "skipped": False,
            "error": str(exc),
        }

    Logger.info(
        "expiry.lifecycle.complete",
        extra={"archived": archived, "purged": purged, "reactivated": 0},
    )
    return {
        "archived": archived,
        "purged": purged,
        "reactivated": 0,
        "skipped": False,
    }


async def _loop() -> None:
    """Hourly loop. Sleeps first so startup isn't spiked by an immediate run."""
    while True:
        try:
            await asyncio.sleep(LIFECYCLE_INTERVAL_SECONDS)
            await run_lifecycle_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Defensive: keep looping even if a cycle blows up.
            Logger.error("expiry.loop.error", extra={"error": str(exc)})


async def start_expiry_worker() -> None:
    """Idempotent — calling twice is a no-op."""
    global _task
    async with _lock:
        if _task and not _task.done():
            return
        _task = asyncio.create_task(_loop(), name="queue-expiry-worker")
        Logger.info(
            "expiry.worker.started",
            extra={"interval_seconds": LIFECYCLE_INTERVAL_SECONDS},
        )


async def stop_expiry_worker() -> None:
    """Idempotent — safe to call when the task isn't running."""
    global _task
    async with _lock:
        task = _task
        _task = None
    if task is None or task.done():
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        Logger.error("expiry.worker.stop_error", extra={"error": str(exc)})
    Logger.info("expiry.worker.stopped", extra={})
