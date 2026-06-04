"""Validation queue router."""
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from apps.validation.database import get_db
from apps.validation.models import HistoryAction, HistoryEntry
from apps.validation.repositories import (
    CVERepository,
    HistoryRepository,
    HostRepository,
    QueueRepository,
    ServiceRepository,
)
from apps.validation.services.executor import ExecutorService
from apps.validation.tasks import run_lifecycle_once
from sdk import Logger

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")

# Status filter values accepted by the queue page. "all" means no filter.
_KNOWN_STATUSES = {"pending", "approved", "completed", "rejected", "expired", "all"}


def _hx_refresh_or_json(request: Request, payload: dict) -> HTMLResponse | dict:
    """Helper: return an HX-Refresh response for HTMX, JSON for direct callers."""
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            content="",
            status_code=200,
            headers={"HX-Refresh": "true"},
        )
    return payload


async def _read_notes(request: Request) -> str:
    """Extract `notes` from a request body that is either JSON or form-encoded.

    HTMX sends form-encoded bodies by default (`hx-vals='{...}'` is serialised
    as `application/x-www-form-urlencoded`), while direct API callers send
    JSON. Both must work for these mutation endpoints.
    """
    ctype = (request.headers.get("content-type") or "").lower()
    try:
        if "application/json" in ctype:
            payload = await request.json()
            if isinstance(payload, dict):
                return str(payload.get("notes") or "")
            return ""
        if "form" in ctype:
            form = await request.form()
            return str(form.get("notes") or "")
    except Exception:
        return ""
    return ""


@router.get("/queue", response_class=HTMLResponse)
async def queue_page(
    request: Request,
    host: str | None = None,
    status: str | None = None,
):
    # Normalise the status filter — anything unknown collapses to "pending"
    # (the default tab when the user lands on the queue from the nav).
    selected_status = (status or "pending").lower()
    if selected_status not in _KNOWN_STATUSES:
        selected_status = "pending"

    # Retention windows for the "expired" computation. Imported once so we
    # don't pay an import cost per request.
    from apps.validation.config import (
        RETAIN_EXPLOITABLE_DEFAULT,
        RETAIN_NOT_EXPLOITABLE_DEFAULT,
        RETAIN_REJECTED_DEFAULT,
        get_retention_days,
    )
    retain_exploit = get_retention_days(
        "TOOL_RETAIN_EXPLOITABLE", RETAIN_EXPLOITABLE_DEFAULT
    )
    retain_not_exploit = get_retention_days(
        "TOOL_RETAIN_NOT_EXPLOITABLE", RETAIN_NOT_EXPLOITABLE_DEFAULT
    )
    retain_rejected = get_retention_days(
        "TOOL_RETAIN_REJECTED", RETAIN_REJECTED_DEFAULT
    )

    async with get_db() as db:
        queue_repo = QueueRepository(db)
        host_repo = HostRepository(db)
        service_repo = ServiceRepository(db)
        cve_repo = CVERepository(db)

        # "expired" tab is computed from retention windows, not a stored status.
        if selected_status == "expired":
            items = await queue_repo.get_archivable(
                retain_exploit, retain_not_exploit, retain_rejected
            )
            expired_count = len(items)
        elif selected_status == "all":
            items = await queue_repo.list_all()
            expired_count = len(
                await queue_repo.get_archivable(
                    retain_exploit, retain_not_exploit, retain_rejected
                )
            )
        else:
            items = await queue_repo.list_by_status(selected_status)
            expired_count = len(
                await queue_repo.get_archivable(
                    retain_exploit, retain_not_exploit, retain_rejected
                )
            )

        counts = await queue_repo.count_by_status()

        tab_counts: dict[str, int] = {
            "pending": counts.get("pending", 0),
            "approved": counts.get("approved", 0),
            "completed": counts.get("completed", 0),
            "rejected": counts.get("rejected", 0),
            "expired": expired_count,
            "all": sum(counts.values()),
        }

        # Build asset-name lookup so the queue can show which managed
        # asset (if any) each item belongs to. Match is by exact target IP.
        async with db.execute("SELECT name, target FROM assets") as cur:
            asset_rows = await cur.fetchall()
        asset_name_by_target = {r["target"]: r["name"] for r in asset_rows}

        # Enrich with host/service/cve data
        for item in items:
            item.host = await host_repo.get_by_id(item.host_id)
            item.service = await service_repo.get_by_id(item.service_id)
            if item.cve_id:
                item.cve = await cve_repo.get_by_id(item.cve_id)
            if item.host:
                item.asset_name = asset_name_by_target.get(item.host.ip)

    # Optional filter from /discovery host expansion ("View Queue Items →")
    filtered = [i for i in items if (not host) or i.host_id == host]

    # Group by host for the "Group by Host" view
    groups_map: dict[str, dict] = {}
    for it in filtered:
        g = groups_map.setdefault(
            it.host_id,
            {"host": it.host, "host_id": it.host_id, "items": [], "pending": 0, "approved": 0},
        )
        g["items"].append(it)
        if it.status == "pending":
            g["pending"] += 1
        elif it.status == "approved":
            g["approved"] += 1
    groups = sorted(
        groups_map.values(),
        key=lambda g: g["items"][0].created_at,
        reverse=True,
    )

    return templates.TemplateResponse(
        "queue.html",
        {
            "request": request,
            "items": filtered,
            "groups": groups,
            "counts": counts,
            "tab_counts": tab_counts,
            "selected_host": host,
            "selected_status": selected_status,
        },
    )


@router.post("/queue/reject-all-pending")
async def reject_all_pending(request: Request):
    """Reject every queue item currently in 'pending' status."""
    async with get_db() as db:
        queue_repo = QueueRepository(db)
        history_repo = HistoryRepository(db)
        count = await queue_repo.reject_all_pending(notes="Bulk rejection")
        if count:
            await history_repo.insert(HistoryEntry(
                action=HistoryAction.REJECT,
                summary=f"Bulk rejected {count} pending queue item(s)",
                detail={"count": count, "source": "reject-all-pending"},
            ))
    Logger.info("queue.reject_all_pending", extra={"count": count})

    if request.headers.get("HX-Request"):
        # Force the queue page to refresh so all rows show their new status.
        return HTMLResponse(
            content="",
            status_code=200,
            headers={"HX-Refresh": "true"},
        )
    return {"rejected": count}


@router.post("/queue/purge-test-items")
async def purge_test_items(request: Request):
    """Delete every queue item whose host is loopback/test target."""
    async with get_db() as db:
        repo = QueueRepository(db)
        purged = await repo.purge_test_targets()
    Logger.info("queue.purge_test_items", extra={"purged": purged})
    return _hx_refresh_or_json(request, {"purged": purged})


@router.post("/queue/archive-completed")
async def archive_completed(request: Request):
    """
    Force a full lifecycle pass (archive + purge), regardless of the
    TOOL_AUTO_ARCHIVE flag. Logs an expiry.lifecycle.complete entry.
    """
    result = await run_lifecycle_once(force=True)
    Logger.info("queue.archive_completed", extra=result)
    return _hx_refresh_or_json(request, result)


@router.patch("/queue/{item_id}/approve", response_class=HTMLResponse)
async def approve_item(item_id: str, request: Request):
    notes = await _read_notes(request)
    async with get_db() as db:
        repo = QueueRepository(db)
        item = await repo.get_by_id(item_id)
        if not item:
            raise HTTPException(status_code=404, detail="Queue item not found")
        await repo.approve(item_id, notes)

        # Write history
        history_repo = HistoryRepository(db)
        await history_repo.insert(HistoryEntry(
            action=HistoryAction.APPROVE,
            summary=f"Approved {item.validation_type} on queue item {item_id[:8]}",
            detail={"item_id": item_id, "notes": notes},
        ))

    # Execute immediately after approval
    executor = ExecutorService()
    finding = await executor.execute(item_id)

    # Return updated queue row fragment for HTMX swap
    async with get_db() as db:
        queue_repo = QueueRepository(db)
        host_repo = HostRepository(db)
        service_repo = ServiceRepository(db)
        updated = await queue_repo.get_by_id(item_id)
        if updated:
            updated.host = await host_repo.get_by_id(updated.host_id)
            updated.service = await service_repo.get_by_id(updated.service_id)

    return templates.TemplateResponse(
        "partials/queue_row.html",
        {"request": request, "item": updated, "finding": finding},
    )


@router.patch("/queue/{item_id}/reject", response_class=HTMLResponse)
async def reject_item(item_id: str, request: Request):
    notes = await _read_notes(request)
    async with get_db() as db:
        repo = QueueRepository(db)
        item = await repo.get_by_id(item_id)
        if not item:
            raise HTTPException(status_code=404, detail="Queue item not found")
        await repo.reject(item_id, notes)

        history_repo = HistoryRepository(db)
        await history_repo.insert(HistoryEntry(
            action=HistoryAction.REJECT,
            summary=f"Rejected {item.validation_type} on queue item {item_id[:8]}",
            detail={"item_id": item_id, "notes": notes},
        ))

    async with get_db() as db:
        queue_repo = QueueRepository(db)
        host_repo = HostRepository(db)
        service_repo = ServiceRepository(db)
        updated = await queue_repo.get_by_id(item_id)
        if updated:
            updated.host = await host_repo.get_by_id(updated.host_id)
            updated.service = await service_repo.get_by_id(updated.service_id)

    return templates.TemplateResponse(
        "partials/queue_row.html",
        {"request": request, "item": updated, "finding": None},
    )
