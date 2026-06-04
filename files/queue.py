"""Validation queue router."""
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from apps.validation.database import get_db
from apps.validation.models import ApprovalRequest, RejectionRequest
from apps.validation.repositories import CVERepository, HistoryRepository, QueueRepository, ServiceRepository, HostRepository
from apps.validation.services.executor import ExecutorService

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")


@router.get("/queue", response_class=HTMLResponse)
async def queue_page(request: Request):
    async with await get_db() as db:
        queue_repo = QueueRepository(db)
        host_repo = HostRepository(db)
        service_repo = ServiceRepository(db)
        cve_repo = CVERepository(db)

        items = await queue_repo.list_all()
        counts = await queue_repo.count_by_status()

        # Enrich with host/service/cve data
        for item in items:
            item.host = await host_repo.get_by_id(item.host_id)
            item.service = await service_repo.get_by_id(item.service_id)
            if item.cve_id:
                item.cve = await cve_repo.get_by_id(item.cve_id)

    return templates.TemplateResponse(
        "queue.html",
        {"request": request, "items": items, "counts": counts},
    )


@router.patch("/queue/{item_id}/approve", response_class=HTMLResponse)
async def approve_item(item_id: str, body: ApprovalRequest, request: Request):
    async with await get_db() as db:
        repo = QueueRepository(db)
        item = await repo.get_by_id(item_id)
        if not item:
            raise HTTPException(status_code=404, detail="Queue item not found")
        await repo.approve(item_id, body.notes)

        # Write history
        history_repo = HistoryRepository(db)
        from apps.validation.models import HistoryAction, HistoryEntry
        await history_repo.insert(HistoryEntry(
            action=HistoryAction.APPROVE,
            summary=f"Approved {item.validation_type} on queue item {item_id[:8]}",
            detail={"item_id": item_id, "notes": body.notes},
        ))

    # Execute immediately after approval
    executor = ExecutorService()
    finding = await executor.execute(item_id)

    # Return updated queue row fragment for HTMX swap
    async with await get_db() as db:
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
async def reject_item(item_id: str, body: RejectionRequest, request: Request):
    async with await get_db() as db:
        repo = QueueRepository(db)
        item = await repo.get_by_id(item_id)
        if not item:
            raise HTTPException(status_code=404, detail="Queue item not found")
        await repo.reject(item_id, body.notes)

        history_repo = HistoryRepository(db)
        from apps.validation.models import HistoryAction, HistoryEntry
        await history_repo.insert(HistoryEntry(
            action=HistoryAction.REJECT,
            summary=f"Rejected {item.validation_type} on queue item {item_id[:8]}",
            detail={"item_id": item_id, "notes": body.notes},
        ))

    async with await get_db() as db:
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
