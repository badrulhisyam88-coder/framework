"""Changes router."""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from apps.validation.database import get_db
from apps.validation.repositories import ChangeRepository

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")


@router.get("/changes", response_class=HTMLResponse)
async def changes_page(request: Request):
    async with get_db() as db:
        repo = ChangeRepository(db)
        changes = await repo.list_all()
        unacked = await repo.count_unacknowledged()
    return templates.TemplateResponse(
        "changes.html",
        {"request": request, "changes": changes, "unacknowledged": unacked},
    )


@router.post("/changes/{change_id}/acknowledge")
async def acknowledge_change(change_id: str):
    async with get_db() as db:
        repo = ChangeRepository(db)
        await repo.acknowledge(change_id)
    return {"acknowledged": True}


@router.post("/changes/acknowledge-all")
async def acknowledge_all():
    async with get_db() as db:
        repo = ChangeRepository(db)
        await repo.acknowledge_all()
    return {"acknowledged": True}
