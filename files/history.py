"""History router."""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from apps.validation.database import get_db
from apps.validation.repositories import HistoryRepository

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")


@router.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    async with await get_db() as db:
        repo = HistoryRepository(db)
        entries = await repo.list_all()
    return templates.TemplateResponse(
        "history.html", {"request": request, "entries": entries}
    )
