"""Settings router — NVD sync, configuration display."""
import os
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from apps.validation.database import get_db
from apps.validation.engines.nvd_sync import NVDSyncEngine
from apps.validation.repositories import CVERepository

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    async with await get_db() as db:
        cve_repo = CVERepository(db)
        total_cves = await cve_repo.count()
        last_sync = await cve_repo.get_sync_meta("last_sync")

    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "total_cves": total_cves,
            "last_sync": last_sync or "Never",
            "has_api_key": bool(os.getenv("TOOL_NVD_API_KEY")),
        },
    )


@router.post("/settings/nvd-sync")
async def trigger_nvd_sync(full: bool = False):
    api_key = os.getenv("TOOL_NVD_API_KEY")
    engine = NVDSyncEngine(api_key=api_key or None)
    if full:
        result = await engine.sync_full()
    else:
        result = await engine.sync_recent(days=7)
    return result
