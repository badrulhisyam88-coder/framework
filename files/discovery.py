"""Discovery router — scan initiation and host/service listing."""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from apps.validation.database import get_db
from apps.validation.models import ScanRequest, ScanResult
from apps.validation.repositories import HostRepository, ServiceRepository
from apps.validation.services.scanner import ScannerService

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")


@router.get("/discovery", response_class=HTMLResponse)
async def discovery_page(request: Request):
    async with await get_db() as db:
        host_repo = HostRepository(db)
        service_repo = ServiceRepository(db)
        hosts = await host_repo.list_all()
        total_services = await service_repo.count()
    return templates.TemplateResponse(
        "discovery.html",
        {"request": request, "hosts": hosts, "total_services": total_services},
    )


@router.post("/discovery/scan")
async def run_scan(request: ScanRequest) -> ScanResult:
    service = ScannerService()
    return await service.run_scan(request)


@router.get("/discovery/hosts")
async def list_hosts():
    async with await get_db() as db:
        repo = HostRepository(db)
        return await repo.list_all()


@router.get("/discovery/hosts/{host_id}/services")
async def list_services(host_id: str):
    async with await get_db() as db:
        repo = ServiceRepository(db)
        return await repo.list_by_host(host_id)
