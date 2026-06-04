"""Discovery router."""
import json

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from apps.validation.config import clamp_workers, get_default_workers
from apps.validation.database import get_db
from apps.validation.models import ScanRequest
from apps.validation.repositories import AssetRepository, HostRepository, ServiceRepository
from apps.validation.services.scanner import ScannerService
from sdk import Logger

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")


@router.get("/discovery", response_class=HTMLResponse)
async def discovery_page(request: Request):
    async with get_db() as db:
        host_repo = HostRepository(db)
        service_repo = ServiceRepository(db)
        asset_repo = AssetRepository(db)
        hosts = await host_repo.list_all()
        total_services = await service_repo.count()
        services_per_host = await service_repo.count_by_host_all()
        asset_name_by_target = await asset_repo.map_target_to_name()
    for h in hosts:
        h.asset_name = asset_name_by_target.get(h.ip)
    return templates.TemplateResponse(
        "discovery.html",
        {
            "request": request,
            "hosts": hosts,
            "total_services": total_services,
            "services_per_host": services_per_host,
            "default_workers": get_default_workers(),
        },
    )


@router.post("/discovery/scan")
async def run_scan(
    request: Request,
    target: str = Form(...),
    scan_type: str = Form("quick"),
    custom_args: str | None = Form(None),
    workers: int = Form(default=None),
):
    effective_workers = clamp_workers(workers if workers is not None else get_default_workers())
    scan_request = ScanRequest(
        target=target,
        scan_type=scan_type,
        custom_args=custom_args,
        workers=effective_workers,
    )
    service = ScannerService()
    result = await service.run_scan(scan_request)

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            "partials/scan_result.html",
            {"request": request, "result": result},
        )
    return result


@router.get("/discovery/scan-stream")
async def scan_stream(
    request: Request,
    target: str,
    scan_type: str = "quick",
    custom_args: str | None = None,
    workers: int | None = None,
):
    """DEPRECATED — use POST /api/v1/validation/scanner/investigations/{id}/runs instead.

    This SSE endpoint is preserved for backward compatibility only.
    It will be removed in a future release. Migrate to the investigation-run
    orchestration API which provides grouped execution, evidence linkage,
    and investigation continuity.
    """
    from apps.scanner_orchestration.target_resolution.ssrf_guard import validate_target

    # SSRF guard — same policy as the canonical /runs endpoint
    allowed, reason = validate_target(target)
    if not allowed:
        Logger.info(
            "discovery.scan_stream.ssrf_blocked",
            extra={"target": target, "reason": reason},
        )
        # Return SSE-format error so clients handling events see it
        async def error_stream():
            yield f'event: error\ndata: {json.dumps({"message": reason})}\n\n'
        return StreamingResponse(error_stream(), media_type="text/event-stream")

    Logger.info(
        "discovery.scan_stream.deprecated",
        extra={"target": target, "path": "/discovery/scan-stream"},
    )

    effective_workers = clamp_workers(workers if workers is not None else get_default_workers())
    scan_request = ScanRequest(
        target=target,
        scan_type=scan_type,
        custom_args=custom_args,
        workers=effective_workers,
    )
    service = ScannerService()

    async def event_generator():
        try:
            async for event in service.run_scan_stream(scan_request):
                if await request.is_disconnected():
                    Logger.info("scan_stream.client_disconnected", extra={"target": target})
                    break
                if event["type"] == "complete":
                    result = event["result"]
                    html = templates.get_template("partials/scan_result.html").render(
                        request=request, result=result
                    )
                    payload = json.dumps({
                        "hosts_found": result.hosts_found,
                        "services_found": result.services_found,
                        "queue_items_created": result.queue_items_created,
                        "html": html,
                    })
                    yield f"event: complete\ndata: {payload}\n\n"
                else:
                    payload = json.dumps({
                        k: v for k, v in event.items() if k != "type"
                    })
                    yield f"event: {event['type']}\ndata: {payload}\n\n"
        except Exception as e:
            Logger.error("scan_stream.error", extra={"error": str(e), "target": target})
            yield f"event: error\ndata: {json.dumps({'message': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/discovery/hosts")
async def list_hosts():
    async with get_db() as db:
        repo = HostRepository(db)
        return await repo.list_all()


@router.get("/discovery/hosts/{host_id}/services")
async def list_services(host_id: str, request: Request):
    async with get_db() as db:
        repo = ServiceRepository(db)
        services = await repo.list_by_host(host_id)

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            "partials/host_services.html",
            {"request": request, "services": services, "host_id": host_id},
        )
    return services
