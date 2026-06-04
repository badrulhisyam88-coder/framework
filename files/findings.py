"""Findings router."""
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from apps.validation.database import get_db
from apps.validation.models import FindingStatus, FindingStatusUpdate
from apps.validation.repositories import CVERepository, FindingRepository, HostRepository, ServiceRepository

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")


@router.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request):
    async with await get_db() as db:
        finding_repo = FindingRepository(db)
        host_repo = HostRepository(db)
        service_repo = ServiceRepository(db)
        cve_repo = CVERepository(db)

        findings = await finding_repo.list_all()
        severity_counts = await finding_repo.count_by_severity()
        status_counts = await finding_repo.count_by_validation_status()

        for f in findings:
            f.host = await host_repo.get_by_id(f.host_id)
            if f.service_id:
                f.service = await service_repo.get_by_id(f.service_id)
            if f.cve_id:
                f.cve = await cve_repo.get_by_id(f.cve_id)

    return templates.TemplateResponse(
        "findings.html",
        {
            "request": request,
            "findings": findings,
            "severity_counts": severity_counts,
            "status_counts": status_counts,
        },
    )


@router.patch("/findings/{finding_id}/status")
async def update_finding_status(finding_id: str, body: FindingStatusUpdate):
    async with await get_db() as db:
        repo = FindingRepository(db)
        finding = await repo.get_by_id(finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        await repo.update_status(finding_id, body.status)
    return {"id": finding_id, "status": body.status}


@router.get("/findings/{finding_id}", response_class=HTMLResponse)
async def finding_detail(finding_id: str, request: Request):
    async with await get_db() as db:
        finding_repo = FindingRepository(db)
        host_repo = HostRepository(db)
        service_repo = ServiceRepository(db)
        cve_repo = CVERepository(db)

        finding = await finding_repo.get_by_id(finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        finding.host = await host_repo.get_by_id(finding.host_id)
        if finding.service_id:
            finding.service = await service_repo.get_by_id(finding.service_id)
        if finding.cve_id:
            finding.cve = await cve_repo.get_by_id(finding.cve_id)

    return templates.TemplateResponse(
        "finding_detail.html",
        {"request": request, "finding": finding},
    )
