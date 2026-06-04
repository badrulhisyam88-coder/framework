"""Findings router."""
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from apps.validation.database import get_db
from apps.validation.models import (
    FindingStatus,
    KnownIssue,
    KnownIssueMatchField,
    ValidationStatus,
)
from apps.validation.repositories import (
    AssetRepository,
    CVERepository,
    FindingRepository,
    HostRepository,
    KnownIssueRepository,
    ServiceRepository,
)
from sdk import Logger

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")

_FINDING_STATUS_FILTERS = {"open", "suppressed", "all"}


@router.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request, status: str | None = None):
    view = (status or "open").lower()
    if view not in _FINDING_STATUS_FILTERS:
        view = "open"

    async with get_db() as db:
        finding_repo = FindingRepository(db)
        host_repo = HostRepository(db)
        service_repo = ServiceRepository(db)
        cve_repo = CVERepository(db)
        asset_repo = AssetRepository(db)

        all_findings = await finding_repo.list_all(limit=10_000)
        severity_counts = await finding_repo.count_by_severity()
        status_counts = await finding_repo.count_by_validation_status()
        asset_name_by_target = await asset_repo.map_target_to_name()

        open_count = sum(1 for f in all_findings if f.status == "open")
        suppressed_count = sum(1 for f in all_findings if f.status == "suppressed")

        if view == "open":
            findings = [f for f in all_findings if f.status == "open"]
        elif view == "suppressed":
            findings = [f for f in all_findings if f.status == "suppressed"]
        else:
            findings = all_findings

        for f in findings:
            f.host = await host_repo.get_by_id(f.host_id)
            if f.service_id:
                f.service = await service_repo.get_by_id(f.service_id)
            if f.cve_id:
                f.cve = await cve_repo.get_by_id(f.cve_id)
            if f.host:
                f.asset_name = asset_name_by_target.get(f.host.ip)

    # Group findings by host with severity / exploitable counts per group.
    groups_map: dict[str, dict] = {}
    for f in findings:
        g = groups_map.setdefault(
            f.host_id,
            {
                "host": f.host,
                "host_id": f.host_id,
                "asset_name": f.asset_name,
                "items": [],
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "exploitable": 0,
            },
        )
        g["items"].append(f)
        if f.severity in g:
            g[f.severity] += 1
        if f.validation_status == "validated_exploitable":
            g["exploitable"] += 1
    groups = sorted(
        groups_map.values(),
        key=lambda g: (g["exploitable"], g["critical"], g["high"]),
        reverse=True,
    )

    return templates.TemplateResponse(
        "findings.html",
        {
            "request": request,
            "findings": findings,
            "groups": groups,
            "severity_counts": severity_counts,
            "status_counts": status_counts,
            "view": view,
            "open_count": open_count,
            "suppressed_count": suppressed_count,
            "total_count": len(all_findings),
        },
    )


@router.patch("/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: str,
    request: Request,
    status: str = Form(...),
    from_target: str = Form(default=""),
):
    try:
        new_status = FindingStatus(status)
    except ValueError as e:
        raise HTTPException(
            status_code=400, detail=f"Invalid status: {status}"
        ) from e

    async with get_db() as db:
        repo = FindingRepository(db)
        finding = await repo.get_by_id(finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        await repo.update_status(finding_id, new_status)
    Logger.info(
        "finding.status_updated",
        extra={"finding_id": finding_id, "status": str(new_status)},
    )
    if request.headers.get("HX-Request"):
        suffix = f"?from_target={from_target}" if from_target else ""
        return HTMLResponse(
            content="",
            status_code=200,
            headers={
                "HX-Redirect": f"/api/v1/validation/findings/{finding_id}{suffix}"
            },
        )
    return {"id": finding_id, "status": new_status}


@router.get("/findings/{finding_id}", response_class=HTMLResponse)
async def finding_detail(finding_id: str, request: Request):
    async with get_db() as db:
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


@router.post("/findings/{finding_id}/mark-known-issue", response_class=HTMLResponse)
async def mark_known_issue(
    finding_id: str,
    request: Request,
    reason: str = Form(...),
    match_on: str = Form(...),
):
    reason = (reason or "").strip()
    if len(reason) < 10:
        raise HTTPException(
            status_code=400,
            detail="Reason must be at least 10 characters.",
        )
    try:
        field = KnownIssueMatchField(match_on)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid match_on: {match_on}") from e

    async with get_db() as db:
        finding_repo = FindingRepository(db)
        service_repo = ServiceRepository(db)
        host_repo = HostRepository(db)
        cve_repo = CVERepository(db)
        known_repo = KnownIssueRepository(db)

        finding = await finding_repo.get_by_id(finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        service = (
            await service_repo.get_by_id(finding.service_id)
            if finding.service_id else None
        )

        # Derive the rule's match_value from the finding's own data.
        if field == KnownIssueMatchField.FINDING_TYPE:
            match_value = finding.finding_type
        elif field == KnownIssueMatchField.FINDING_TYPE_PORT:
            if not service:
                raise HTTPException(
                    status_code=400,
                    detail="Finding has no service/port; cannot match by port.",
                )
            match_value = str(service.port)
        elif field == KnownIssueMatchField.CVE_ID:
            if not finding.cve_id:
                raise HTTPException(
                    status_code=400,
                    detail="Finding has no CVE; cannot match by CVE id.",
                )
            match_value = finding.cve_id
        elif field == KnownIssueMatchField.FINDING_TYPE_VALIDATION_STATUS:
            match_value = str(ValidationStatus.VALIDATED_NOT_EXPLOITABLE)
        else:
            # FINDING_TYPE_EVIDENCE_CONTAINS — not currently surfaced in the UI,
            # but supported here for completeness. The reason is reused as
            # the substring to match on. Operators can adjust via the API.
            match_value = reason

        rule = KnownIssue(
            finding_type=finding.finding_type,
            match_field=field,
            match_value=match_value,
            reason=reason,
        )
        await known_repo.insert(rule)
        await known_repo.record_hit(rule.id)
        await finding_repo.set_suppressed(finding_id, reason)

        # Reload with display joins for the response template.
        finding = await finding_repo.get_by_id(finding_id)
        finding.host = await host_repo.get_by_id(finding.host_id)
        if finding.service_id:
            finding.service = await service_repo.get_by_id(finding.service_id)
        if finding.cve_id:
            finding.cve = await cve_repo.get_by_id(finding.cve_id)

    Logger.info(
        "known_issue.created",
        extra={
            "rule_id": rule.id,
            "finding_id": finding_id,
            "match_field": str(field),
            "match_value": match_value,
        },
    )
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            content="",
            status_code=200,
            headers={"HX-Redirect": f"/api/v1/validation/findings/{finding_id}"},
        )
    return templates.TemplateResponse(
        "finding_detail.html",
        {"request": request, "finding": finding},
    )
