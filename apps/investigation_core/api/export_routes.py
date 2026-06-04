"""Knowledge export API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from apps.investigation_core.evidence.storage.artifact_repo import ArtifactRepository
from apps.investigation_core.exports.services.export_service import ExportService
from apps.investigation_core.guided_actions.approvals.approval_service import ApprovalService
from apps.investigation_core.guided_actions.models.approval import ApprovalStatus
from apps.investigation_core.guided_actions.registry.action_registry import action_registry
from apps.investigation_core.services.investigation_service import InvestigationService
from apps.validation.database import get_db
from apps.validation.repositories import FindingRepository, HostRepository, ServiceRepository

router = APIRouter(tags=["investigation-core-exports"])
templates = Jinja2Templates(directory="frontend/templates")


@router.post("/investigations/{investigation_id}/export")
async def generate_export(investigation_id: str, request: Request):
    async with get_db() as db:
        inv_svc = InvestigationService(db)
        inv = await inv_svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")

        # Derive target (first target in investigation)
        target = inv.targets[0] if inv.targets else investigation_id[:8]

        # Gather findings
        host_repo = HostRepository(db)
        finding_repo = FindingRepository(db)
        svc_repo = ServiceRepository(db)
        all_hosts = await host_repo.list_all()
        host = next((h for h in all_hosts if h.ip == target), None)
        host_id = host.id if host else None
        all_findings = await finding_repo.list_all(limit=10_000)
        findings = [f for f in all_findings if f.host_id == host_id] if host_id else []
        for f in findings:
            if f.service_id:
                f.service = await svc_repo.get_by_id(f.service_id)

        # Gather evidence
        artifact_repo = ArtifactRepository(db)
        evidence = await artifact_repo.list_for_investigation(investigation_id)

        # Gather completed guided actions
        approval_svc = ApprovalService(db)
        approvals = await approval_svc.list_approvals(investigation_id)
        completed_action_objs = [
            action_registry.get(a.action_id)
            for a in approvals
            if a.status == ApprovalStatus.COMPLETED and action_registry.get(a.action_id)
        ]

        export_svc = ExportService(db)
        record = await export_svc.generate_export(
            investigation_id,
            target,
            findings=findings,
            evidence=evidence,
            guided_action_objects=completed_action_objs,
        )

    return {
        "export_id": record.export_id,
        "status": str(record.status),
        "vault_path": record.vault_path,
        "file_path": record.file_path,
    }


@router.get("/investigations/{investigation_id}/exports")
async def list_exports(investigation_id: str):
    async with get_db() as db:
        export_svc = ExportService(db)
        records = await export_svc.list_exports(investigation_id)
    return [r.model_dump(mode="json") for r in records]


# ── HTMX partial ──────────────────────────────────────────────────────────


@router.get(
    "/investigations/{investigation_id}/export/partial",
    response_class=HTMLResponse,
)
async def export_partial(investigation_id: str, request: Request):
    async with get_db() as db:
        inv_svc = InvestigationService(db)
        inv = await inv_svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        export_svc = ExportService(db)
        exports = await export_svc.list_exports(investigation_id)

    return templates.TemplateResponse(
        "partials/export_panel.html",
        {
            "request": request,
            "investigation": inv,
            "exports": exports,
        },
    )
