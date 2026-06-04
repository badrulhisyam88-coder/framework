"""Guided Action API routes — approval workflow and action discovery."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from apps.investigation_core.evidence.services.evidence_service import EvidenceService
from apps.investigation_core.guided_actions.approvals.approval_service import ApprovalService
from apps.investigation_core.guided_actions.execution.execution_modes import (
    get_execution_context,
)
from apps.investigation_core.guided_actions.models.approval import ApprovalStatus
from apps.investigation_core.guided_actions.registry.action_registry import action_registry
from apps.investigation_core.guided_actions.validation.outcome_validator import (
    OutcomeValidationError,
    validate_completion_request,
)
from apps.investigation_core.services.investigation_service import InvestigationService
from apps.validation.database import get_db

router = APIRouter(tags=["investigation-core-actions"])
templates = Jinja2Templates(directory="frontend/templates")


class ApproveActionRequest(BaseModel):
    notes: str | None = None


class CompleteActionRequest(BaseModel):
    evidence_ids: list[str] = []


# ---------------------------------------------------------------------------
# Action catalogue
# ---------------------------------------------------------------------------


@router.get("/actions")
async def list_all_actions():
    return [
        {
            "action_id": a.action_id,
            "title": a.title,
            "finding_types": a.finding_types,
            "execution_mode": str(a.execution_mode),
            "risk_level": str(a.risk_level),
            "approval_required": a.approval_required,
            "related_learning_path": a.related_learning_path,
        }
        for a in action_registry.all_actions()
    ]


@router.get("/actions/{action_id}")
async def get_action(action_id: str):
    action = action_registry.get(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    return action.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Per-investigation action workflow
# ---------------------------------------------------------------------------


@router.get("/investigations/{investigation_id}/actions")
async def get_investigation_actions(investigation_id: str):
    async with get_db() as db:
        inv_svc = InvestigationService(db)
        inv = await inv_svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        finding_types = await inv_svc._finding_types_for_investigation(inv)
        approval_svc = ApprovalService(db)
        recommended = await approval_svc.recommend_actions(investigation_id, finding_types)

    return [
        {
            "action": a.model_dump(mode="json"),
            "approval": apr.model_dump(mode="json") if apr else None,
        }
        for a, apr in recommended
    ]


@router.post("/investigations/{investigation_id}/actions/{action_id}/request")
async def request_approval(investigation_id: str, action_id: str):
    if not action_registry.get(action_id):
        raise HTTPException(status_code=404, detail="Action not found")
    async with get_db() as db:
        svc = ApprovalService(db)
        approval = await svc.request_approval(investigation_id, action_id)
    return approval.model_dump(mode="json")


@router.post("/investigations/{investigation_id}/actions/{action_id}/approve")
async def approve_action(
    investigation_id: str,
    action_id: str,
    body: ApproveActionRequest,
):
    if not action_registry.get(action_id):
        raise HTTPException(status_code=404, detail="Action not found")
    async with get_db() as db:
        svc = ApprovalService(db)
        approval = await svc.approve(investigation_id, action_id, notes=body.notes)
    return approval.model_dump(mode="json")


@router.post("/investigations/{investigation_id}/actions/{action_id}/reject")
async def reject_action(
    investigation_id: str,
    action_id: str,
    body: ApproveActionRequest,
):
    async with get_db() as db:
        svc = ApprovalService(db)
        try:
            approval = await svc.reject(investigation_id, action_id, notes=body.notes)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
    return approval.model_dump(mode="json")


@router.post("/investigations/{investigation_id}/actions/{action_id}/complete")
async def complete_action(
    investigation_id: str,
    action_id: str,
    body: CompleteActionRequest,
):
    async with get_db() as db:
        svc = ApprovalService(db)
        approval = await svc.get_approval(investigation_id, action_id)
        try:
            validate_completion_request(approval, evidence_ids=body.evidence_ids)
        except OutcomeValidationError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        approval = await svc.complete(
            investigation_id, action_id, evidence_ids=body.evidence_ids
        )
    return approval.model_dump(mode="json")


# ---------------------------------------------------------------------------
# HTMX partials
# ---------------------------------------------------------------------------


@router.get(
    "/investigations/{investigation_id}/actions/partial",
    response_class=HTMLResponse,
)
async def guided_actions_partial(investigation_id: str, request: Request):
    async with get_db() as db:
        inv_svc = InvestigationService(db)
        inv = await inv_svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        finding_types = await inv_svc._finding_types_for_investigation(inv)
        approval_svc = ApprovalService(db)
        recommended = await approval_svc.recommend_actions(investigation_id, finding_types)
        evidence_svc = EvidenceService(db)
        evidence_count = await evidence_svc.count(investigation_id)

    enriched = []
    for action, approval in recommended:
        is_approved = approval and approval.status == ApprovalStatus.APPROVED
        exec_ctx = get_execution_context(action) if is_approved else None
        enriched.append({
            "action": action,
            "approval": approval,
            "exec_ctx": exec_ctx,
        })

    return templates.TemplateResponse(
        "partials/guided_action_panel.html",
        {
            "request": request,
            "investigation": inv,
            "recommended": enriched,
            "evidence_count": evidence_count,
        },
    )


@router.get(
    "/investigations/{investigation_id}/actions/{action_id}/detail-partial",
    response_class=HTMLResponse,
)
async def action_detail_partial(
    investigation_id: str, action_id: str, request: Request
):
    action = action_registry.get(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    async with get_db() as db:
        svc = ApprovalService(db)
        approval = await svc.get_approval(investigation_id, action_id)
        evidence_svc = EvidenceService(db)
        action_evidence = await evidence_svc.list_for_guided_action(
            investigation_id, action_id
        )

    exec_ctx = (
        get_execution_context(action)
        if approval and approval.status == ApprovalStatus.APPROVED
        else None
    )

    return templates.TemplateResponse(
        "partials/action_approval_panel.html",
        {
            "request": request,
            "investigation": {"investigation_id": investigation_id},
            "action": action,
            "approval": approval,
            "exec_ctx": exec_ctx,
            "action_evidence": action_evidence,
        },
    )
