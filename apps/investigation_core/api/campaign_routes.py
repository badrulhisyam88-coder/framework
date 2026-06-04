"""Campaign API routes — CRUD + dashboard / timeline HTMX partials.

All endpoints are mounted under /api/v1/validation/investigation-core/campaigns.
Routes are human-driven: no auto-launch, no autonomous chaining.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from apps.investigation_core.campaigns.models.campaign import (
    CAMPAIGN_STATUS_LABELS,
    STAGE_LABELS,
    STAGE_ORDER,
    CampaignStage,
    CampaignStatus,
)
from apps.investigation_core.campaigns.models.objective import (
    CampaignObjective,
    SubObjective,
)
from apps.investigation_core.campaigns.services.campaign_service import CampaignService
from apps.investigation_core.storage.investigation_repo import InvestigationRepository
from apps.validation.database import get_db

router = APIRouter(tags=["investigation-core-campaigns"])
templates = Jinja2Templates(directory="frontend/templates")


# ── Request / response models ──────────────────────────────────────────────


class CreateCampaignRequest(BaseModel):
    title: str
    description: str = ""
    status: str = "planning"


class AttachInvestigationRequest(BaseModel):
    investigation_id: str
    stage: str = "recon"
    parent_investigation_id: str | None = None
    notes: str | None = None


class UpdateMembershipRequest(BaseModel):
    stage: str


class UpdateCampaignRequest(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None


class SubObjectiveRequest(BaseModel):
    title: str
    milestone_keys: list[str] = []
    finding_types: list[str] = []


class AddObjectiveRequest(BaseModel):
    title: str
    description: str = ""
    sub_objectives: list[SubObjectiveRequest] = []


# ── JSON CRUD ───────────────────────────────────────────────────────────────


@router.get("/campaigns")
async def list_campaigns():
    async with get_db() as db:
        svc = CampaignService(db)
        campaigns = await svc.list_campaigns()
    return [c.model_dump(mode="json") for c in campaigns]


@router.post("/campaigns")
async def create_campaign(body: CreateCampaignRequest):
    try:
        status = CampaignStatus(body.status)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}") from e
    async with get_db() as db:
        svc = CampaignService(db)
        campaign = await svc.create_campaign(
            title=body.title.strip() or "Untitled Campaign",
            description=body.description,
            status=status,
        )
    return campaign.model_dump(mode="json")


@router.get("/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str):
    async with get_db() as db:
        svc = CampaignService(db)
        campaign = await svc.get_campaign(campaign_id)
        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")
        members = await svc.list_members(campaign_id)
    return {
        "campaign": campaign.model_dump(mode="json"),
        "members": [m.model_dump(mode="json") for m in members],
    }


@router.patch("/campaigns/{campaign_id}")
async def update_campaign(campaign_id: str, body: UpdateCampaignRequest):
    async with get_db() as db:
        svc = CampaignService(db)
        campaign = await svc.get_campaign(campaign_id)
        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")
        if body.title is not None:
            campaign.title = body.title
        if body.description is not None:
            campaign.description = body.description
        if body.status is not None:
            try:
                campaign.status = CampaignStatus(body.status)
            except ValueError as e:
                raise HTTPException(
                    status_code=400, detail=f"Invalid status: {body.status}"
                ) from e
        await svc.update_campaign(campaign)
    return campaign.model_dump(mode="json")


@router.post("/campaigns/{campaign_id}/investigations")
async def attach_investigation(campaign_id: str, body: AttachInvestigationRequest):
    try:
        stage = CampaignStage(body.stage)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid stage: {body.stage}") from e
    async with get_db() as db:
        svc = CampaignService(db)
        if not await svc.get_campaign(campaign_id):
            raise HTTPException(status_code=404, detail="Campaign not found")
        inv_repo = InvestigationRepository(db)
        if not await inv_repo.get_by_id(body.investigation_id):
            raise HTTPException(status_code=404, detail="Investigation not found")
        membership = await svc.add_investigation(
            campaign_id,
            body.investigation_id,
            stage=stage,
            parent_investigation_id=body.parent_investigation_id,
            notes=body.notes,
        )
    return membership.model_dump(mode="json")


@router.patch("/campaigns/{campaign_id}/investigations/{investigation_id}")
async def update_membership(
    campaign_id: str, investigation_id: str, body: UpdateMembershipRequest
):
    try:
        stage = CampaignStage(body.stage)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid stage: {body.stage}") from e
    async with get_db() as db:
        svc = CampaignService(db)
        await svc.update_membership_stage(campaign_id, investigation_id, stage)
    return {"campaign_id": campaign_id, "investigation_id": investigation_id, "stage": str(stage)}


@router.delete("/campaigns/{campaign_id}/investigations/{investigation_id}")
async def detach_investigation(campaign_id: str, investigation_id: str):
    async with get_db() as db:
        svc = CampaignService(db)
        await svc.detach_investigation(campaign_id, investigation_id)
    return {"detached": investigation_id, "campaign_id": campaign_id}


@router.post("/campaigns/{campaign_id}/objectives")
async def add_objective(campaign_id: str, body: AddObjectiveRequest):
    async with get_db() as db:
        svc = CampaignService(db)
        campaign = await svc.get_campaign(campaign_id)
        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")
        objective = CampaignObjective(
            title=body.title,
            description=body.description,
            sub_objectives=[
                SubObjective(
                    title=s.title,
                    milestone_keys=s.milestone_keys,
                    finding_types=s.finding_types,
                )
                for s in body.sub_objectives
            ],
        )
        campaign.objectives.append(objective)
        await svc.update_campaign(campaign)
    return objective.model_dump(mode="json")


# ── HTMX partials ──────────────────────────────────────────────────────────


@router.get("/campaigns/{campaign_id}/dashboard/partial", response_class=HTMLResponse)
async def campaign_dashboard_partial(campaign_id: str, request: Request):
    async with get_db() as db:
        svc = CampaignService(db)
        campaign = await svc.get_campaign(campaign_id)
        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")
        members = await svc.list_members(campaign_id)
        snapshot = await svc.progress_snapshot(campaign_id)
        # Pull titles for each member investigation
        inv_repo = InvestigationRepository(db)
        member_views = []
        for m in members:
            inv = await inv_repo.get_by_id(m.investigation_id)
            member_views.append({
                "membership": m,
                "investigation_title": inv.title if inv else m.investigation_id[:8],
                "stage_label": STAGE_LABELS[str(m.stage)],
            })

    response = templates.TemplateResponse(
        "partials/campaign_dashboard.html",
        {
            "request": request,
            "campaign": campaign,
            "members": member_views,
            "snapshot": snapshot,
            "stage_labels": STAGE_LABELS,
            "stage_order": STAGE_ORDER,
            "status_labels": CAMPAIGN_STATUS_LABELS,
        },
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


@router.get("/campaigns/{campaign_id}/timeline/partial", response_class=HTMLResponse)
async def campaign_timeline_partial(campaign_id: str, request: Request):
    async with get_db() as db:
        svc = CampaignService(db)
        if not await svc.get_campaign(campaign_id):
            raise HTTPException(status_code=404, detail="Campaign not found")
        snapshot = await svc.progress_snapshot(campaign_id)

    return templates.TemplateResponse(
        "partials/campaign_timeline.html",
        {
            "request": request,
            "campaign_id": campaign_id,
            "snapshot": snapshot,
            "stage_labels": STAGE_LABELS,
        },
    )


@router.post("/campaigns/{campaign_id}/synthesize")
async def synthesize_campaign(campaign_id: str):
    """Render the campaign-level markdown synthesis into the knowledge vault."""
    from apps.investigation_core.campaigns.exports.synthesis_service import (
        CampaignSynthesisService,
    )

    async with get_db() as db:
        svc = CampaignSynthesisService(db)
        try:
            result = await svc.synthesize(campaign_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
    return result


@router.get("/campaigns/list/partial", response_class=HTMLResponse)
async def campaigns_list_partial(request: Request):
    async with get_db() as db:
        svc = CampaignService(db)
        campaigns = await svc.list_campaigns()
        # Pull a quick member count for each
        member_counts: dict[str, int] = {}
        for c in campaigns:
            ms = await svc.list_members(c.campaign_id)
            member_counts[c.campaign_id] = len(ms)
    return templates.TemplateResponse(
        "partials/campaigns_list.html",
        {
            "request": request,
            "campaigns": campaigns,
            "member_counts": member_counts,
            "status_labels": CAMPAIGN_STATUS_LABELS,
        },
    )
