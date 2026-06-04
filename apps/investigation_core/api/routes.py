"""FastAPI routes for investigation_core.

All routes are mounted under /api/v1/validation/investigation-core by the
validation API __init__.py.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from apps.investigation_core.learning.path_registry import registry as path_registry
from apps.investigation_core.services.investigation_service import InvestigationService
from apps.investigation_core.taxonomy.stages import EVENT_TYPE_LABELS, STAGE_LABELS, EventType
from apps.validation.database import get_db

router = APIRouter(tags=["investigation-core"])
templates = Jinja2Templates(directory="frontend/templates")


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class CreateInvestigationRequest(BaseModel):
    target: str
    title: str | None = None


class RecordEventRequest(BaseModel):
    event_type: str
    summary: str
    detail: dict[str, Any] | None = None
    actor: str = "user"


class StartLearningPathRequest(BaseModel):
    path_id: str


# ---------------------------------------------------------------------------
# Investigation CRUD
# ---------------------------------------------------------------------------


@router.post("/investigations")
async def create_investigation(body: CreateInvestigationRequest):
    async with get_db() as db:
        svc = InvestigationService(db)
        inv, created = await svc.get_or_create(body.target, title=body.title)
    return {"investigation_id": inv.investigation_id, "created": created}


@router.get("/investigations")
async def list_investigations():
    async with get_db() as db:
        svc = InvestigationService(db)
        investigations = await svc.list_all()
    return [i.model_dump(mode="json") for i in investigations]


@router.get("/investigations/{investigation_id}")
async def get_investigation(investigation_id: str):
    async with get_db() as db:
        svc = InvestigationService(db)
        inv = await svc.get_by_id(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


@router.get("/investigations/{investigation_id}/timeline")
async def get_timeline(investigation_id: str):
    async with get_db() as db:
        svc = InvestigationService(db)
        inv = await svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        events = await svc.get_timeline(investigation_id)
    return [e.model_dump(mode="json") for e in events]


@router.post("/investigations/{investigation_id}/events")
async def record_event(investigation_id: str, body: RecordEventRequest):
    try:
        event_type = EventType(body.event_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid event_type: {body.event_type}") from e

    async with get_db() as db:
        svc = InvestigationService(db)
        inv = await svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        event = await svc.record_raw_event(
            investigation_id,
            event_type,
            body.summary,
            detail=body.detail,
            actor=body.actor,
        )
    return event.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Learning paths
# ---------------------------------------------------------------------------


@router.get("/learning/paths")
async def list_paths():
    paths = path_registry.all_paths()
    return [
        {
            "path_id": p.path_id,
            "title": p.title,
            "difficulty": p.difficulty,
            "finding_types": p.finding_types,
            "step_count": len(p.guided_steps),
            "objectives": p.learning_objectives,
        }
        for p in paths
    ]


@router.get("/learning/paths/{path_id}")
async def get_path(path_id: str):
    path = path_registry.get(path_id)
    if not path:
        raise HTTPException(status_code=404, detail="Path not found")
    return path.model_dump(mode="json")


@router.get("/investigations/{investigation_id}/learning")
async def get_learning_recommendations(investigation_id: str):
    async with get_db() as db:
        svc = InvestigationService(db)
        inv = await svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        recommendations = await svc.get_recommendations(investigation_id)
        progress_list = await svc.get_progress(investigation_id)
    return {
        "recommendations": [
            {
                "path_id": r.path.path_id,
                "title": r.path.title,
                "difficulty": r.path.difficulty,
                "matched_finding_types": r.matched_finding_types,
                "already_started": r.already_started,
                "already_completed": r.already_completed,
                "step_count": len(r.path.guided_steps),
            }
            for r in recommendations
        ],
        "progress": [p.model_dump(mode="json") for p in progress_list],
    }


@router.post("/investigations/{investigation_id}/learning/start")
async def start_learning_path(investigation_id: str, body: StartLearningPathRequest):
    async with get_db() as db:
        svc = InvestigationService(db)
        inv = await svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if not path_registry.get(body.path_id):
            raise HTTPException(status_code=404, detail="Learning path not found")
        progress = await svc.start_learning_path(investigation_id, body.path_id, actor="user")
    return progress.model_dump(mode="json")


@router.post("/investigations/{investigation_id}/learning/{path_id}/steps/{step_id}/complete")
async def complete_step(investigation_id: str, path_id: str, step_id: str):
    async with get_db() as db:
        svc = InvestigationService(db)
        inv = await svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        try:
            progress = await svc.complete_step(investigation_id, path_id, step_id)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
    return progress.model_dump(mode="json")


# ---------------------------------------------------------------------------
# HTMX partials
# ---------------------------------------------------------------------------


@router.get("/investigations/{investigation_id}/timeline/partial", response_class=HTMLResponse)
async def timeline_partial(investigation_id: str, request: Request):
    async with get_db() as db:
        svc = InvestigationService(db)
        inv = await svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        events = await svc.get_timeline(investigation_id)

    return templates.TemplateResponse(
        "partials/investigation_timeline_panel.html",
        {
            "request": request,
            "investigation": inv,
            "events": events,
            "event_labels": EVENT_TYPE_LABELS,
            "stage_labels": STAGE_LABELS,
        },
    )


@router.get("/investigations/{investigation_id}/learning/partial", response_class=HTMLResponse)
async def learning_partial(investigation_id: str, request: Request):
    async with get_db() as db:
        svc = InvestigationService(db)
        inv = await svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        recommendations = await svc.get_recommendations(investigation_id)
        progress_list = await svc.get_progress(investigation_id)

    progress_by_path = {p.path_id: p for p in progress_list}

    return templates.TemplateResponse(
        "partials/learning_path_panel.html",
        {
            "request": request,
            "investigation": inv,
            "recommendations": recommendations,
            "progress_by_path": progress_by_path,
        },
    )
