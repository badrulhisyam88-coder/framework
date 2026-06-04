"""Evidence API routes — capture and retrieve evidence artifacts."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from apps.investigation_core.evidence.models.artifact import (
    ARTIFACT_TYPE_LABELS,
    ArtifactType,
)
from apps.investigation_core.evidence.services.evidence_service import EvidenceService
from apps.investigation_core.evidence.validation.rules import ArtifactValidationError
from apps.investigation_core.storage.investigation_repo import InvestigationRepository
from apps.validation.database import get_db

router = APIRouter(tags=["investigation-core-evidence"])
templates = Jinja2Templates(directory="frontend/templates")


class CaptureEvidenceRequest(BaseModel):
    artifact_type: str
    title: str
    content: str
    description: str = ""
    finding_id: str | None = None
    learning_path_id: str | None = None
    guided_action_id: str | None = None
    tags: list[str] = []


@router.post("/investigations/{investigation_id}/evidence")
async def capture_evidence(investigation_id: str, body: CaptureEvidenceRequest):
    try:
        artifact_type = ArtifactType(body.artifact_type)
    except ValueError as e:
        raise HTTPException(
            status_code=400, detail=f"Invalid artifact_type: {body.artifact_type}"
        ) from e

    async with get_db() as db:
        inv_repo = InvestigationRepository(db)
        inv = await inv_repo.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")

        svc = EvidenceService(db)
        try:
            artifact = await svc.capture(
                investigation_id,
                artifact_type,
                body.title,
                body.content,
                description=body.description,
                finding_id=body.finding_id,
                learning_path_id=body.learning_path_id,
                guided_action_id=body.guided_action_id,
                tags=body.tags,
            )
        except ArtifactValidationError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e

    return artifact.model_dump(mode="json")


@router.get("/investigations/{investigation_id}/evidence")
async def list_evidence(investigation_id: str):
    async with get_db() as db:
        inv_repo = InvestigationRepository(db)
        inv = await inv_repo.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        svc = EvidenceService(db)
        artifacts = await svc.list_for_investigation(investigation_id)
    return [a.model_dump(mode="json") for a in artifacts]


# ---------------------------------------------------------------------------
# HTMX partial — MUST be registered BEFORE /evidence/{evidence_id}
# Otherwise FastAPI matches "partial" as an evidence_id and returns 404.
# ---------------------------------------------------------------------------


@router.get(
    "/investigations/{investigation_id}/evidence/partial",
    response_class=HTMLResponse,
)
async def evidence_partial(investigation_id: str, request: Request):
    async with get_db() as db:
        inv_repo = InvestigationRepository(db)
        inv = await inv_repo.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        svc = EvidenceService(db)
        artifacts = await svc.list_for_investigation(investigation_id)
        count = len(artifacts)

    return templates.TemplateResponse(
        "partials/evidence_panel.html",
        {
            "request": request,
            "investigation": inv,
            "artifacts": artifacts,
            "artifact_count": count,
            "artifact_type_labels": ARTIFACT_TYPE_LABELS,
            "artifact_types": [t for t in ArtifactType],
        },
    )


# Per-evidence routes — registered AFTER /partial so the literal path wins.
@router.get("/investigations/{investigation_id}/evidence/{evidence_id}")
async def get_evidence(investigation_id: str, evidence_id: str):
    async with get_db() as db:
        svc = EvidenceService(db)
        artifact = await svc.get_by_id(evidence_id)
    if not artifact or artifact.investigation_id != investigation_id:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return artifact.model_dump(mode="json")


@router.delete("/investigations/{investigation_id}/evidence/{evidence_id}")
async def delete_evidence(investigation_id: str, evidence_id: str):
    async with get_db() as db:
        svc = EvidenceService(db)
        artifact = await svc.get_by_id(evidence_id)
        if not artifact or artifact.investigation_id != investigation_id:
            raise HTTPException(status_code=404, detail="Evidence not found")
        await svc.delete(evidence_id)
    return {"deleted": evidence_id}
