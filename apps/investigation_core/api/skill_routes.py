"""Skill graph and mastery API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from apps.investigation_core.evidence.storage.artifact_repo import ArtifactRepository
from apps.investigation_core.guided_actions.approvals.approval_service import ApprovalService
from apps.investigation_core.guided_actions.models.approval import ApprovalStatus
from apps.investigation_core.progression.models.mastery import MASTERY_STATUS_LABELS
from apps.investigation_core.progression.tracking.mastery_tracker import MasteryTracker
from apps.investigation_core.services.investigation_service import InvestigationService
from apps.investigation_core.skills.graph.skill_graph import skill_graph
from apps.investigation_core.skills.recommendations.skill_recommender import SkillRecommender
from apps.investigation_core.storage.learning_repo import LearningProgressRepository
from apps.validation.database import get_db

router = APIRouter(tags=["investigation-core-skills"])
templates = Jinja2Templates(directory="frontend/templates")
_recommender = SkillRecommender()


@router.get("/skills")
async def list_skills():
    return [
        {
            "skill_id": s.skill_id,
            "category": str(s.category),
            "title": s.title,
            "difficulty": str(s.difficulty),
            "prerequisites": s.prerequisites,
            "related_findings": s.related_findings,
        }
        for s in skill_graph.topological_order()
    ]


@router.get("/skills/{skill_id}")
async def get_skill(skill_id: str):
    skill = skill_graph.get(skill_id)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")
    return skill.model_dump(mode="json")


@router.get("/investigations/{investigation_id}/skills")
async def get_investigation_skills(investigation_id: str):
    async with get_db() as db:
        inv_svc = InvestigationService(db)
        inv = await inv_svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        finding_types = await inv_svc._finding_types_for_investigation(inv)

        mastery_list = await MasteryTracker(db).get_mastery(investigation_id)
        mastery_by_skill = {m.skill_id: m for m in mastery_list}
        recommendations = _recommender.recommend(
            finding_types, mastery_by_skill=mastery_by_skill
        )
    return [
        {
            "skill_id": r.skill.skill_id,
            "title": r.skill.title,
            "difficulty": str(r.skill.difficulty),
            "category": str(r.skill.category),
            "is_available": r.is_available,
            "is_in_progress": r.is_in_progress,
            "is_completed": r.is_completed,
            "is_mastered": r.is_mastered,
            "confidence_score": r.confidence_score,
            "matched_finding_types": r.matched_finding_types,
        }
        for r in recommendations
    ]


@router.post("/investigations/{investigation_id}/skills/sync")
async def sync_skills(investigation_id: str):
    """Trigger a mastery sync for the investigation."""
    async with get_db() as db:
        inv_svc = InvestigationService(db)
        inv = await inv_svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")

        finding_types = await inv_svc._finding_types_for_investigation(inv)
        lr_repo = LearningProgressRepository(db)
        all_progress = await lr_repo.list_for_investigation(investigation_id)
        completed_paths = [
            p.path_id for p in all_progress if str(p.status) == "completed"
        ]
        artifact_repo = ArtifactRepository(db)
        artifacts = await artifact_repo.list_for_investigation(investigation_id)
        artifact_types = [str(a.artifact_type) for a in artifacts]

        approval_svc = ApprovalService(db)
        approvals = await approval_svc.list_approvals(investigation_id)
        completed_actions = [
            a.action_id
            for a in approvals
            if a.status == ApprovalStatus.COMPLETED
        ]

        tracker = MasteryTracker(db)
        mastery = await tracker.sync_investigation(
            investigation_id,
            finding_types,
            artifact_types,
            completed_paths,
            completed_actions,
        )
    return {"synced": len(mastery)}


@router.post("/investigations/{investigation_id}/skills/{skill_id}/validate")
async def validate_skill(investigation_id: str, skill_id: str):
    """Manually mark a skill as mastered (operator/user override)."""
    if not skill_graph.get(skill_id):
        raise HTTPException(status_code=404, detail="Skill not found")
    async with get_db() as db:
        tracker = MasteryTracker(db)
        mastery = await tracker.manual_validate(investigation_id, skill_id)
    return mastery.model_dump(mode="json")


# ── HTMX partial ──────────────────────────────────────────────────────────


@router.get(
    "/investigations/{investigation_id}/skills/partial",
    response_class=HTMLResponse,
)
async def skills_partial(investigation_id: str, request: Request):
    async with get_db() as db:
        inv_svc = InvestigationService(db)
        inv = await inv_svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")

        finding_types = await inv_svc._finding_types_for_investigation(inv)
        lr_repo = LearningProgressRepository(db)
        all_progress = await lr_repo.list_for_investigation(investigation_id)
        completed_paths = [
            p.path_id for p in all_progress if str(p.status) == "completed"
        ]
        artifact_repo = ArtifactRepository(db)
        artifacts = await artifact_repo.list_for_investigation(investigation_id)
        artifact_types = [str(a.artifact_type) for a in artifacts]

        approval_svc = ApprovalService(db)
        approvals = await approval_svc.list_approvals(investigation_id)
        completed_actions = [
            a.action_id
            for a in approvals
            if a.status == ApprovalStatus.COMPLETED
        ]

        tracker = MasteryTracker(db)
        mastery_list = await tracker.sync_investigation(
            investigation_id,
            finding_types,
            artifact_types,
            completed_paths,
            completed_actions,
        )
        mastery_by_skill = {m.skill_id: m for m in mastery_list}
        recommendations = _recommender.recommend(
            finding_types, mastery_by_skill=mastery_by_skill
        )
        next_skill = _recommender.next_skill(
            finding_types, mastery_by_skill=mastery_by_skill
        )

    return templates.TemplateResponse(
        "partials/skill_progression_panel.html",
        {
            "request": request,
            "investigation": inv,
            "recommendations": recommendations,
            "next_skill": next_skill,
            "mastery_by_skill": mastery_by_skill,
            "mastery_status_labels": MASTERY_STATUS_LABELS,
        },
    )
