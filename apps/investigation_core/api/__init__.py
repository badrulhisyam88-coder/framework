from fastapi import APIRouter

from apps.investigation_core.api.campaign_routes import router as _campaign_router
from apps.investigation_core.api.evidence_routes import router as _evidence_router
from apps.investigation_core.api.export_routes import router as _export_router
from apps.investigation_core.api.guided_action_routes import router as _guided_router
from apps.investigation_core.api.routes import router as _core_router
from apps.investigation_core.api.skill_routes import router as _skill_router

# Single combined router — all routes under /investigation-core prefix.
router = APIRouter(prefix="/investigation-core")
router.include_router(_core_router)
router.include_router(_evidence_router)
router.include_router(_guided_router)
router.include_router(_skill_router)
router.include_router(_export_router)
router.include_router(_campaign_router)

__all__ = ["router"]
