from fastapi import APIRouter

from apps.investigation_core.api import router as investigation_core_router
from apps.investigation_workspace.api.routes import router as workspace_router
from apps.scanner_orchestration.api.routes import router as scanner_router
from apps.validation.api import (
    assets,
    changes,
    custom_report,
    discovery,
    findings,
    history,
    investigations,
    known_issues,
    metasploit,
    queue,
    reports,
    settings_router,
)

validation_router = APIRouter(prefix="/api/v1/validation", tags=["validation"])
validation_router.include_router(investigation_core_router)
validation_router.include_router(workspace_router)
validation_router.include_router(scanner_router)
validation_router.include_router(investigations.router)
validation_router.include_router(discovery.router)
validation_router.include_router(custom_report.router)
validation_router.include_router(assets.router)
validation_router.include_router(queue.router)
validation_router.include_router(findings.router)
validation_router.include_router(changes.router)
validation_router.include_router(history.router)
validation_router.include_router(settings_router.router)
validation_router.include_router(known_issues.router)
validation_router.include_router(reports.router)
validation_router.include_router(metasploit.router)
