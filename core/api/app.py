"""
FastAPI application factory.

PROTECTED FILE — read CLAUDE.md before modifying.

Changes from base:
- Added validation module router
- Added admin UI router
- Added static file serving
- Added frontend index redirect
- Added DB init to lifespan
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from apps.admin_ui.routes import router as admin_router
from apps.validation.api import validation_router
from apps.validation.database import init_db
from core.api.health import router as health_router
from core.config.settings import get_settings
from core.logging.setup import configure_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    await init_db()
    # Part 1 — Zombie-branch recovery: any branch left 'running'/'armed' in the DB
    # at startup has no live backing task and must be terminated immediately.
    try:
        from apps.conductor.exploitation.zombie_recovery import recover_zombie_branches
        await recover_zombie_branches()
    except Exception:
        pass
    # Part 1b — Zombie-scan recovery: any scan_execution left 'running' in the DB
    # at startup (e.g. passive_probe interrupted mid-run) is definitively orphaned.
    try:
        from apps.conductor.exploitation.zombie_recovery import recover_zombie_scans
        await recover_zombie_scans()
    except Exception:
        pass
    # Part 1c — Autonomous-status recovery: any investigation state blob with
    # autonomous_status='running' in the DB at startup has no live backing task.
    try:
        from apps.conductor.exploitation.zombie_recovery import recover_zombie_autonomous_status
        await recover_zombie_autonomous_status()
    except Exception:
        pass
    # Part 1d — Orchestration-DB recovery: investigations/phase_state stuck at
    # 'running' states in the separate conductor orchestration.db.
    try:
        from apps.conductor.exploitation.zombie_recovery import recover_zombie_orchestration_status
        await recover_zombie_orchestration_status()
    except Exception:
        pass
    # Rebuild ChromaDB vault index on startup (no-op if vault not mounted or chromadb absent)
    try:
        from apps.conductor.qwen.vault_embedder import rebuild_index
        await rebuild_index()
    except Exception:
        pass
    yield


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        lifespan=lifespan,
    )

    # Health endpoints (bare + prefixed) — do not reorder
    app.include_router(health_router)
    app.include_router(health_router, prefix=settings.api_prefix)

    # Validation module
    app.include_router(validation_router)

    # Admin UI
    app.include_router(admin_router)

    # Static files
    app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

    @app.get("/", include_in_schema=False)
    async def root():
        return RedirectResponse(url="/api/v1/validation/discovery")

    return app
