"""
FastAPI application factory.

PROTECTED FILE — read CLAUDE.md before modifying.

Changes from base:
- Added validation module router
- Added static file serving
- Added frontend index redirect
- Added DB init to lifespan
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

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

    # Static files
    app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

    @app.get("/", include_in_schema=False)
    async def root():
        return RedirectResponse(url="/api/v1/validation/discovery")

    return app
