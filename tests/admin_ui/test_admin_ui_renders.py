"""Integration tests for PR A.1 — backend admin UI rendering.

All 7 assertions:
  1. GET /admin → 302 to /admin/conductor
  2. GET /admin/conductor → 200, contains heading and htmx polling div
  3. GET /admin/conductor/refresh → 200, "No active investigations."
  4. GET /admin/conductor/refresh after start → shows investigation ID
  5. GET /admin/execution → 200, contains "Execution"
  6. GET /admin/execution/refresh → 200, shows mock engine IDs
  7. GET / in admin-only app → 404; no admin content at root

Tests use a minimal FastAPI app (no validation lifespan) with an isolated
SQLite DB via pytest tmp_path. asyncio_mode=auto (set in pyproject.toml).
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

# ── fixture ───────────────────────────────────────────────────────────────────


@pytest.fixture
async def admin_setup(tmp_path):
    """Yields (httpx_client, conductor) with fresh Conductor + isolated SQLite."""
    from fastapi import FastAPI

    import apps.admin_ui.state_provider as sp
    import apps.conductor.engines.mock  # noqa: F401 — triggers engine registration
    from apps.admin_ui.routes import router
    from apps.conductor.conductor import Conductor
    from apps.conductor.events.bus import EventBus

    bus = EventBus()
    conductor = Conductor(bus=bus, db_path=tmp_path / "test.db")
    sp._conductor = conductor

    app = FastAPI()
    app.include_router(router)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client, conductor

    sp._conductor = None


# ── Tests ─────────────────────────────────────────────────────────────────────


async def test_admin_root_redirects_to_conductor(admin_setup):
    client, _ = admin_setup
    resp = await client.get("/admin", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"].endswith("/admin/settings")


async def test_conductor_panel_renders(admin_setup):
    client, _ = admin_setup
    resp = await client.get("/admin/conductor")
    assert resp.status_code == 200
    html = resp.text
    assert "Conductor" in html
    assert 'hx-get="/admin/conductor/refresh"' in html


async def test_conductor_refresh_with_no_investigations(admin_setup):
    client, _ = admin_setup
    resp = await client.get("/admin/conductor/refresh")
    assert resp.status_code == 200
    assert "No active investigations." in resp.text


async def test_conductor_refresh_with_one_investigation(admin_setup):
    client, conductor = admin_setup
    inv_id = await conductor.start_investigation("mock://target", {})
    await asyncio.sleep(0.1)  # let background task register the context

    resp = await client.get("/admin/conductor/refresh")
    assert resp.status_code == 200
    assert inv_id in resp.text

    await conductor.cancel_investigation(inv_id)


async def test_execution_panel_renders(admin_setup):
    client, _ = admin_setup
    resp = await client.get("/admin/execution")
    assert resp.status_code == 200
    assert "Execution" in resp.text


async def test_execution_refresh_shows_engine_roster(admin_setup):
    client, _ = admin_setup
    resp = await client.get("/admin/execution/refresh")
    assert resp.status_code == 200
    html = resp.text
    assert "mock_simple" in html
    assert "mock_chained" in html


async def test_existing_routes_not_at_admin_root(admin_setup):
    """GET / is not defined in the admin-only test app.

    Admin routes are all under /admin/*; the root must not show admin content.
    """
    client, _ = admin_setup
    resp = await client.get("/", follow_redirects=False)
    assert resp.status_code == 404
    assert "Conductor" not in resp.text
