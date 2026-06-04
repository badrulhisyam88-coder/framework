"""Integration tests — Settings panel at /admin/settings.

Tests 1-5:
  1. GET /admin/settings → 200, contains heading and gate table
  2. GET /admin/settings/refresh → 200, partial fragment with gate rows
  3. POST /admin/settings/nmap_external_scan → toggles gate, returns fragment
  4. POST /admin/settings/<unknown> → 400
  5. Settings nav link present in conductor panel response

Gate state is reset before and after each test.
"""
from __future__ import annotations

import pytest

from apps.conductor.gates import reset_all_gates_to_defaults


@pytest.fixture(autouse=True)
def reset_gates():
    reset_all_gates_to_defaults()
    yield
    reset_all_gates_to_defaults()


@pytest.fixture
async def admin_setup(tmp_path):
    import httpx
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
        yield client

    sp._conductor = None


# ── Test 1: full page renders ────────────────────────────────────────────────


async def test_settings_panel_renders(admin_setup):
    client = admin_setup
    resp = await client.get("/admin/settings")
    assert resp.status_code == 200
    html = resp.text
    assert "Dashboard" in html
    assert "nmap_external_scan" in html
    assert "settings-container" in html


# ── Test 2: refresh returns partial fragment ─────────────────────────────────


async def test_settings_refresh_returns_fragment(admin_setup):
    client = admin_setup
    resp = await client.get("/admin/settings/refresh")
    assert resp.status_code == 200
    html = resp.text
    assert "nmap_external_scan" in html
    assert "Last updated:" in html


# ── Test 3: POST toggles the gate ────────────────────────────────────────────


async def test_toggle_gate_enables_and_reflects_in_response(admin_setup):
    from apps.conductor.gates import get_gate

    client = admin_setup
    assert get_gate("nmap_external_scan") is False

    resp = await client.post("/admin/settings/nmap_external_scan")
    assert resp.status_code == 200
    assert get_gate("nmap_external_scan") is True
    assert "ON" in resp.text

    # Toggle back
    resp2 = await client.post("/admin/settings/nmap_external_scan")
    assert resp2.status_code == 200
    assert get_gate("nmap_external_scan") is False


# ── Test 4: POST unknown gate → 400 ─────────────────────────────────────────


async def test_toggle_unknown_gate_returns_400(admin_setup):
    client = admin_setup
    resp = await client.post("/admin/settings/no_such_gate")
    assert resp.status_code == 400


# ── Test 5: Settings nav link in conductor panel ─────────────────────────────


async def test_settings_nav_link_present(admin_setup):
    client = admin_setup
    resp = await client.get("/admin/conductor")
    assert resp.status_code == 200
    assert 'href="/admin/settings"' in resp.text
