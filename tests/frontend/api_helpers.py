"""Category 2 — JSON endpoint shape assertions.

Helpers for calling API endpoints against a minimal FastAPI test app with
mock investigation state, returning structured responses for assertion.

Requires FastAPI and httpx (present in Docker; absent in bare test env).
Tests using these helpers must call pytest.importorskip("fastapi") or be
placed in a file that skips at collection time when fastapi is absent.

Async helpers follow the same httpx.AsyncClient + ASGI transport pattern
established in tests/admin_ui/test_admin_ui_renders.py. Requires
pytest-asyncio with asyncio_mode="strict" and @pytest.mark.asyncio.

Typical use:
    import pytest
    import pytest_asyncio
    pytest.importorskip("fastapi")

    from tests.frontend.api_helpers import build_admin_app, async_client

    @pytest_asyncio.fixture
    async def client(tmp_path):
        async with async_client(build_admin_app(tmp_path)) as c:
            yield c

    @pytest.mark.asyncio
    async def test_refresh_returns_200(client):
        resp = await client.get("/admin/conductor/refresh")
        assert resp.status_code == 200
        assert_json_shape(resp.json(), ["investigations"])  # if JSON
"""
from __future__ import annotations

import contextlib
from typing import Any


def build_admin_app(tmp_path, *, register_mock_engines: bool = True):
    """Build a minimal FastAPI app with the admin UI router and an isolated Conductor.

    Returns a (FastAPI app, Conductor) tuple. The Conductor uses an isolated
    SQLite DB at tmp_path so tests do not share state.
    """
    from fastapi import FastAPI

    import apps.admin_ui.state_provider as sp
    from apps.admin_ui.routes import router
    from apps.conductor.conductor import Conductor
    from apps.conductor.events.bus import EventBus

    if register_mock_engines:
        import apps.conductor.engines.mock  # noqa: F401 — triggers registration

    bus = EventBus()
    conductor = Conductor(bus=bus, db_path=tmp_path / "test.db")
    sp._conductor = conductor

    app = FastAPI()
    app.include_router(router)
    return app, conductor


@contextlib.asynccontextmanager
async def async_client(app_and_conductor):
    """Async context manager yielding an httpx.AsyncClient bound to the given ASGI app.

    Usage:
        app, conductor = build_admin_app(tmp_path)
        async with async_client((app, conductor)) as (client, conductor):
            resp = await client.get("/admin/conductor/refresh")
    """
    import apps.admin_ui.state_provider as sp
    import httpx

    app, conductor = app_and_conductor
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            yield client, conductor
    finally:
        sp._conductor = None


def assert_json_shape(data: dict[str, Any], required_keys: list[str]) -> None:
    """Assert that all required_keys are present in the JSON response dict."""
    missing = [k for k in required_keys if k not in data]
    assert not missing, (
        f"JSON response missing required keys: {missing}. Got keys: {list(data.keys())}"
    )


def assert_html_200(response, *, contains: str | None = None) -> None:
    """Assert response is 200 and optionally that text appears in the body."""
    assert response.status_code == 200, (
        f"Expected 200, got {response.status_code}. Body: {response.text[:300]}"
    )
    if contains is not None:
        assert contains in response.text, (
            f"Expected {contains!r} in response body. Got: {response.text[:500]}"
        )
