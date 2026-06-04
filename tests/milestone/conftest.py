"""Milestone test configuration — Playwright browser infrastructure.

All tests in tests/milestone/ require Playwright + Chromium + uvicorn.
If any of these are unavailable, every test in this directory is automatically
skipped — no false failures, no error output beyond the skip message.

Per-PR invocation: pytest tests/conductor/ tests/frontend/ ... (omit tests/milestone/)
Milestone invocation: pytest tests/milestone/ -m milestone
"""
from __future__ import annotations

import asyncio
import socket
import threading
import time

import pytest
import pytest_asyncio

# ── Environment probe — runs once at collection time ──────────────────────────


def _probe_playwright_env() -> tuple[bool, str]:
    """Try to launch Chromium headlessly. Return (ok, reason)."""
    try:
        import uvicorn  # noqa: F401 — live server dependency
    except ImportError:
        return False, "uvicorn not installed (available in Docker, not bare env)"

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return False, "playwright Python package not installed"

    async def _launch_probe():
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            await browser.close()

    try:
        asyncio.run(_launch_probe())
        return True, ""
    except Exception as exc:
        return False, f"Chromium launch failed: {str(exc)[:200]}"


_PW_AVAILABLE, _PW_SKIP_REASON = _probe_playwright_env()


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def require_playwright():
    """Skip all milestone tests if Playwright / Chromium / uvicorn are unavailable.

    Used as a dependency by live_server_url and browser_context so the skip
    fires before any server or browser setup is attempted.
    """
    if not _PW_AVAILABLE:
        pytest.skip(f"Playwright environment not available: {_PW_SKIP_REASON}")


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="session")
def live_server_url(tmp_path_factory, require_playwright):
    """Start the minimal admin FastAPI app and return its base URL.

    Uses an isolated SQLite DB. Runs uvicorn in a daemon thread so the test
    process exits cleanly regardless of test outcome. Server ready is confirmed
    by polling the TCP port before yielding.
    """
    import uvicorn

    import apps.admin_ui.state_provider as sp
    import apps.conductor.engines.mock  # noqa: F401 — register mock engines
    # Register all V2.2 exploitation engines so the execution panel roster is complete.
    import apps.conductor.engines.xss_exploit_engine          # noqa: F401
    import apps.conductor.engines.credential_brute_engine     # noqa: F401
    import apps.conductor.engines.cmdi_reflected_engine       # noqa: F401
    import apps.conductor.engines.cmdi_blind_time_engine      # noqa: F401
    import apps.conductor.engines.cmdi_blind_boolean_engine   # noqa: F401
    import apps.conductor.engines.sqli_auth_bypass_engine     # noqa: F401
    import apps.conductor.engines.default_creds_engine        # noqa: F401
    import apps.conductor.engines.access_control_engine       # noqa: F401
    import apps.conductor.engines.metasploit_recipe_engine    # noqa: F401
    from apps.admin_ui.routes import router
    from apps.conductor.conductor import Conductor
    from apps.conductor.events.bus import EventBus
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    tmp_path = tmp_path_factory.mktemp("milestone_db")
    bus = EventBus()
    conductor = Conductor(bus=bus, db_path=tmp_path / "test.db")
    sp._conductor = conductor

    app = FastAPI()
    app.include_router(router)

    # ── Test-only investigation management endpoints ──────────────────────────
    # Not part of the production admin router — used by milestone Playwright
    # tests to start/cancel investigations without needing the workspace routes.

    @app.post("/_test/start-investigation")
    async def _test_start_investigation(body: dict):
        inv_id = await conductor.start_investigation(
            body.get("target", "mock://test"), {}
        )
        return JSONResponse({"investigation_id": inv_id})

    @app.post("/_test/cancel-investigation")
    async def _test_cancel_investigation(body: dict):
        await conductor.cancel_investigation(body["investigation_id"])
        return JSONResponse({"ok": True})

    port = _find_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    if not _wait_for_port("127.0.0.1", port, timeout=10.0):
        pytest.fail("Live server did not start within 10 seconds")

    yield f"http://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=5.0)
    sp._conductor = None


@pytest_asyncio.fixture
async def browser_context(live_server_url):
    """Playwright BrowserContext connected to the live server.

    Function-scoped: each test gets a fresh context (no cookie/storage bleed).
    Yields (context, base_url) so tests can construct full page URLs.
    """
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(base_url=live_server_url)
        try:
            yield context, live_server_url
        finally:
            await context.close()
            await browser.close()
