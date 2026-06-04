"""Milestone harness sanity test.

Single scenario that confirms the Playwright harness infrastructure works:
live server starts, browser navigates, JS executes, structural assertion passes.

This is NOT a coverage scenario. It does not test any V2.1/V2.2 surface.
It only proves the harness substrate is functional before real milestone
scenarios are added at V2.2 closeout.

Run:
    pytest tests/milestone/ -m milestone -v

Skips cleanly when Playwright/Chromium/uvicorn are unavailable (bare test env).
"""
from __future__ import annotations

import pytest


@pytest.mark.milestone
@pytest.mark.asyncio
async def test_harness_loads_admin_conductor_panel(browser_context):
    """Harness sanity: browser navigates to /admin/conductor and the page renders.

    Assertions:
    - HTTP 200 (page loaded — no 500 or redirect loop)
    - <h1>Conductor</h1> heading is present in the DOM (template rendered)
    - htmx polling div is present (client-side JS attributes preserved)
    - 'No active investigations.' row is visible (empty-state rendering correct)

    This is the minimum smoke proof that:
    1. The live server starts and serves the admin routes
    2. Playwright navigates and receives rendered HTML
    3. DOM structure is accessible via page.query_selector
    4. The conductor partial renders with correct empty state
    """
    from tests.milestone.pages.admin_page import AdminConductorPage

    context, base_url = browser_context
    admin = await AdminConductorPage.open(context, base_url)

    try:
        # Heading present — template rendered at all
        heading = await admin.heading_text()
        assert heading == "Conductor", (
            f"Expected h1='Conductor', got {heading!r}. "
            "Template failed to render or route is broken."
        )

        # Empty state — no investigations, correct fallback row
        page = admin._page
        body_text = await page.text_content("body") or ""
        assert "No active investigations." in body_text, (
            "Expected 'No active investigations.' in rendered page. "
            "Empty-state row missing from conductor table."
        )

        # htmx attributes preserved — JS runtime can wire up polling
        hx_div = await page.query_selector("[hx-get='/admin/conductor/refresh']")
        assert hx_div is not None, (
            "htmx polling div [hx-get='/admin/conductor/refresh'] not found. "
            "The htmx trigger for the conductor table is missing — "
            "live polling will not function."
        )

        # Last-updated marker — staleness indicator
        last_updated = await page.query_selector(".last-updated")
        assert last_updated is not None, (
            ".last-updated element not found in conductor table. "
            "Operator loses the live-polling staleness indicator."
        )
    finally:
        await admin.close()
