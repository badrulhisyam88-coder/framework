"""Verification helper — NOT production code.

Phase 56 follow-up: live-browser verification of scenarios 5 (ghost
node lock) and 6 (side-panel button lock) that the Phase 56 PR
verified by code inspection only.

Uses Playwright + headless Chromium. The investigation id and a known
ghost-bearing finding are passed in via env vars (defaults provided
matching the dev environment used during this session).

Run from repo root:
  .venv/bin/python scripts/verify_phase56_browser.py
"""
from __future__ import annotations

import asyncio
import os
import sys

from playwright.async_api import async_playwright


INVESTIGATION_ID = os.environ.get(
    "PHASE56_INV", "c6578a52-85f3-44f3-a2de-4c57ea716216",
)
WORKSPACE_URL = (
    f"http://localhost:8000/api/v1/validation/investigations/workspace"
    f"?target=http://host.docker.internal:10000/"
)
# The investigation workspace URL uses ?target=...; we'll let the
# workspace render and Playwright will navigate to the React Flow canvas.


async def main() -> int:
    results: dict[str, bool] = {}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1600, "height": 1000})
        page    = await context.new_page()

        post_count: dict[str, int] = {}
        executed_urls: list[str] = []

        async def on_request(req):
            if "/suggest/" in req.url and "/execute" in req.url and req.method == "POST":
                executed_urls.append(req.url)
                post_count[req.url] = post_count.get(req.url, 0) + 1

        page.on("request", on_request)

        # Load the workspace
        await page.goto(WORKSPACE_URL, wait_until="networkidle", timeout=15000)

        # Wait for React Flow nodes to render
        try:
            await page.wait_for_selector(".react-flow__node", timeout=10000)
        except Exception as e:
            print(f"FAIL: React Flow canvas didn't render: {e}")
            await browser.close()
            return 1

        # ── Scenario 5 — ghost lock ───────────────────────────────────
        # Find a ghost node (CSS: .inv-node--ghost).
        ghosts = await page.query_selector_all(".react-flow__node .inv-node--ghost")
        print(f"Found {len(ghosts)} ghost nodes on canvas")
        if not ghosts:
            print("FAIL scenario 5: no ghost nodes on the canvas")
            results["5_ghost_present"] = False
        else:
            results["5_ghost_present"] = True
            ghost = ghosts[0]

            # Capture cursor BEFORE click (should be 'pointer').
            cursor_before = await ghost.evaluate(
                "el => getComputedStyle(el).cursor",
            )
            print(f"cursor before click: {cursor_before}")
            results["5_cursor_pointer_before"] = cursor_before == "pointer"

            # First click — should fire ONE POST.
            executed_urls.clear()
            post_count.clear()
            await ghost.click()
            await page.wait_for_timeout(150)  # settle optimistic flip
            posts_after_first = len(executed_urls)
            print(f"POSTs after first click: {posts_after_first}")
            results["5_one_post_first_click"] = posts_after_first == 1

            # Cursor should now be 'wait' (activating state).
            cursor_active = await ghost.evaluate(
                "el => getComputedStyle(el).cursor",
            )
            print(f"cursor during activating: {cursor_active}")
            results["5_cursor_wait_during"] = cursor_active == "wait"

            # Second click while still activating — should NOT fire a POST.
            before_second = len(executed_urls)
            await ghost.click()
            await page.wait_for_timeout(150)
            posts_after_second = len(executed_urls)
            print(f"POSTs after second click (was {before_second}): "
                  f"{posts_after_second}")
            results["5_no_second_post"] = posts_after_second == before_second

        # ── Scenario 6 — side-panel button lock ───────────────────────
        # The structured-evidence panel (with .inv-panel-execute-btn) only
        # opens for outcome nodes that carry structured payload. The XSS
        # probe (Phase 55) is currently the only one that does. Click an
        # outcome node whose label contains "Reflected XSS" to surface it.
        outcomes = await page.query_selector_all(".react-flow__node.react-flow__node-outcome")
        print(f"Found {len(outcomes)} outcome nodes")
        target_outcome = None
        for o in outcomes:
            text = (await o.inner_text()) or ""
            if "Reflected XSS" in text:
                target_outcome = o
                break
        if not target_outcome:
            print("FAIL scenario 6: no Reflected-XSS outcome on canvas — "
                  "trigger the XSS probe to produce one")
            results["6_outcome_present"] = False
        else:
            results["6_outcome_present"] = True
            await target_outcome.click()
            await page.wait_for_timeout(400)
            panel_visible = await page.is_visible("#inv-panel-root:not(.hidden)")
            print(f"Panel visible: {panel_visible}")

            btn = await page.query_selector(".inv-panel-execute-btn")
            if not btn:
                print("INFO: no .inv-panel-execute-btn even after expanding")
                results["6_button_present"] = False
            else:
                results["6_button_present"] = True
                executed_urls.clear()

                disabled_before = await btn.evaluate("el => el.disabled")
                label_before    = await btn.inner_text()
                print(f"Before click: disabled={disabled_before}, "
                      f"label={label_before!r}")

                # First click — one POST + button disables + label swap
                await btn.click()
                await page.wait_for_timeout(200)
                posts_after = len(executed_urls)
                disabled_after = await btn.evaluate("el => el.disabled")
                label_after    = await btn.inner_text()
                print(f"After 1 click: POSTs={posts_after}, "
                      f"disabled={disabled_after}, label={label_after!r}")
                results["6_one_post_first_click"]   = posts_after == 1
                results["6_disabled_during"]        = disabled_after is True
                results["6_label_swapped"]          = "Running" in label_after

                # Spam-click during running — no additional POSTs
                for _ in range(3):
                    try:
                        await btn.click(force=True)
                    except Exception:
                        # disabled btn refuses; force=True bypasses
                        # Playwright's actionability check
                        pass
                    await page.wait_for_timeout(80)
                posts_after_spam = len(executed_urls)
                print(f"After spam: POSTs={posts_after_spam}")
                results["6_no_post_during_running"] = posts_after_spam == posts_after

        await browser.close()

    # Tally
    print()
    print("=" * 50)
    for k, v in results.items():
        print(f"  {k:32} {'PASS' if v else 'FAIL'}")
    overall = all(results.values()) and len(results) >= 5
    print()
    print(f"OVERALL: {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
