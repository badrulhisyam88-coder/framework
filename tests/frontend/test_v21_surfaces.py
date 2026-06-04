"""V2.1 surface backfill — frontend smoke coverage for defects caught manually.

Three tests, one per smoke category. Each is tied to a specific V2.1 defect that
operator-driven live verification caught after the fact; the test docstring records
which defect it would have caught.

Test 1 (Category 1 — HTML): conductor table renders correct current_phase per phase
  state. Catches Pattern 13 failure mode at the rendering layer.

Test 2 (Category 2 — API): /admin/conductor/refresh returns 200 with the expected
  HTML structural elements. Note: this endpoint returns an HTML fragment (htmx
  polling), not JSON — see flag in report.

Test 3 (Category 3 — static asset): csp_xss_reflected is absent from
  exploit-tree.js. Catches incomplete frontend cleanup after atomic engine lifts
  (the V2.2 Step 1 gap that was discovered by the UI investigation).
"""
from __future__ import annotations

import pytest
import pytest_asyncio


# ── Test 1 — HTML: conductor table phase rendering ────────────────────────────


def _make_investigation(state: str, current_phase: str | None) -> dict:
    return {
        "id": "inv_smoke_001",
        "target": "http://smoke.local",
        "state": state,
        "current_phase": current_phase,
        "findings_count": 0,
        "age_seconds": 10,
    }


def _render_conductor_table(investigations: list[dict]) -> object:
    from tests.frontend.html_helpers import render_template_file
    return render_template_file(
        "apps/admin_ui/templates",
        "admin/_conductor_table.html",
        context={
            "investigations": investigations,
            "target_auth": {},
            "expired_targets": [],
            "now_iso": "2026-01-01T00:00:00",
        },
    )


@pytest.mark.parametrize("phase", ["recon", "enumeration", "exploitation"])
def test_conductor_table_renders_active_phase_name(phase):
    """_conductor_table.html renders the correct current_phase text in its cell.

    Defect caught: Pattern 13 (V2.1 Step 3 gap) — the bootstrap returned
    "complete" after enumeration because PhasedRun had no exploitation_run field
    and _current_phase() never returned "exploitation". If the template were reading
    from the wrong field (e.g., stale data), this test would fail even after the
    PhasedRun fix, because the rendered HTML would show the wrong phase name.

    Also covers: any future template refactor that renames the {{ inv.current_phase }}
    binding — the test fails immediately rather than silently showing "—" in the UI.
    """
    from tests.frontend.html_helpers import select, text_of

    soup = _render_conductor_table([_make_investigation("RUNNING", phase)])
    cell_texts = [text_of(c) for c in select(soup, "td")]
    assert phase in cell_texts, (
        f"current_phase='{phase}' not found in rendered table cells. "
        f"Got: {cell_texts}. Check that _conductor_table.html still renders "
        "{{ inv.current_phase or '—' }} in the correct <td>."
    )


def test_conductor_table_renders_dash_when_phase_none():
    """_conductor_table.html renders '—' when current_phase is None.

    Guards against the template silently rendering an empty cell when phase
    state is unavailable — operator sees '—' rather than a blank field.
    """
    from tests.frontend.html_helpers import select, text_of

    soup = _render_conductor_table([_make_investigation("RUNNING", None)])
    cell_texts = [text_of(c) for c in select(soup, "td")]
    assert "—" in cell_texts, (
        f"Expected '—' for None current_phase but got: {cell_texts}"
    )


def test_conductor_table_mark_done_button_present_for_exploit_running():
    """_conductor_table.html renders the 'Mark Done' button when state=EXPLOIT_RUNNING.

    Defect caught: if the template's {% if inv.state == "EXPLOIT_RUNNING" %} guard
    is wrong (e.g., renamed to EXPLOITATION_RUNNING or missing), the operator
    cannot mark exploitation complete — the button silently disappears.
    The button must have hx-post="/admin/exploitation/complete" for the htmx
    wiring to function.
    """
    from tests.frontend.html_helpers import attr, select, text_of

    soup = _render_conductor_table(
        [_make_investigation("EXPLOIT_RUNNING", "exploitation")]
    )
    buttons = select(soup, "button[hx-post]")
    assert len(buttons) == 1, (
        f"Expected 1 'Mark Done' button for EXPLOIT_RUNNING state, got {len(buttons)}. "
        "Check {% if inv.state == 'EXPLOIT_RUNNING' %} in _conductor_table.html."
    )
    assert "Mark Done" in text_of(buttons[0])
    assert attr(buttons[0], "hx-post") == "/admin/exploitation/complete", (
        "Mark Done button hx-post attribute changed — frontend wiring is broken."
    )


def test_conductor_table_no_mark_done_button_for_non_exploit_state():
    """_conductor_table.html does NOT render Mark Done for non-exploitation states.

    Guards against accidentally showing the Mark Done button in recon/enumeration
    phases, which would let the operator close exploitation before it starts.
    """
    from tests.frontend.html_helpers import select

    for state in ("RUNNING", "COMPLETE", "FAILED"):
        soup = _render_conductor_table([_make_investigation(state, "recon")])
        buttons = select(soup, "button[hx-post]")
        assert not buttons, (
            f"'Mark Done' button incorrectly rendered for state={state!r}."
        )


# ── Test 2 — API: /admin/conductor/refresh HTML shape ─────────────────────────
# NOTE: /admin/conductor/refresh returns an HTML fragment (htmx polling endpoint),
# NOT JSON. The Category 2 API helper is used here for structural HTML shape
# assertions rather than JSON field assertions. A true JSON endpoint test
# would target /workspace-data.json — see helper limitations in report.


@pytest_asyncio.fixture
async def admin_client(tmp_path):
    """Async httpx client against a minimal admin app with isolated Conductor."""
    pytest.importorskip("fastapi")

    from tests.frontend.api_helpers import async_client, build_admin_app

    app_bundle = build_admin_app(tmp_path)
    async with async_client(app_bundle) as (client, conductor):
        yield client, conductor


@pytest.mark.asyncio
async def test_conductor_refresh_returns_table_headers(admin_client):
    """GET /admin/conductor/refresh returns 200 with expected table column headers.

    Defect class caught: if a route handler is removed, a template file renamed,
    or a column header renamed (e.g., "Current Phase" → "Phase"), this test fails
    immediately. The frontend polled this endpoint every 2s; any structural
    regression would break the UI silently until operator noticed missing columns.

    Verifies: all six column headers present (Investigation ID, Target, State,
    Current Phase, Findings, Age). Action column omitted — operator-driven,
    appears only for EXPLOIT_RUNNING.
    """
    from tests.frontend.api_helpers import assert_html_200

    client, _ = admin_client
    resp = await client.get("/admin/conductor/refresh")
    assert_html_200(resp)

    for expected_header in ("Investigation ID", "Target", "State", "Current Phase",
                            "Findings", "Age"):
        assert expected_header in resp.text, (
            f"Expected table header {expected_header!r} missing from "
            "/admin/conductor/refresh response. Column renamed or removed?"
        )


@pytest.mark.asyncio
async def test_conductor_refresh_contains_last_updated_marker(admin_client):
    """GET /admin/conductor/refresh always renders the last-updated timestamp.

    The 'last-updated' CSS class on the final <p> tag is what the operator
    uses to verify the UI is live-polling. If the template drops this element
    (e.g., partial template refactor removes the last line), the operator loses
    the staleness indicator silently.
    """
    client, _ = admin_client
    resp = await client.get("/admin/conductor/refresh")
    assert resp.status_code == 200
    assert "last-updated" in resp.text, (
        "class='last-updated' paragraph missing from _conductor_table.html. "
        "Operator loses the live-polling staleness indicator."
    )


# ── Test 3 — Static asset: csp_xss_reflected retired from exploit-tree.js ─────


def test_csp_xss_reflected_absent_from_exploit_tree_js():
    """csp_xss_reflected must not appear in exploit-tree.js.

    Defect caught: V2.2 Step 1 retired csp_xss_reflected as an action_kind by
    lifting probe_xss_reflected into XssReflectedEngine. The catalog entry and
    backend route were cleaned up, but the frontend CRITICAL_KINDS array in
    exploit-tree.js still referenced the identifier. The operator saw the
    category highlighted as critical even though the engine had been retired.
    This cleanup was caught by a UI investigation after the fact.

    This is exactly the class of defect frontend smoke tests exist to catch:
    the backend and seam tests all passed, but the frontend still referenced
    a retired identifier.
    """
    from tests.frontend.asset_helpers import assert_absent

    assert_absent("frontend/static/js/exploit-tree.js", "csp_xss_reflected")


def test_exploit_tree_js_critical_kinds_array_still_present():
    """CRITICAL_KINDS array must still exist in exploit-tree.js.

    Regression guard: confirms the cleanup of csp_xss_reflected did not
    accidentally remove the entire CRITICAL_KINDS declaration. If the array
    were deleted, no action_kinds would ever render as critical — a silent
    regression in the operator UI severity indicators.
    """
    from tests.frontend.asset_helpers import assert_present

    assert_present("frontend/static/js/exploit-tree.js", "CRITICAL_KINDS")
