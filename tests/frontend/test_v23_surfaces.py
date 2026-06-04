"""V2.3 surface checks — /exploitation-data.json endpoint + mindmap smoke coverage.

Eight tests across two categories:

Test 1 (Category 3): exploitation-data.json route handler present in routes.py.
Test 2 (Category 2): GET exploitation-data.json returns 200 + empty shape for empty inv.
Test 3 (Category 2): GET exploitation-data.json returns branch fields when seeded.
Test 4 (Category 3): exploitation-mindmap.js present in static/js/.
Test 5 (Category 3): investigation_workspace.html references exploitation-mindmap.js.
Test 6 (Category 3): exploitation-mindmap.js exposes mount/refresh API globals.
Test 7 (Category 3): exploitation-mindmap.js uses RF.ReactFlow as primary accessor (R2 fix).
Test 8 (Category 3): _pollBranches() fires before root.render() in mount path (R3 fix).

Tests 2-3 require fastapi + aiosqlite (Docker). Tests 1, 4-8 run everywhere.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio


# ── Test 1 — Category 3: route handler present in routes.py ──────────────────


def test_exploitation_data_endpoint_present_in_routes():
    """exploitation_data_json handler must exist in routes.py.

    Defect class caught: if the endpoint is accidentally dropped during a
    routes.py refactor or merge, the three-level mindmap (V2.3 Step 4)
    loses its data source silently. This static check fails immediately.
    """
    from tests.frontend.asset_helpers import assert_present
    assert_present(
        "apps/investigation_workspace/api/routes.py",
        "exploitation-data.json",
    )
    assert_present(
        "apps/investigation_workspace/api/routes.py",
        "async def exploitation_data_json",
    )


# ── Tests 2–3 — Category 2: JSON endpoint shape assertions ───────────────────


def _make_branch_record(
    branch_id: str = "exb_smoke001",
    investigation_id: str = "inv_smoke",
    finding_id: str = "fnd_001",
    engine_id: str = "credential_brute",
    technique_class: str = "brute_force.credentials",
    state: str = "succeeded",
    operator_params: dict | None = None,
    artifact: dict | None = None,
    exhaustion_record: dict | None = None,
    stage_log: list | None = None,
    created_at: str = "2026-05-27T10:00:00+00:00",
    updated_at: str = "2026-05-27T10:00:42+00:00",
):
    """Build a BranchRecord-like object (duck-typed for the route handler)."""
    from dataclasses import dataclass

    @dataclass
    class _R:
        branch_id: str
        investigation_id: str
        finding_id: str
        engine_id: str
        technique_class: str
        state: str
        operator_params: dict
        artifact: dict | None
        exhaustion_record: dict | None
        stage_log: list
        created_at: str
        updated_at: str

    return _R(
        branch_id=branch_id,
        investigation_id=investigation_id,
        finding_id=finding_id,
        engine_id=engine_id,
        technique_class=technique_class,
        state=state,
        operator_params=operator_params or {},
        artifact=artifact,
        exhaustion_record=exhaustion_record,
        stage_log=stage_log or [],
        created_at=created_at,
        updated_at=updated_at,
    )


@pytest_asyncio.fixture
async def workspace_client(tmp_path):
    """Minimal FastAPI app with workspace router; BranchReader mocked (no real DB).

    Skips on host when fastapi or aiosqlite is absent.
    """
    pytest.importorskip("aiosqlite")
    pytest.importorskip("fastapi")

    import httpx
    from fastapi import FastAPI

    from apps.investigation_workspace.api.routes import router

    app = FastAPI()
    app.include_router(router)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_exploitation_data_empty_investigation_returns_200(workspace_client):
    """GET exploitation-data.json for an investigation with no branches → 200 + empty dict.

    Defect class caught: if the endpoint raises on an empty result (e.g.,
    returns 404 or throws an unhandled exception when list_for_investigation
    returns []), the mindmap cannot render the "no engines have run" state.

    This is the expected behaviour before any exploitation engine has executed.
    """
    mock_reader = AsyncMock()
    mock_reader.list_for_investigation.return_value = []

    with patch(
        "apps.conductor.exploitation.branch_store.BranchReader",
        return_value=mock_reader,
    ):
        resp = await workspace_client.get(
            "/workspace/investigations/inv_smoke_empty/exploitation-data.json"
        )

    assert resp.status_code == 200, (
        f"Expected 200, got {resp.status_code}. "
        "exploitation-data.json must return 200 even when branches is empty."
    )
    data = resp.json()
    assert "investigation_id" in data, "Response missing 'investigation_id' key"
    assert "branches" in data, "Response missing 'branches' key"
    assert data["investigation_id"] == "inv_smoke_empty"
    assert data["branches"] == {}, (
        f"Expected empty branches dict, got {data['branches']!r}. "
        "Endpoint must return empty dict (not 404, not null) before engines run."
    )


@pytest.mark.asyncio
async def test_exploitation_data_returns_branch_fields(workspace_client):
    """GET exploitation-data.json returns all required branch fields keyed by branch_id.

    Defect class caught: if a field is dropped from the serialisation (e.g.,
    artifact or exhaustion_record serialised as str instead of dict), the
    right-side panel (V2.3 Step 4) renders incorrect or missing data.
    """
    record = _make_branch_record(
        branch_id="exb_smoke001",
        investigation_id="inv_smoke_seeded",
        state="succeeded",
        artifact={"artifact_type": "captured_session", "username": "wiener"},
        stage_log=[
            {"state": "pending", "at": "2026-05-27T10:00:00+00:00"},
            {"state": "succeeded", "at": "2026-05-27T10:00:42+00:00"},
        ],
    )

    mock_reader = AsyncMock()
    mock_reader.list_for_investigation.return_value = [record]

    with patch(
        "apps.conductor.exploitation.branch_store.BranchReader",
        return_value=mock_reader,
    ):
        resp = await workspace_client.get(
            "/workspace/investigations/inv_smoke_seeded/exploitation-data.json"
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["investigation_id"] == "inv_smoke_seeded"
    assert "exb_smoke001" in data["branches"], (
        "Branch keyed by branch_id not found in response. "
        f"branches keys: {list(data['branches'].keys())}"
    )
    branch = data["branches"]["exb_smoke001"]

    _required_fields = (
        "branch_id", "finding_id", "engine_id", "technique_class",
        "state", "operator_params", "artifact", "exhaustion_record",
        "stage_log", "created_at", "updated_at",
    )
    missing = [f for f in _required_fields if f not in branch]
    assert not missing, (
        f"Branch response missing required fields: {missing}. "
        "All fields from D2 operator decision must be present."
    )

    assert branch["state"] == "succeeded"
    assert branch["artifact"]["artifact_type"] == "captured_session"
    assert branch["exhaustion_record"] is None
    assert len(branch["stage_log"]) == 2
    mock_reader.list_for_investigation.assert_called_once_with("inv_smoke_seeded")


# ── Tests 4–6 — Category 3: V2.3 Step 4 static asset checks ─────────────────


def test_exploitation_mindmap_js_present():
    """exploitation-mindmap.js must exist as a static asset.

    Defect class caught: if the file is accidentally deleted or not created,
    investigation_workspace.html will load a 404 script and the mindmap will
    silently fail to mount.
    """
    from tests.frontend.asset_helpers import assert_present
    assert_present(
        "frontend/static/js/exploitation-mindmap.js",
        "mountExploitationMindmap",
    )


def test_template_references_exploitation_mindmap_not_old_tree():
    """investigation_workspace.html must reference exploitation-mindmap.js, not exploit-tree.js.

    Defect class caught: if a merge reverts the script tag to exploit-tree.js,
    the three-level mindmap never loads and the operator sees only the old
    single-layer tree (no branch state, no panel).
    """
    from tests.frontend.asset_helpers import assert_present, assert_absent
    assert_present(
        "frontend/templates/investigation_workspace.html",
        "exploitation-mindmap.js",
    )
    assert_absent(
        "frontend/templates/investigation_workspace.html",
        "exploit-tree.js",
    )


def test_exploitation_mindmap_exposes_global_api():
    """exploitation-mindmap.js must expose both window.mountExploitationMindmap
    and window.refreshExploitationMindmap so workspace.js can call them.

    Defect class caught: if either global is missing, workspace.js falls through
    silently and the mindmap container renders empty even when data is available.
    """
    from tests.frontend.asset_helpers import assert_present
    assert_present(
        "frontend/static/js/exploitation-mindmap.js",
        "window.mountExploitationMindmap",
    )
    assert_present(
        "frontend/static/js/exploitation-mindmap.js",
        "window.refreshExploitationMindmap",
    )


# ── Tests 7–8 — Category 3: V2.3 regression fix checks ──────────────────────


def test_exploitation_mindmap_uses_rf_reactflow_accessor():
    """exploitation-mindmap.js must use RF.ReactFlow as the primary React Flow
    component accessor (named UMD export), not RF.default alone.

    Defect class caught: React Flow's UMD bundle exposes the component as
    RF.ReactFlow (named export); RF.default is undefined. Using only RF.default
    causes React.createElement(undefined) — the canvas renders nothing and all
    onNodeClick handlers are unreachable. The fix uses the fallback chain
    RF.ReactFlow || RF.default || RF; this test verifies RF.ReactFlow is present
    as the primary accessor. (R2 regression fix.)
    """
    from tests.frontend.asset_helpers import assert_present
    assert_present(
        "frontend/static/js/exploitation-mindmap.js",
        "RF.ReactFlow",
    )


def test_exploitation_mindmap_polls_before_initial_render():
    """_pollBranches() must be called before root.render() in mountExploitationMindmap.

    Defect class caught: if _pollBranches() fires after the initial render,
    the first paint uses an empty _branchMap, showing stale 'Execute →' buttons
    for all previously-executed engines until the first poll returns (~400-1100ms).
    Moving the poll before render starts the fetch while React initialises,
    eliminating the visible first-paint race window. (R3 regression fix.)

    Uses the function definition marker (not the JSDoc comment) so the search
    section starts at the actual function body, avoiding false matches from
    entry.root.render() in the _render() helper defined earlier in the file.
    """
    from pathlib import Path
    src = (Path(__file__).parent.parent.parent /
           "frontend/static/js/exploitation-mindmap.js").read_text()
    # Start at the function definition, not the JSDoc comment reference above it
    mount_start = src.index("window.mountExploitationMindmap = function")
    mount_section = src[mount_start:]
    poll_pos   = mount_section.index("_pollBranches()")
    # Use \n    root.render( to distinguish from entry.root.render( in _render()
    render_pos = mount_section.index("\n    root.render(")
    assert poll_pos < render_pos, (
        "_pollBranches() must appear before root.render() in mountExploitationMindmap. "
        f"Found poll at offset {poll_pos}, render at offset {render_pos}."
    )


# ── Tests 9–12 — Category 3: V2.3 consolidated regression fix checks ─────────


def test_template_has_ws_exploitation_initial_data_tag():
    """investigation_workspace.html must contain id="ws-exploitation-initial-data" script tag.

    Defect class caught: if the pre-seed tag is absent, mountExploitationMindmap
    cannot synchronously hydrate _branchMap before _buildGraph(), and the first
    paint always shows empty L2/L3 nodes for investigations with existing branches
    (async-race regression). (R3-Bug1 consolidated fix.)
    """
    from tests.frontend.asset_helpers import assert_present
    assert_present(
        "frontend/templates/investigation_workspace.html",
        'id="ws-exploitation-initial-data"',
    )


def test_exploitation_mindmap_preseed_before_build_graph():
    """exploitation-mindmap.js must read ws-exploitation-initial-data before
    _buildGraph(treeData) in the mountExploitationMindmap function body.

    Defect class caught: if the getElementById lookup appears after _buildGraph(),
    the graph is built from an empty _branchMap and the pre-seed has no effect —
    all L2/L3 nodes are absent from the first paint regardless. (R3-Bug1 fix.)
    """
    from pathlib import Path
    src = (Path(__file__).parent.parent.parent /
           "frontend/static/js/exploitation-mindmap.js").read_text()
    mount_start = src.index("window.mountExploitationMindmap = function")
    mount_section = src[mount_start:]
    preseed_pos = mount_section.index("getElementById('ws-exploitation-initial-data')")
    build_pos   = mount_section.index("_buildGraph(treeData)")
    assert preseed_pos < build_pos, (
        "getElementById('ws-exploitation-initial-data') must appear before "
        f"_buildGraph(treeData) in mountExploitationMindmap. "
        f"Found preseed at offset {preseed_pos}, _buildGraph at offset {build_pos}."
    )


def test_template_does_not_load_dagre_from_cdn():
    """investigation_workspace.html must NOT load dagre from cdn.jsdelivr.net/npm/dagre.

    Defect class caught: CDN-loaded dagre silently falls back to a 4-column grid
    layout when the CDN is unreachable in the lab environment — the mindmap
    renders but loses the hierarchical LR tree layout (R1 symptom). Vendoring
    dagre locally eliminates the CDN dependency. (Dagre CDN risk fix.)

    Note: Preact CDN references (cdn.jsdelivr.net/npm/preact) are intentional and
    not in scope for this check.
    """
    from tests.frontend.asset_helpers import assert_absent
    assert_absent(
        "frontend/templates/investigation_workspace.html",
        "cdn.jsdelivr.net/npm/dagre",
    )


def test_exploitation_mindmap_no_silent_bare_catch():
    """exploitation-mindmap.js must not contain an empty .catch(function () {})
    that silently swallows Execute errors without operator feedback.

    Defect class caught: if the Execute fetch rejects (network error, 500, CSRF
    mismatch) and the catch is empty, the operator sees no error signal and
    retries believing the action succeeded. The fix renders 'Execute failed —
    retry' below the button. (Silent Execute catch fix.)
    """
    from tests.frontend.asset_helpers import assert_absent
    assert_absent(
        "frontend/static/js/exploitation-mindmap.js",
        ".catch(function () {})",
    )


# ── Tests 13–14 — resp.ok guard + _kickPoll order (ghost execute fix) ─────────


def test_execute_fetch_checks_resp_ok_before_set_local_exec():
    """exploitation-mindmap.js Execute .then() must check resp.ok before calling
    setLocalExec(true).

    Defect (now fixed): .then(function () { setLocalExec(true); ... }) fires on
    ANY HTTP response including 4xx/5xx. When the backend returns 409 (conductor
    context absent after server restart), the badge shows '✓ Executed' but no
    branch is written to DB. On hard refresh, Execute → reappears (state loss).

    Fix: .then(function (resp) { if (!resp.ok) { setExecError(...); return; }
         setLocalExec(true); ... })

    This test verifies the fix is in place for the non-critical Execute → path.
    It also covers the critical (armed/confirm) path.
    """
    from pathlib import Path
    src = (Path(__file__).parent.parent.parent /
           "frontend/static/js/exploitation-mindmap.js").read_text()

    assert "function (resp)" in src, (
        "Execute .then() callback must accept a resp parameter. "
        "Found .then(function () — no parameter means resp.ok cannot be checked. "
        "Ghost execute: 409 triggers setLocalExec(true) with no branch written."
    )
    assert "resp.ok" in src, (
        "resp.ok check not found in exploitation-mindmap.js. "
        "The .then() handler must check resp.ok before setLocalExec(true)."
    )

    # Verify resp.ok check appears BEFORE setLocalExec(true) — not after
    ok_pos   = src.index("resp.ok")
    exec_pos = src.index("setLocalExec(true)")
    assert ok_pos < exec_pos, (
        f"resp.ok (offset {ok_pos}) must appear before setLocalExec(true) "
        f"(offset {exec_pos}). If resp.ok check is after setLocalExec, the "
        "badge shows even on error responses."
    )


def test_kick_poll_called_after_resp_ok_confirmed():
    """exploitation-mindmap.js must call _kickPoll() AFTER the resp.ok guard,
    not before it.

    After a confirmed successful execute, _kickPoll() triggers a branch state
    poll. As soon as the engine writes a branch to DB, the next poll updates
    _branchMap and the DB-backed '✓ Done'/'No finding' badge replaces the
    volatile '✓ Executed' badge — so state persists even if the operator
    refreshes before the next scheduled poll.

    Defect class caught: if _kickPoll() is moved before the resp.ok check,
    a 409 response triggers a poll (which returns empty branches) before the
    error is shown, causing a confusing UI flash.

    Verification: in the non-critical path, resp.ok guard comes before
    setLocalExec(true) which comes before _kickPoll(). All three must be
    in this order.
    """
    from pathlib import Path
    src = (Path(__file__).parent.parent.parent /
           "frontend/static/js/exploitation-mindmap.js").read_text()

    assert "_kickPoll()" in src, "_kickPoll() not found in exploitation-mindmap.js."
    assert "resp.ok" in src, "resp.ok not found — prerequisite for this test."
    assert "setLocalExec(true)" in src

    # Find the non-critical Execute path section: starts after the 'else {' that
    # follows the isCritical block. Use the non-critical fetch URL (no ?confirm=)
    # as the anchor. Locate the first fetch call that does NOT have ?confirm= in it.
    non_crit_fetch = src.index(
        "fetch(d.execute_url, {\n                method: 'POST'"
    )
    section = src[non_crit_fetch:non_crit_fetch + 600]

    ok_pos   = section.index("resp.ok")
    exec_pos = section.index("setLocalExec(true)")
    poll_pos = section.index("_kickPoll()")

    assert ok_pos < exec_pos < poll_pos, (
        f"Order wrong in non-critical Execute path. "
        f"resp.ok at {ok_pos}, setLocalExec at {exec_pos}, _kickPoll at {poll_pos}. "
        "Required order: resp.ok check → setLocalExec(true) → _kickPoll()."
    )
