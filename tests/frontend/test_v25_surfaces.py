"""V2.5 Step 3 surface checks — AI chat panel structure.

Tests updated to reflect the persistent right-panel architecture (floating widget removed).

Test 1 (Category 3): persistent panel elements present in investigation_workspace.html.
Test 2 (Category 3): chat elements (qwen-history, qwen-input, qwen-send) inside ws-panel.
  The floating qwen-toggle / qwen-window are intentionally absent (replaced by Zone C).
"""
from __future__ import annotations

from pathlib import Path

_ROOT     = Path(__file__).resolve().parents[2]
_TEMPLATE = _ROOT / "frontend/templates/investigation_workspace.html"
_MINDMAP  = _ROOT / "frontend/static/js/exploitation-mindmap.js"


# ── Test 1: persistent panel elements in template ───────────────────────────


def test_qwen_chat_panel_container_in_template():
    """investigation_workspace.html must contain the persistent AI panel and chat elements.

    Defect class caught: if any element is absent the chat is silently dead —
    getElementById returns null and no events are wired.
    """
    from tests.frontend.asset_helpers import assert_present
    assert_present("frontend/templates/investigation_workspace.html", "ws-zone-a")
    assert_present("frontend/templates/investigation_workspace.html", "ws-zone-b")
    assert_present("frontend/templates/investigation_workspace.html", "ws-zone-c")
    assert_present("frontend/templates/investigation_workspace.html", "ws-branch-detail")
    assert_present("frontend/templates/investigation_workspace.html", "qwen-history")
    assert_present("frontend/templates/investigation_workspace.html", "qwen-input")
    assert_present("frontend/templates/investigation_workspace.html", "qwen-send")


# ── Test 2: chat elements inside persistent panel (not floating widget) ──────


def test_qwen_chat_panel_only_in_exploitation_pane():
    """Chat elements (qwen-history/input/send) must be inside #ws-panel, not floating.

    The floating qwen-toggle / qwen-window were removed when the chat was rehomed
    into the persistent right panel (Zone C). This test ensures the floating widget
    is gone and the chat elements live inside the persistent aside#ws-panel.
    """
    src = _TEMPLATE.read_text(encoding="utf-8")

    ws_panel_start = src.find('id="ws-panel"')
    assert ws_panel_start != -1, "#ws-panel aside not found in template"

    # Panel must NOT be hidden by default
    panel_tag = src[ws_panel_start:ws_panel_start + 200]
    assert 'class="hidden' not in panel_tag and '"hidden ' not in panel_tag, (
        "#ws-panel must not start with class containing 'hidden' — panel is persistent"
    )

    # Floating widget elements must be gone
    assert 'id="qwen-toggle"' not in src, (
        "qwen-toggle button still present — floating widget was removed in favour of "
        "persistent Zone C panel. Remove the toggle button from the template."
    )
    assert 'id="qwen-window"' not in src, (
        "qwen-window div still present — floating widget was removed. "
        "The chat elements now live inside the persistent #ws-panel Zone C."
    )

    # Chat elements must appear after #ws-panel (inside it)
    history_pos = src.find('id="qwen-history"')
    input_pos   = src.find('id="qwen-input"')
    send_pos    = src.find('id="qwen-send"')
    assert history_pos > ws_panel_start, "qwen-history must be inside #ws-panel"
    assert input_pos   > ws_panel_start, "qwen-input must be inside #ws-panel"
    assert send_pos    > ws_panel_start, "qwen-send must be inside #ws-panel"


# ── Test 3: chat JS wired into exploitation-mindmap.js ───────────────────────


def test_qwen_chat_js_in_mindmap():
    """exploitation-mindmap.js must contain the _chatSend function and _chatHistory var.

    Defect class caught: if the chat JS is accidentally left in a separate file
    or missing entirely, the Send button has no event listener and is silently dead.
    """
    from tests.frontend.asset_helpers import assert_present
    assert_present(
        "frontend/static/js/exploitation-mindmap.js",
        "_chatSend",
    )
    assert_present(
        "frontend/static/js/exploitation-mindmap.js",
        "_chatHistory",
    )
    assert_present(
        "frontend/static/js/exploitation-mindmap.js",
        "qwen/chat",
    )


# ── Test 4: backend route present in routes.py ───────────────────────────────


def test_qwen_chat_endpoint_in_routes():
    """routes.py must declare the POST /qwen/chat endpoint.

    Defect class caught: if the endpoint is absent the Send button gets a 404
    and the error branch fires, showing 'Qwen is currently unavailable' even
    when Ollama is running fine.
    """
    from tests.frontend.asset_helpers import assert_present
    assert_present(
        "apps/investigation_workspace/api/routes.py",
        "qwen/chat",
    )
    assert_present(
        "apps/investigation_workspace/api/routes.py",
        "async def qwen_chat",
    )


# ── V2.5 Step 4 surface checks ────────────────────────────────────────────────


def test_approval_card_rendered_for_action():
    """exploitation-mindmap.js must contain _chatRenderApproval function.

    Defect class caught: if _chatRenderApproval is absent the ACTION block from
    Qwen is silently ignored — the operator never sees the approval card and
    cannot dispatch engines via the chat panel.
    """
    src = _MINDMAP.read_text()
    assert '_chatRenderApproval' in src, "_chatRenderApproval function missing from exploitation-mindmap.js"
    assert 'qwen-approve-btn' in src, "qwen-approve-btn class missing — approval button not rendered"
    assert ('QWEN WANTS TO RUN' in src or 'AI WANTS TO RUN' in src), \
        "approval card header text missing from exploitation-mindmap.js"


def test_approve_btn_has_data_attributes():
    """Approve button must set data-engine and data-finding-type.

    Defect class caught: if either data attribute is missing the click handler
    cannot determine which engine to dispatch, causing a silent no-op.
    """
    src = _MINDMAP.read_text()
    assert 'data-engine=' in src, "data-engine attribute missing from approve button"
    assert 'data-finding-type=' in src, "data-finding-type attribute missing from approve button"


# ── V2.6 Step 1 — ai_probe label check ───────────────────────────────────────


def test_ai_probe_label_uses_finding_title():
    """ai_probe action node in _build_exploit_tree synthesis uses finding title, not raw engine_id.

    The synthesis block that emits finding + action nodes for ai_probe branches
    must set label = fdata.get("title") or fallback, not the plain engine_id string.

    Defect class caught: if the action node label is set to engine_id directly,
    the mindmap shows internal engine names ('access_control') instead of the
    human-readable Qwen-authored title ('Qwen: Mass assignment via /api/checkout').
    """
    from pathlib import Path

    routes_src = (
        Path(__file__).resolve().parents[2]
        / "apps/investigation_workspace/api/routes.py"
    ).read_text(encoding="utf-8")

    synth_marker = "Synthesize finding + action nodes for ai_probe"
    synth_start = routes_src.find(synth_marker)
    assert synth_start != -1, (
        f"Synthesis block comment '{synth_marker}' not found in routes.py. "
        "The ai_probe synthesis block must be present."
    )

    # Inspect the synthesis block (up to 1500 chars from the marker)
    synth_block = routes_src[synth_start : synth_start + 1500]

    # Both the finding node and action node must derive label from fdata.get("title")
    has_title_lookup = (
        'fdata.get("title")' in synth_block
        or "fdata.get('title')" in synth_block
    )
    assert has_title_lookup, (
        "synthesis block does not use fdata.get(\"title\") for the node label. "
        "Both finding and action nodes must use the finding title as the label. "
        f"Block content:\n{synth_block[:500]}"
    )


# ── Chat-dispatch unification tests ──────────────────────────────────────────

def test_chat_approve_uses_seed_autonomous_not_execute_suggestion():
    """Approve button handler must call _seedAutonomous, not fetch execute_suggestion.

    Regression guard: before this fix the Approve button fired a POST to
    /finding/{id}/suggest/{engine}/execute. That path dispatches via
    execute_suggestion which:
    (a) requires an active conductor context (raises 409 when context absent), and
    (b) may write the branch under the wrong investigation_id if the context was
        created for a different investigation — making the branch invisible to the
        mindmap's exploitation-data.json polling.

    After the fix: Approve calls _seedAutonomous (same path as Execute/AI Continue),
    which goes through autonomous/seed → autonomous orchestrator → creates the branch
    under the correct investigation_id → mindmap renders it live.
    """
    src = _MINDMAP.read_text()
    # Must use _seedAutonomous in the approve handler region
    approve_region_start = src.find("approveBtn.addEventListener('click'")
    assert approve_region_start != -1, "Approve click handler not found"
    # Wide window: comprehensive allSelections building added ~1100 chars before _seedAutonomous
    approve_region = src[approve_region_start : approve_region_start + 3000]
    assert '_seedAutonomous' in approve_region, (
        "Approve click handler must call _seedAutonomous. "
        "Found handler region:\n" + approve_region[:600]
    )
    # Must NOT call execute_suggestion from the approve handler
    assert 'suggest/' not in approve_region, (
        "Approve handler must not use the execute_suggestion URL path (/suggest/.../execute). "
        "That path creates branches under the wrong investigation_id. "
        "Use _seedAutonomous instead."
    )


def test_chat_pending_watch_set_on_approve():
    """Approve handler must set _chatPendingWatch to track the dispatched branch.

    Defect class caught: without _chatPendingWatch, _pollBranches cannot post
    the terminal result back to the chat (operator sees 'Starting...' forever).
    """
    src = _MINDMAP.read_text()
    assert '_chatPendingWatch' in src, "_chatPendingWatch variable missing from mindmap JS"
    # Set in the approve handler
    approve_start = src.find("approveBtn.addEventListener('click'")
    approve_region = src[approve_start : approve_start + 1500]
    assert '_chatPendingWatch' in approve_region, (
        "_chatPendingWatch must be set inside the Approve click handler"
    )
    # Checked in _pollBranches
    poll_start = src.find('function _pollBranches()')
    assert poll_start != -1, "_pollBranches function not found"
    poll_region = src[poll_start : poll_start + 3000]
    assert '_chatPendingWatch' in poll_region, (
        "_chatPendingWatch terminal-state check must be inside _pollBranches"
    )


def test_approved_engines_includes_username_enum_and_js_spider():
    """_APPROVED_ENGINES in routes.py must include username_enum and js_spider.

    Defect class caught: if an engine is absent from _APPROVED_ENGINES, Qwen's
    ACTION block with that engine_id parses as null — the approval card is never
    shown and the operator cannot run the AI-recommended engine via chat.
    """
    from pathlib import Path
    routes_src = (
        Path(__file__).resolve().parents[2]
        / "apps/investigation_workspace/api/routes.py"
    ).read_text(encoding="utf-8")

    approved_start = routes_src.find("_APPROVED_ENGINES = frozenset({")
    assert approved_start != -1, "_APPROVED_ENGINES not found in routes.py"
    approved_block = routes_src[approved_start : approved_start + 400]

    for engine in ("username_enum", "js_spider", "xss_reflected"):
        assert engine in approved_block, (
            f"'{engine}' must be in _APPROVED_ENGINES so Qwen can recommend it via ACTION block. "
            f"Block: {approved_block}"
        )


# ── Layout regression guard ───────────────────────────────────────────────────

def test_autonomous_progress_slot_in_template():
    """Template must have #autonomous-progress-slot for bounded progress trail injection.

    Regression guard: before this fix, _seedAutonomous used insertAdjacentHTML('afterend')
    on #exploit-tree-root, making the progress div a flex sibling of the mindmap.
    In the flex-col layout the mindmap (flex-1 with min-height:0) shrank — and React Flow,
    sensitive to container-height changes, would show a blank canvas.

    Fix: a dedicated slot with position:absolute at the pane bottom.
    The mindmap height never changes regardless of progress div content.
    """
    from pathlib import Path
    template = (
        Path(__file__).resolve().parents[2]
        / "frontend/templates/investigation_workspace.html"
    ).read_text(encoding="utf-8")
    assert "autonomous-progress-slot" in template, (
        "#autonomous-progress-slot must be in the template — without it, "
        "_seedAutonomous falls back to inserting as a flex sibling of the mindmap, "
        "which collapses the mindmap canvas."
    )
    # Must be absolutely positioned so it does not displace the mindmap
    slot_start = template.find("autonomous-progress-slot")
    slot_block = template[max(0, slot_start - 20) : slot_start + 300]
    assert "position:absolute" in slot_block or "position: absolute" in slot_block, (
        "#autonomous-progress-slot must have position:absolute so the mindmap "
        "height is never changed by the progress trail content. "
        f"Found: {slot_block!r}"
    )


def test_seed_autonomous_injects_into_slot_not_after_mindmap():
    """_seedAutonomous must inject the progress div into #autonomous-progress-slot.

    Regression guard: the old code used insertAdjacentHTML('afterend', ...) on
    #exploit-tree-root which displaced the mindmap in the flex layout.
    The new code uses slot.innerHTML = html (inject into the bounded slot).
    """
    src = _MINDMAP.read_text()
    # Must reference the slot
    assert "autonomous-progress-slot" in src, (
        "_seedAutonomous must reference #autonomous-progress-slot for injection"
    )
    # Injection region: the else branch of the progDiv check
    else_inject_start = src.find("slot.innerHTML = html")
    assert else_inject_start != -1, (
        "Injection into slot.innerHTML must be present in _seedAutonomous"
    )
    # The old afterend injection must be a FALLBACK only (not the primary path)
    afterend_idx = src.find("insertAdjacentHTML('afterend'")
    assert afterend_idx != -1, "afterend fallback should still exist for old templates"
    # Verify afterend is inside the fallback block (after the slot check)
    slot_check_idx = src.find("autonomous-progress-slot")
    assert slot_check_idx < afterend_idx, (
        "insertAdjacentHTML afterend must come AFTER the slot check (fallback only), "
        "not as the primary injection path"
    )


# ── AI Continue vs Execute path unification ───────────────────────────────────

def test_ai_continue_button_removed():
    """ActionNode must NOT have an 'AI Continue →' button.

    Regression guard: the per-node AI Continue button was removed because it was
    redundant with the chat-driven orchestrated loop and a recurring source of
    dispatch/timeout bugs. The chat path is the intended trigger for the full loop.
    Execute → remains for single-shot deterministic dispatch.
    """
    src = _MINDMAP.read_text()
    # var aiContinueBtn must no longer exist in the file
    assert "var aiContinueBtn" not in src, (
        "'var aiContinueBtn' must not appear — the button was removed. "
        "Use chat for the AI-driven loop; Execute → for single-shot dispatch."
    )
    # 'AI Continue →' label must not appear in the ActionNode component
    action_node_start = src.find("function ActionNode(props)")
    assert action_node_start != -1
    action_node_region = src[action_node_start : action_node_start + 4000]
    assert "'AI Continue →'" not in action_node_region, (
        "The 'AI Continue →' label must not appear in ActionNode — button was removed."
    )


def test_ai_continue_chat_path_intact():
    """Chat-approve (_chatRenderApproval) must still call _seedAutonomous.

    Removing the node button must NOT affect the chat dispatch path.
    The chat Approve button → _seedAutonomous → /autonomous/seed → full orchestration.
    """
    src = _MINDMAP.read_text()
    # Chat path must still use _seedAutonomous
    approve_region_start = src.find("approveBtn.addEventListener('click'")
    assert approve_region_start != -1, "Chat Approve click handler not found"
    # Wide window: allSelections building added before _seedAutonomous call
    approve_region = src[approve_region_start : approve_region_start + 3000]
    assert '_seedAutonomous' in approve_region, (
        "Chat Approve handler must still call _seedAutonomous after node button removal"
    )


def test_execute_uses_execute_suggestion_not_seed():
    """Execute → must call execute_suggestion (single-shot), not _seedAutonomous.

    Regression guard: if Execute were changed to call _seedAutonomous, it would
    run the full orchestrated loop instead of a single deterministic branch.
    """
    src = _MINDMAP.read_text()
    # Find the Execute button region: search for the onClick that uses execute_url
    exec_region_start = src.find("'Execute →'")
    assert exec_region_start != -1, "Execute → button text not found"
    # The onClick handler is before the label text — look back 900 chars
    exec_btn_region = src[max(0, exec_region_start - 900) : exec_region_start + 100]

    # Execute must use execute_url (single-shot dispatch)
    assert "execute_url" in exec_btn_region, (
        "Execute → must use d.execute_url (execute_suggestion single-shot dispatch)"
    )
    # Execute must NOT call _seedAutonomous
    assert "_seedAutonomous" not in exec_btn_region, (
        "Execute → must NOT call _seedAutonomous — it must remain single-shot"
    )


# ── Action-node layout size guard ─────────────────────────────────────────────

def test_action_node_height_fits_two_controls_not_three():
    """ACTION_H must be at the compact 2-control height (Execute + Select), not the
    old 3-control height that included the removed AI Continue button.

    Before: ACTION_H = 165  (reserved space for Execute + AI Continue + Select)
    After:  ACTION_H = 128  (fits title(2-line) + sub_label + Execute + Select + gaps + padding)

    If ACTION_H is still 165 (or larger), every action node has ~37px of dead space
    at the bottom where the removed button used to be.
    """
    src = _MINDMAP.read_text()
    import re
    m = re.search(r'var ACTION_H\s*=\s*(\d+)', src)
    assert m is not None, "ACTION_H constant not found in exploitation-mindmap.js"
    action_h = int(m.group(1))
    assert action_h <= 140, (
        f"ACTION_H = {action_h} is too large — still reserving space for the removed "
        f"AI Continue button. Expected ≤ 140 (fits title + sub_label + Execute + Select). "
        f"Old value was 165 (3 controls); compact value with 2 controls is ~128."
    )
    assert action_h >= 110, (
        f"ACTION_H = {action_h} is too small — 2-line titles or Execute/Select will clip. "
        f"Minimum with 2-line title + 2 controls + padding is ~110px."
    )


# ── Regression guard: mindmap canvas not destroyed on run-start ───────────────

def test_exploit_tree_not_destroyed_when_topology_empty_and_already_mounted():
    """workspace.js _mountOrRefreshExploitTree must NOT destroy the React root when
    the topology is transiently empty and the tree is already mounted.

    Regression guard for the recurring "canvas disappears on run-start" bug:
      1. Run starts → inv-topology-refresh fires
      2. workspace.js fetches workspace-data.json during a race window
      3. exploit_tree.nodes = [] (topology not yet updated)
      4. OLD code: root.innerHTML = '...' unconditionally → destroys React root
      5. NEW code: only shows placeholder when _exploitTreeMounted is false

    Cite: workspace.js _mountOrRefreshExploitTree, the !_exploitTreeMounted guard
    added before root.innerHTML so that a mounted canvas is never destroyed by an
    empty-topology response.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parents[2] / "frontend/static/js/workspace.js").read_text()

    fn_start = src.find("function _mountOrRefreshExploitTree(")
    assert fn_start != -1, "_mountOrRefreshExploitTree not found in workspace.js"
    fn_body = src[fn_start : fn_start + 1200]

    # The guard must check _exploitTreeMounted BEFORE setting root.innerHTML
    mounted_check_idx = fn_body.find("!_exploitTreeMounted")
    inner_html_idx    = fn_body.find("root.innerHTML =")

    assert mounted_check_idx != -1, (
        "_exploitTreeMounted check missing from the empty-nodes branch of "
        "_mountOrRefreshExploitTree. Without this guard, an empty topology response "
        "during a run destroys the React root and blanks the canvas."
    )
    assert inner_html_idx != -1, "root.innerHTML = assignment not found"
    assert mounted_check_idx < inner_html_idx, (
        "The _exploitTreeMounted check must appear BEFORE root.innerHTML so that "
        "a mounted canvas is never destroyed by an empty-topology fetch (race condition "
        "on run-start triggers inv-topology-refresh → empty nodes → canvas blank)."
    )


def test_exploit_tree_not_destroyed_docstring_present():
    """The fix must include an inline comment explaining WHY the guard exists,
    so future developers don't remove it as 'dead code'."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[2] / "frontend/static/js/workspace.js").read_text()

    fn_start = src.find("function _mountOrRefreshExploitTree(")
    fn_body = src[fn_start : fn_start + 1200]

    assert "canvas" in fn_body.lower() or "run-start" in fn_body or "race" in fn_body.lower(), (
        "The empty-nodes guard in _mountOrRefreshExploitTree must have an inline "
        "comment explaining the run-start race condition, so it is not removed."
    )
