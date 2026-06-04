"""V2.4 surface checks — setActiveTab fix + finding_type in topology nodes.

Three tests:

Test 1 (Category 3): setActiveTab in workspace.js sets _activeCategorySlug
  so URL-restored and poll-restored tab state propagates to the mindmap
  filter without requiring a physical click.

Test 2 (Category 3): _emit_node in topology_v2.py includes finding_type in
  node data so _build_exploit_tree can derive the correct category_id for
  exploit-tree finding nodes. Previously all nodes got category_id='uncategorized'.

Test 3 (Category 3): _filterTreeByCategory guard — fallback return treeData
  only when NO findings match; a category with matching findings must filter.
"""
from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_WORKSPACE_JS   = _ROOT / "frontend/static/js/workspace.js"
_TOPOLOGY_PY    = _ROOT / "apps/investigation_workspace/branch/topology_v2.py"


# ── Test 1: setActiveTab sets _activeCategorySlug ─────────────────────────────


def test_set_active_tab_propagates_active_category_slug():
    """setActiveTab must assign _activeCategorySlug so URL/poll restore works.

    Defect class caught: without this assignment, navigating back to a tab
    via URL ?tab=<slug> or a poll-cycle re-render left _activeCategorySlug
    empty, so the mindmap showed all categories until the operator clicked
    the tab a second time.
    """
    src = _WORKSPACE_JS.read_text()
    func_start = src.find("function setActiveTab(slug)")
    assert func_start != -1, "setActiveTab function not found in workspace.js"

    # Find the closing brace of setActiveTab
    depth = 0
    func_body_start = src.find("{", func_start)
    func_end = func_body_start
    for i, ch in enumerate(src[func_body_start:], start=func_body_start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                func_end = i
                break
    func_body = src[func_start:func_end + 1]

    assert "_activeCategorySlug" in func_body, (
        "setActiveTab body must assign _activeCategorySlug — "
        "URL-restored tab state would not propagate to mindmap filter without it."
    )
    # The assignment must handle the 'all' chip correctly (reset to empty)
    assert "slug !== 'all'" in func_body or "slug != 'all'" in func_body, (
        "setActiveTab must clear _activeCategorySlug when slug is 'all' "
        "so the mindmap shows every category when the All chip is active."
    )


# ── Test 2: _emit_node writes finding_type into node data ─────────────────────


def test_emit_node_includes_finding_type():
    """_emit_node must include finding_type in node data dict.

    Defect class caught: without finding_type in the emitted node data,
    _build_exploit_tree called d.get('finding_type', '') → '' for every
    finding node, so for_finding_type('') returned 'uncategorized' for all
    exploit-tree findings. Category filter chips ('Authentication', 'SQL
    Injection', etc.) would never match any node.
    """
    src = _TOPOLOGY_PY.read_text()

    func_start = src.find("def _emit_node(node:")
    assert func_start != -1, "_emit_node function not found in topology_v2.py"

    # Grab from function start to the next top-level def
    next_def = src.find("\ndef ", func_start + 1)
    func_body = src[func_start:next_def] if next_def != -1 else src[func_start:]

    assert '"finding_type"' in func_body, (
        '_emit_node must write "finding_type" into node data so that '
        "_build_exploit_tree can derive the correct category_id. "
        "Without it, all exploit-tree finding nodes get category_id='uncategorized'."
    )


# ── Test 3: _filterTreeByCategory no-match fallback is still present ──────────


def test_filter_tree_by_category_fallback_present():
    """_filterTreeByCategory must keep its no-match fallback (return treeData).

    The fallback fires when a category chip is clicked but no finding nodes
    match (e.g. the 'All' chip, or a chip for a category with no exploitable
    findings). It must not silently blank the mindmap.
    """
    src = _WORKSPACE_JS.read_text()
    func_start = src.find("function _filterTreeByCategory(")
    assert func_start != -1, "_filterTreeByCategory not found in workspace.js"

    next_func = src.find("\n  function ", func_start + 1)
    func_body = src[func_start:next_func] if next_func != -1 else src[func_start:]

    assert "return treeData" in func_body, (
        "_filterTreeByCategory must return the original treeData when no "
        "findings match the selected category — blanking the mindmap would "
        "be worse than showing all nodes."
    )
