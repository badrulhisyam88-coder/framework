"""Pattern 19 — Panel Data Source Seam.

Seam invariant: the exploitation mindmap panel reads branch state ONLY from
exploitation-data.json (cached in-memory after polling). It must not make a
secondary server fetch (e.g., to context-panel) to display branch details.

Defect class: if a developer adds a fetch() call inside the panel rendering
function (e.g., to fetch richer artifact data from a new endpoint), the panel
silently stops working in the "no network" or "stale-token" case and the
operator loses the artifact view exactly when exploitation has succeeded.

These are static source checks — no runtime or browser needed. Pass on host.
"""
from __future__ import annotations

import pathlib
import re

_ROOT = pathlib.Path(__file__).parents[3]
_MINDMAP = _ROOT / "frontend/static/js/exploitation-mindmap.js"


def _src() -> str:
    return _MINDMAP.read_text(encoding="utf-8")


# ── P19-A ─────────────────────────────────────────────────────────────────────


def test_p19a_mindmap_polls_exploitation_data_endpoint():
    """exploitation-mindmap.js must reference the /exploitation-data.json URL.

    Defect class caught: if the polling URL is accidentally changed or removed,
    the mindmap silently stops receiving branch updates after page load.
    """
    src = _src()
    assert "exploitation-data.json" in src, (
        "exploitation-data.json URL not found in exploitation-mindmap.js. "
        "The mindmap must poll this endpoint for branch state (Pattern 19)."
    )


# ── P19-B ─────────────────────────────────────────────────────────────────────


def test_p19b_panel_does_not_call_context_panel_endpoint():
    """Panel rendering must not fetch from the context-panel endpoint.

    Defect class caught: context-panel is the old capture-bundle server
    endpoint. Panel rendering for the exploitation mindmap must use cached
    branch data from exploitation-data.json, not issue a new server request.
    Adding a context-panel fetch violates Pattern 19 and breaks offline
    artifact inspection.
    """
    src = _src()
    assert "context-panel" not in src, (
        "'context-panel' found in exploitation-mindmap.js. "
        "Mindmap panel must read from cached _branchMap only (Pattern 19). "
        "Remove any fetch to context-panel."
    )


# ── P19-C ─────────────────────────────────────────────────────────────────────


def test_p19c_panel_open_function_uses_cached_branch_data():
    """Panel open functions (_panelForAction/Progress/Result) exist and use _branch data.

    Defect class caught: if a refactor renames _branch to a different attribute
    or reads from a separate fetch, the panel silently renders empty fields.
    """
    src = _src()
    assert "_panelForAction" in src, "_panelForAction function missing from exploitation-mindmap.js"
    assert "_panelForProgress" in src, "_panelForProgress function missing"
    assert "_panelForResult" in src, "_panelForResult function missing"
    # All three panel functions receive branch state from data._branch (no extra fetch)
    assert "d._branch" in src or "data._branch" in src, (
        "Panel functions must access ._branch from node data (Pattern 19). "
        "No secondary fetch for branch details."
    )


# ── P19-D ─────────────────────────────────────────────────────────────────────


def test_p19d_only_exploitation_data_is_fetched():
    """The only fetch() call URL in exploitation-mindmap.js must be exploitation-data.json.

    Defect class caught: adding a fetch() call for workspace-data.json creates
    two competing sources of truth for branch state and makes the panel
    non-deterministic. Tree data is passed in via the mount/refresh API.
    """
    src = _src()
    # Count occurrences of exploitation-data.json (the canonical branch source)
    assert src.count("exploitation-data.json") >= 1, "exploitation-data.json URL missing"
    # workspace-data.json must not be fetched — it's passed in via mount/refresh
    # Check that no fetch( call contains workspace-data.json
    import re
    fetch_urls = re.findall(r"fetch\s*\(\s*['\"]([^'\"]+)['\"]", src)
    for url in fetch_urls:
        assert "workspace-data.json" not in url, (
            "exploitation-mindmap.js fetches workspace-data.json directly at URL: "
            + url + ". Tree data must be passed in via mountExploitationMindmap (Pattern 19)."
        )


# ── P19-E ─────────────────────────────────────────────────────────────────────


def test_p19e_template_references_mindmap_not_old_exploit_tree():
    """investigation_workspace.html must load exploitation-mindmap.js, not exploit-tree.js.

    Defect class caught: if the script tag is accidentally reverted to
    exploit-tree.js during a merge, the three-level mindmap stops loading and
    the operator sees only the old single-layer tree (no branch state).
    """
    template = (_ROOT / "frontend/templates/investigation_workspace.html").read_text(encoding="utf-8")
    assert "exploitation-mindmap.js" in template, (
        "investigation_workspace.html does not load exploitation-mindmap.js. "
        "V2.3 Step 4 requires this script to be present."
    )
    assert "exploit-tree.js" not in template, (
        "exploit-tree.js still referenced in investigation_workspace.html. "
        "It was replaced by exploitation-mindmap.js in V2.3 Step 4."
    )
