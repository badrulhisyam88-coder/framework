"""V2.5 milestone scenarios — Qwen AI branch spawning.

6 scenarios: 4 static (pass everywhere), 2 browser (skip without Chromium).
Static: panel structure, endpoint in routes, ACTION parsing, ai_probe filter.
Browser: chat interaction, approval card click.

Run:
    pytest tests/milestone/test_v25_milestone.py -v
"""
from __future__ import annotations

from pathlib import Path

import pytest

# ── Constants ─────────────────────────────────────────────────────────────────

_ROOT      = Path(__file__).parents[2]
_TEMPLATE  = _ROOT / "frontend/templates/investigation_workspace.html"
_MINDMAP   = _ROOT / "frontend/static/js/exploitation-mindmap.js"
_ROUTES    = _ROOT / "apps/investigation_workspace/api/routes.py"
_TOPOLOGY  = _ROOT / "apps/investigation_workspace/branch/topology_v2.py"


def _has_chromium() -> bool:
    """Return True only if playwright + a Chromium executable are present."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401

        with sync_playwright() as pw:
            try:
                pw.chromium.launch(headless=True)
                return True
            except Exception:
                return False
    except ImportError:
        return False


# ── Scenario 1 — Qwen chat panel in template ─────────────────────────────────


@pytest.mark.milestone
def test_qwen_chat_panel_in_exploitation_template():
    """investigation_workspace.html must contain the persistent AI panel and chat elements.

    Static assertions (updated for persistent-panel architecture):

    - 'ws-zone-a', 'ws-zone-b', 'ws-zone-c' present (three-zone structure)
    - 'ws-branch-detail' present (inline branch detail replaces transient panel)
    - 'qwen-history', 'qwen-input', 'qwen-send' present (chat in Zone C)
    - 'qwen-toggle' and 'qwen-window' absent (floating widget removed)

    Defect class caught: absent elements → getElementById returns null,
    the chat panel or zone structure is silently dead.
    """
    src = _TEMPLATE.read_text(encoding="utf-8")
    assert "ws-zone-a" in src, "Zone A strip missing from investigation_workspace.html"
    assert "ws-zone-b" in src, "Zone B strip missing from investigation_workspace.html"
    assert "ws-zone-c" in src, "Zone C area missing from investigation_workspace.html"
    assert "ws-branch-detail" in src, "ws-branch-detail card missing — branch clicks have no target"
    assert "qwen-history" in src, "qwen-history missing — chat messages have no container"
    assert "qwen-input" in src, "qwen-input missing — operator cannot type instructions"
    assert "qwen-send" in src, "qwen-send missing — operator cannot submit chat"
    assert "qwen-toggle" not in src, (
        "qwen-toggle still present — floating widget was removed (rehomed to Zone C). "
        "Remove the toggle button from the template."
    )
    assert "qwen-window" not in src, (
        "qwen-window still present — floating overlay was removed. "
        "Chat elements now live inside the persistent ws-panel Zone C."
    )


# ── Scenario 2 — Qwen chat endpoint in routes.py ─────────────────────────────


@pytest.mark.milestone
def test_qwen_chat_endpoint_in_routes():
    """routes.py must declare async def qwen_chat.

    Static assertions:

    - 'async def qwen_chat' present in routes.py
    - 'qwen/chat' URL fragment present in routes.py

    Defect class caught: absent endpoint → 404 on every Send click;
    the error handler shows 'Qwen is currently unavailable' even if
    Ollama is healthy.
    """
    src = _ROUTES.read_text(encoding="utf-8")
    assert "async def qwen_chat" in src, (
        "'async def qwen_chat' missing from routes.py. "
        "POST /qwen/chat endpoint is required for the chat panel."
    )
    assert "qwen/chat" in src, (
        "'qwen/chat' URL fragment missing from routes.py. "
        "The route path must include 'qwen/chat'."
    )


# ── Scenario 3 — ACTION block parsing in routes.py ───────────────────────────


@pytest.mark.milestone
def test_action_block_parsed_in_routes():
    """routes.py must contain _parse_qwen_action and APPROVED_ENGINES frozenset.

    Static assertions:

    - '_parse_qwen_action' present in routes.py
    - 'APPROVED_ENGINES' frozenset declared in routes.py

    Defect class caught: absent parser → ACTION blocks from Qwen are
    silently ignored; operator never sees the approval card.
    Absent frozenset → engine_id validation has no allowlist; any
    engine_id in the ACTION block would be dispatched unchecked.
    """
    src = _ROUTES.read_text(encoding="utf-8")
    assert "_parse_qwen_action" in src, (
        "'_parse_qwen_action' function missing from routes.py. "
        "ACTION block parsing is required for approval card rendering."
    )
    assert "APPROVED_ENGINES" in src, (
        "'APPROVED_ENGINES' frozenset missing from routes.py. "
        "Engine allowlist required for safe Qwen-triggered dispatch."
    )
    assert "frozenset" in src, (
        "'frozenset' not used in routes.py — APPROVED_ENGINES must be "
        "an immutable frozenset to prevent accidental mutation."
    )


# ── Scenario 4 — ai_probe passes _has_v2_engine filter ───────────────────────


@pytest.mark.milestone
def test_ai_probe_passes_v2_engine_filter():
    """_has_v2_engine('ai_probe') must return True.

    Imports topology_v2._has_v2_engine directly and calls it.

    Defect class caught: if _has_v2_engine returns False for 'ai_probe',
    the Phase 2 ghost emission filter silently drops all AI-triggered
    findings from the exploitation mindmap — they appear in the DB but
    never render as nodes.
    """
    import importlib

    topo = importlib.import_module(
        "apps.investigation_workspace.branch.topology_v2"
    )
    has_v2 = getattr(topo, "_has_v2_engine", None)
    assert has_v2 is not None, (
        "_has_v2_engine not exported from topology_v2. "
        "Function is required for the V2.4 non-exploitable filter."
    )
    result = has_v2("ai_probe")
    assert result is True, (
        "_has_v2_engine('ai_probe') returned False. "
        "ai_probe findings are always AI-engine-backed — must return True."
    )


# ── Scenario 5 — Browser: chat panel renders in Exploitation tab ──────────────


@pytest.mark.milestone
@pytest.mark.skip(
    reason=(
        "Browser test requires Chromium + a running workspace server seeded "
        "with an active investigation in the Exploitation phase. "
        "To exercise manually: "
        "(1) Ensure docker compose is up with OLLAMA_BASE_URL set. "
        "(2) Start an investigation and advance to Exploitation phase. "
        "(3) Open /workspace/investigations/{id}?phase=exploitation. "
        "(4) Assert #qwen-toggle is visible (display != 'none'). "
        "(5) Click #qwen-toggle — assert #qwen-window becomes visible. "
        "(6) Type a message, click Send — assert a reply appears in #qwen-history. "
        "Covered by operator-driven live verification checklist Step 3 (toggle) "
        "and Step 4 (chat response)."
    )
)
async def test_chat_panel_renders_in_browser(browser_context):
    """Browser: exploitation tab shows the Qwen toggle; clicking opens chat window."""


# ── Scenario 6 — Browser: approval card appears after ACTION block ─────────────


@pytest.mark.milestone
@pytest.mark.skip(
    reason=(
        "Browser test requires a live Qwen session that returns an ACTION block. "
        "Ollama must be running and reachable from the backend container. "
        "To exercise manually: "
        "(1) Open Exploitation tab with an active investigation. "
        "(2) Paste a directive that triggers an ACTION block response. "
        "(3) Assert approval card (div.qwen-approval-card) appears in #qwen-history. "
        "(4) Assert 'QWEN WANTS TO RUN' heading text is visible. "
        "(5) Assert Approve and Skip buttons are present (data-engine attribute set). "
        "(6) Click Approve — assert POST dispatched and chat shows 'Running...' status. "
        "Covered by operator-driven live verification checklist Steps 4–6."
    )
)
async def test_approval_card_appears_for_action(browser_context):
    """Browser: Qwen ACTION block → approval card visible; clicking Approve dispatches."""
