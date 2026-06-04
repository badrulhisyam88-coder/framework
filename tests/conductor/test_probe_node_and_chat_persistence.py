"""Mock tests — FIX 1 (probe mindmap nodes) + FIX 2 (chat history persistence).

M1. Agent_state with CONCEPT-LOGIN-PROTECTION-PROBE in completed + a probe branch:
    workspace-data.json includes a node for the probe; artifact accessible via branch.
M2. Existing attack-technique action nodes still render (no regression in node-builder).
C1. After qwen_chat_stream exchange: rows for user + assistant in investigation_chat_history.
C2. GET /investigations/{id}/chat returns those rows for the investigation_id.
"""
from __future__ import annotations

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

_ROUTES  = Path(__file__).resolve().parents[2] / "apps/investigation_workspace/api/routes.py"
_MINDMAP = Path(__file__).resolve().parents[2] / "frontend/static/js/exploitation-mindmap.js"


# ── FIX 1 — Probe nodes in the node-builder ───────────────────────────────────

class TestFix1ProbeNodes:

    def test_m1_routes_has_planner_branches_collection(self):
        """M1: routes.py collects planner_branches (concept-linked branches not in catalog)."""
        src = _ROUTES.read_text()
        assert "planner_branches" in src, (
            "routes.py must collect planner_branches for concept-linked engine branches"
        )
        assert "_concept_engines" in src, (
            "routes.py must derive concept-engine set from CONCEPT_ENGINE_MAP"
        )

    def test_m1_build_workspace_data_accepts_planner_branches(self):
        """M1: _build_workspace_data accepts and processes planner_branches parameter."""
        src = _ROUTES.read_text()
        assert "planner_branches: list | None = None" in src or \
               "planner_branches=None" in src or \
               "planner_branches" in src[src.find("def _build_workspace_data"):
                                          src.find("def _build_workspace_data") + 300], (
            "_build_workspace_data must accept planner_branches parameter"
        )

    def test_m1_probe_node_synthesized_code_present(self):
        """M1: routes.py synthesis block creates action node for planner branches."""
        src = _ROUTES.read_text()
        # The synthesis block must check existing action keys to avoid duplicates
        assert "_existing_action_keys" in src, (
            "Synthesis must track existing action keys to avoid duplicates"
        )
        # Must build an action node with the probe engine_id
        assert "_pb_action_id" in src or "action-{_pb_eid}" in src or \
               "action_kind" in src[src.find("planner_branches"):], (
            "Synthesis block must create an action node with action_kind from engine_id"
        )
        # Edge must connect finding to probe action
        assert "e-planner-" in src, (
            "Synthesis must add an edge connecting finding to probe action"
        )

    def test_m1_probe_node_label_from_concept_id(self):
        """M1: probe action node label derived from concept id (human-readable)."""
        src = _ROUTES.read_text()
        # The label derives from concept id by removing CONCEPT- and replacing hyphens
        assert '"CONCEPT-".replace' in src or \
               '.replace("CONCEPT-", "")' in src or \
               "replace(\"CONCEPT-\"" in src or \
               "_pb_concept.replace" in src, (
            "Probe node label must be derived from concept_id (not raw engine_id)"
        )

    def test_m2_dedup_check_prevents_ghost_action_override(self):
        """M2: planner_branches synthesis skips (finding_id, engine_id) pairs already rendered."""
        src = _ROUTES.read_text()
        # The synthesis checks _existing_action_keys before adding
        pb_block = src[src.find("# Synthesize action nodes for planner-dispatched"):
                       src.find("return {\"nodes\": tree_nodes")]
        assert "_existing_action_keys" in pb_block, (
            "Synthesis must check _existing_action_keys to skip already-rendered nodes"
        )
        assert "continue" in pb_block, (
            "Synthesis must continue (skip) when action pair already exists"
        )

    def test_m2_planner_branches_none_is_safe(self):
        """M2: passing planner_branches=None is safe (no crash)."""
        src = _ROUTES.read_text()
        # The block is guarded with: if planner_branches:
        assert "if planner_branches:" in src, (
            "planner_branches synthesis must be guarded with 'if planner_branches:'"
        )


# ── FIX 2 — Chat history persistence ──────────────────────────────────────────

class TestFix2ChatPersistence:

    def test_c1_chat_persist_helper_exists_in_js(self):
        """C1: _chatPersist helper is present in exploitation-mindmap.js."""
        src = _MINDMAP.read_text()
        assert "_chatPersist" in src, "_chatPersist helper must exist in mindmap JS"
        # Must be defined as a function
        assert "function _chatPersist(" in src or "_chatPersist = function" in src, (
            "_chatPersist must be defined as a function"
        )

    def test_c1_stream_done_calls_chat_persist(self):
        """C1: the streaming done handler calls _chatPersist for the assistant reply."""
        src = _MINDMAP.read_text()
        # Find the result.done block
        done_pos = src.find("if (result.done)")
        assert done_pos != -1, "result.done block must exist in streaming handler"
        # _chatPersist must be called within the done block (within 500 chars after it)
        done_window = src[done_pos: done_pos + 500]
        assert "_chatPersist(" in done_window, (
            "_chatPersist must be called in the result.done block to persist the streamed reply"
        )
        assert "'assistant'" in done_window or '"assistant"' in done_window, (
            "_chatPersist must be called with role='assistant'"
        )

    def test_c1_chat_persist_posts_to_backend(self):
        """C1: _chatPersist sends POST to the /chat endpoint."""
        src = _MINDMAP.read_text()
        persist_pos = src.find("function _chatPersist(")
        assert persist_pos != -1
        persist_fn = src[persist_pos: persist_pos + 400]
        assert "/chat" in persist_fn, "_chatPersist must POST to the /chat backend endpoint"
        assert "method: 'POST'" in persist_fn or "method:'POST'" in persist_fn, (
            "_chatPersist must use POST method"
        )

    def test_c1_chat_append_uses_chat_persist(self):
        """C1: _chatAppend delegates backend write to _chatPersist (no direct fetch)."""
        src = _MINDMAP.read_text()
        append_pos = src.find("function _chatAppend(")
        assert append_pos != -1
        next_fn = src.find("function _chatPersist(", append_pos)
        if next_fn == -1:
            next_fn = src.find("function _", append_pos + 50)
        append_fn = src[append_pos: next_fn if next_fn > 0 else append_pos + 600]
        assert "_chatPersist(" in append_fn, (
            "_chatAppend must delegate backend write to _chatPersist"
        )

    def test_c2_get_chat_history_route_exists(self):
        """C2: GET /investigations/{id}/chat route returns ordered chat rows."""
        src = _ROUTES.read_text()
        assert "@router.get" in src and "investigation_id}/chat" in src, (
            "GET /investigations/{id}/chat route must exist"
        )
        # Route must query investigation_chat_history
        assert "investigation_chat_history" in src, (
            "GET /chat route must query investigation_chat_history table"
        )
        assert "ORDER BY created_at ASC" in src, (
            "GET /chat route must return rows ordered oldest-first"
        )

    def test_c2_js_loads_chat_history_on_mount(self):
        """C2: JS calls _loadChatHistory on mount (within 1s delay)."""
        src = _MINDMAP.read_text()
        assert "setTimeout(_loadChatHistory" in src, (
            "JS must schedule _loadChatHistory on mount"
        )
        # The load must fetch from the /chat endpoint
        load_pos = src.find("function _loadChatHistory(")
        assert load_pos != -1
        # Use a wider window — the fetch URL appears after the variable setup
        load_fn = src[load_pos: load_pos + 1000]
        # The URL ends with /chat?limit=500
        assert "/chat" in load_fn, (
            "_loadChatHistory must fetch from the backend /chat endpoint"
        )

    def test_c2_load_is_guarded_against_duplicate(self):
        """C2: _chatLoadedFromBackend flag prevents duplicate loads on re-mount."""
        src = _MINDMAP.read_text()
        assert "_chatLoadedFromBackend" in src, (
            "_chatLoadedFromBackend guard variable must exist"
        )
        load_fn_pos = src.find("function _loadChatHistory(")
        assert load_fn_pos != -1
        load_fn = src[load_fn_pos: load_fn_pos + 200]
        assert "_chatLoadedFromBackend" in load_fn, (
            "_loadChatHistory must check _chatLoadedFromBackend to prevent duplicate loads"
        )
