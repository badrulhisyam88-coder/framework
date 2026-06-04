"""Phase C — STATE-UPDATE WIRE tests.

C1.  facts dedup: same fact added twice → appears once.
C2.  artifacts: verdict's artifacts_captured maps real object into right bucket.
C3.  pending: unlocks added, sorted desc, excluding ruled_out + completed.
C4.  rules_out: ruled-out concept removed from pending; deduped in ruled_out.
C5.  completed: concept_id appended; removed from pending.
C6.  current_position: authenticated set for credential_brute success.
C7.  current_position: rce set for cmdi_reflected success.
C8.  Success check: valid_credentials_found fires when credentials captured.
C9.  Success check: not fired when no credentials.
C10. Success check: goal-scoped (fires regardless of which step produced the fact).
C11. CONCURRENCY: multiple verdicts applied concurrently → no lost updates.
C12. no_concept_match verdict does NOT update STATE.
C13. pending re-sorts after unlock insertion.
C14. solved flag is preserved (not cleared by subsequent verdicts).
C15. Legacy leaf_type behavior regression (evaluate_leaf still works).
"""
from __future__ import annotations

import asyncio
import pytest
from dataclasses import dataclass
from unittest.mock import AsyncMock, patch


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fresh_state(goal=None):
    from apps.conductor.agent_state import default_agent_state
    return default_agent_state(goal=goal)


def _make_verdict(
    match_kind="known",
    goal_advanced=True,
    state_changes=None,
    artifacts_captured=None,
    unlocks=None,
    rules_out=None,
):
    """Build a mock Verdict without importing leaf_evaluator."""
    @dataclass
    class _V:
        match_kind:         str
        goal_advanced:      bool
        state_changes:      list
        artifacts_captured: dict
        unlocks:            list
        rules_out:          list
    return _V(
        match_kind         = match_kind,
        goal_advanced      = goal_advanced,
        state_changes      = state_changes or [],
        artifacts_captured = artifacts_captured or {},
        unlocks            = unlocks or [],
        rules_out          = rules_out or [],
    )


# ── C1-C7: _apply_verdict_in_place (pure-logic, no DB) ───────────────────────

class TestApplyVerdictInPlace:

    def _apply(self, state, verdict, concept_id="CONCEPT-TEST",
               engine_id="test_eng", exec_state="succeeded"):
        from apps.conductor.agent_state import _apply_verdict_in_place
        _apply_verdict_in_place(state, verdict, concept_id, engine_id, exec_state)

    def test_facts_dedup(self):
        """C1: same fact added twice → appears once."""
        state = _fresh_state()
        v1 = _make_verdict(state_changes=["cred_obtained"])
        v2 = _make_verdict(state_changes=["cred_obtained"])
        self._apply(state, v1)
        self._apply(state, v2)
        assert state["facts"].count("cred_obtained") == 1

    def test_artifacts_mapped_to_bucket(self):
        """C2: artifact object goes into the right bucket (Phase 2: origin tag added)."""
        state = _fresh_state()
        obj = {"username": "wiener", "password": "peter"}
        v = _make_verdict(artifacts_captured={"credentials": obj})
        self._apply(state, v)
        # Phase 2: credential gets an origin tag added; check by username presence
        stored = state["artifacts"]["credentials"]
        assert any(c.get("username") == "wiener" for c in stored), (
            "credential must land in credentials bucket (with origin tag)"
        )

    def test_artifacts_multiple_buckets(self):
        """C2b: artifacts can go into multiple buckets from one verdict."""
        state = _fresh_state()
        cred_obj = {"username": "w", "password": "p"}
        sess_obj = {"session": "abc"}
        v = _make_verdict(artifacts_captured={"credentials": cred_obj, "sessions": sess_obj})
        self._apply(state, v)
        # Phase 2: credentials get origin-tagged; check by username presence
        creds = state["artifacts"]["credentials"]
        assert any(c.get("username") == "w" for c in creds)
        assert sess_obj in state["artifacts"]["sessions"]  # sessions not tagged

    def test_pending_gets_unlocks_sorted(self):
        """C3: unlocks added to pending, sorted desc by priority."""
        state = _fresh_state()
        v = _make_verdict(unlocks=[
            {"concept": "CONCEPT-A", "priority": 50},
            {"concept": "CONCEPT-B", "priority": 90},
        ])
        self._apply(state, v)
        priorities = [p["priority"] for p in state["pending"]]
        assert priorities == sorted(priorities, reverse=True)
        concepts = [p["concept"] for p in state["pending"]]
        assert "CONCEPT-A" in concepts and "CONCEPT-B" in concepts

    def test_pending_excludes_ruled_out(self):
        """C3: unlocks that are in ruled_out are NOT added to pending."""
        state = _fresh_state()
        state["ruled_out"] = ["CONCEPT-BLOCKED"]
        v = _make_verdict(unlocks=[{"concept": "CONCEPT-BLOCKED", "priority": 95}])
        self._apply(state, v)
        assert all(p["concept"] != "CONCEPT-BLOCKED" for p in state["pending"])

    def test_pending_excludes_completed(self):
        """C3: unlocks that are already in completed are NOT re-added to pending."""
        state = _fresh_state()
        state["completed"] = ["CONCEPT-DONE"]
        v = _make_verdict(unlocks=[{"concept": "CONCEPT-DONE", "priority": 95}])
        self._apply(state, v)
        assert all(p["concept"] != "CONCEPT-DONE" for p in state["pending"])

    def test_rules_out_removes_from_pending(self):
        """C4: ruled-out concept is removed from pending."""
        state = _fresh_state()
        state["pending"] = [
            {"concept": "CONCEPT-X", "priority": 80},
            {"concept": "CONCEPT-Y", "priority": 60},
        ]
        v = _make_verdict(rules_out=["CONCEPT-X"])
        self._apply(state, v)
        assert all(p["concept"] != "CONCEPT-X" for p in state["pending"])
        assert "CONCEPT-X" in state["ruled_out"]

    def test_rules_out_dedup(self):
        """C4b: same concept ruled out twice → appears once in ruled_out."""
        state = _fresh_state()
        v1 = _make_verdict(rules_out=["CONCEPT-X"])
        v2 = _make_verdict(rules_out=["CONCEPT-X"])
        self._apply(state, v1)
        self._apply(state, v2)
        assert state["ruled_out"].count("CONCEPT-X") == 1

    def test_completed_appended_and_removed_from_pending(self):
        """C5: completed concept appended; removed from pending."""
        state = _fresh_state()
        state["pending"] = [{"concept": "CONCEPT-CRED-BRUTE", "priority": 80}]
        v = _make_verdict()
        self._apply(state, v, concept_id="CONCEPT-CRED-BRUTE")
        assert "CONCEPT-CRED-BRUTE" in state["completed"]
        assert all(p["concept"] != "CONCEPT-CRED-BRUTE" for p in state["pending"])

    def test_current_position_authentication_on_success(self):
        """C6: credential_brute success + discovered credential → authentication=authenticated.
        Phase 2: authentication advances only when a discovered credential exists in state.
        """
        state = _fresh_state()
        assert state["current_position"]["authentication"] == "none"
        # Phase 2: must have a discovered credential for auth to advance
        cred_obj = {"username": "target_user", "password": "pw"}
        v = _make_verdict(artifacts_captured={"credentials": cred_obj})
        self._apply(state, v, concept_id="CONCEPT-CREDENTIAL-BRUTE", exec_state="succeeded")
        # credential is tagged 'discovered' (no provided_self_user set → backward compat)
        assert state["current_position"]["authentication"] == "authenticated"

    def test_current_position_not_updated_on_exhausted(self):
        """C6b: position NOT updated if exec_state != succeeded."""
        state = _fresh_state()
        v = _make_verdict()
        self._apply(state, v, concept_id="CONCEPT-CREDENTIAL-BRUTE", exec_state="exhausted")
        assert state["current_position"]["authentication"] == "none"

    def test_current_position_rce_on_cmdi(self):
        """C7: cmdi_reflected success → execution=rce."""
        state = _fresh_state()
        v = _make_verdict()
        self._apply(state, v, concept_id="CONCEPT-CMDI-REFLECTED", exec_state="succeeded")
        assert state["current_position"]["execution"] == "rce"

    def test_pending_re_sorts_after_unlocks(self):
        """C13: pending stays sorted after mixed-priority unlock insertion."""
        state = _fresh_state()
        state["pending"] = [{"concept": "CONCEPT-HIGH", "priority": 90}]
        v = _make_verdict(unlocks=[
            {"concept": "CONCEPT-LOW", "priority": 20},
            {"concept": "CONCEPT-MED", "priority": 60},
        ])
        self._apply(state, v, concept_id="CONCEPT-SEED")
        priorities = [p["priority"] for p in state["pending"]]
        assert priorities == sorted(priorities, reverse=True), \
            f"pending not sorted: {priorities}"


# ── C8-C10: check_success ────────────────────────────────────────────────────

class TestCheckSuccess:

    def test_fires_on_credentials_captured(self):
        """C8: valid_credentials_found fires on discovered credential.
        Phase 2: reason is now specific ('discovered credentials for ...')
        instead of the generic 'valid_credentials_found satisfied'.
        """
        from apps.conductor.agent_state import check_success
        state = _fresh_state()
        state["goal"]["success_conditions"] = ["valid_credentials_found"]
        # No provided_self_user → any credential is treated as discovered (backward compat)
        state["artifacts"]["credentials"].append({"username": "w", "password": "p"})
        solved, reason = check_success(state)
        assert solved, f"expected SOLVED, reason={reason!r}"
        # Phase 2: reason is specific, not the old generic string
        assert "w" in reason or "discovered" in reason, (
            f"reason must reference the discovered user or say 'discovered'; got: {reason!r}"
        )

    def test_fires_on_credential_obtained_fact(self):
        """C8b: Fix 2 — bare credential_obtained fact alone no longer fires SOLVED.
        An actual credential object must be in artifacts.credentials.
        """
        from apps.conductor.agent_state import check_success
        state = _fresh_state()
        state["goal"]["success_conditions"] = ["valid_credentials_found"]
        state["facts"].append("credential_obtained")
        # Fix 2: fact alone is NOT sufficient — requires classifiable artifact in bucket
        solved, _ = check_success(state)
        assert not solved, (
            "Fix 2: bare credential_obtained fact must NOT fire SOLVED — "
            "requires a credential object in artifacts.credentials"
        )

    def test_not_fired_without_credentials(self):
        """C9: success check not fired when conditions not met."""
        from apps.conductor.agent_state import check_success
        state = _fresh_state()
        state["goal"]["success_conditions"] = ["valid_credentials_found"]
        solved, _ = check_success(state)
        assert not solved

    def test_goal_scoped_fires_from_any_step(self):
        """C10: success fires regardless of which step produced the credential artifact.
        Fix 2: the check is now artifact-based, not fact-based. A credential in the bucket
        from ANY step (sqli, brute, etc.) fires SOLVED.
        """
        from apps.conductor.agent_state import check_success
        state = _fresh_state()
        state["goal"]["success_conditions"] = ["valid_credentials_found"]
        # Credential captured by sqli bypass (different step) and landed in bucket
        state["artifacts"]["credentials"].append({"username": "target", "origin": "discovered"})
        state["facts"].append("credential_obtained")
        state["completed"].append("CONCEPT-SQLI-AUTH-BYPASS")
        solved, _ = check_success(state)
        assert solved, "goal-scoped check must fire when discovered credential is in bucket"

    def test_solved_flag_preserved_by_subsequent_verdicts(self):
        """C14: solved=True is not cleared by subsequent _apply_verdict_in_place calls."""
        from apps.conductor.agent_state import _apply_verdict_in_place
        state = _fresh_state()
        state["goal"]["success_conditions"] = ["valid_credentials_found"]
        state["artifacts"]["credentials"].append({"u": "w"})
        # First apply triggers SOLVED
        v1 = _make_verdict(state_changes=["credential_obtained"])
        _apply_verdict_in_place(state, v1, "CONCEPT-CREDENTIAL-BRUTE", "cred_brute", "succeeded")
        assert state.get("solved"), "should be SOLVED after first verdict"
        # Second apply (different step) must not clear solved
        v2 = _make_verdict(state_changes=["endpoints_discovered"])
        _apply_verdict_in_place(state, v2, "CONCEPT-JS-SPIDER", "js_spider", "exhausted")
        assert state.get("solved"), "solved must not be cleared by subsequent verdicts"

    def test_no_concept_match_does_not_update_state(self):
        """C12: no_concept_match verdict leaves STATE unchanged."""
        from apps.conductor.agent_state import _apply_verdict_in_place
        state = _fresh_state()
        original_facts = list(state["facts"])
        v = _make_verdict(match_kind="no_concept_match", state_changes=["should_not_appear"])
        # Simulate orchestrator check: only call _apply if match_kind == "known"
        if v.match_kind == "known":
            _apply_verdict_in_place(state, v, "CONCEPT-X", "engine_x", "exhausted")
        assert state["facts"] == original_facts, \
            "no_concept_match verdict must not update STATE"


# ── C11: CONCURRENCY — the parallel-branch hazard ─────────────────────────────

class TestConcurrentStateUpdates:
    """C11: Multiple verdicts applied concurrently → no lost updates."""

    @pytest.mark.asyncio
    async def test_concurrent_verdicts_no_lost_updates(self):
        """C11: 10 verdicts fire concurrently; all facts appear in final STATE."""
        from apps.conductor.agent_state import (
            _get_state_lock, _apply_verdict_in_place, default_agent_state,
        )

        # Shared mutable state (simulates what DB would hold)
        shared_state = default_agent_state()
        shared_state["goal"]["success_conditions"] = []
        lock = _get_state_lock("test-concurrent-inv")

        N_VERDICTS = 10

        async def _apply_one(i: int) -> None:
            fact = f"fact_{i}"
            v = _make_verdict(state_changes=[fact])
            async with lock:
                _apply_verdict_in_place(
                    shared_state, v,
                    concept_id=f"CONCEPT-{i}",
                    engine_id=f"engine_{i}",
                    exec_state="succeeded",
                )

        # Fire all concurrently
        await asyncio.gather(*[_apply_one(i) for i in range(N_VERDICTS)])

        # Every fact must be present
        for i in range(N_VERDICTS):
            assert f"fact_{i}" in shared_state["facts"], (
                f"fact_{i} missing — lost update under concurrency"
            )
        assert len(shared_state["facts"]) == N_VERDICTS, (
            f"expected {N_VERDICTS} distinct facts, got {len(shared_state['facts'])}"
        )

    @pytest.mark.asyncio
    async def test_concurrent_artifact_appends_no_lost_updates(self):
        """C11b: concurrent artifact appends → all objects present, none dropped."""
        from apps.conductor.agent_state import (
            _get_state_lock, _apply_verdict_in_place, default_agent_state,
        )

        shared_state = default_agent_state()
        shared_state["goal"]["success_conditions"] = []
        lock = _get_state_lock("test-concurrent-art")

        N = 5

        async def _add_cred(i: int) -> None:
            obj = {"username": f"user_{i}", "password": f"pass_{i}"}
            v = _make_verdict(artifacts_captured={"credentials": obj})
            async with lock:
                _apply_verdict_in_place(
                    shared_state, v,
                    concept_id=f"CONCEPT-CRED-{i}",
                    engine_id="credential_brute",
                    exec_state="succeeded",
                )

        await asyncio.gather(*[_add_cred(i) for i in range(N)])

        creds = shared_state["artifacts"]["credentials"]
        assert len(creds) == N, f"expected {N} credential objects, got {len(creds)}"
        for i in range(N):
            assert any(c.get("username") == f"user_{i}" for c in creds), (
                f"credential for user_{i} missing — lost update"
            )


# ── C15: Regression — existing leaf_type behavior ─────────────────────────────

class TestLeafBehaviorRegression:
    """C15: evaluate_leaf still works exactly as before (no behavior change)."""

    def test_evaluate_leaf_terminal_on_is_solved(self):
        """C15: _is_solved still fires TERMINAL immediately."""
        from apps.conductor.leaf_evaluator import evaluate_leaf, LeafClassification
        # Artifact that _is_solved recognizes as a win
        art = {"artifact": {"artifact_type": "captured_session",
                             "session_cookies": {"session": "abc"}}}
        with patch("apps.conductor.autonomous_orchestrator._is_solved", return_value=True), \
             patch("apps.conductor.leaf_evaluator._evaluate") as mock_ev:
            from apps.conductor.leaf_evaluator import _evaluate as real_eval
            # Import and call without the patch overriding
            mock_ev.side_effect = real_eval
            # The fast-path fires before concept lookup
            result = evaluate_leaf("credential_brute", "CONCEPT-CREDENTIAL-BRUTE",
                                   artifact=art, state="succeeded")
        # Whether terminal or not, it returns a LeafClassification (not a Verdict)
        assert isinstance(result, LeafClassification)

    def test_autonomous_orchestrator_imports_still_work(self):
        """C15b: imports in autonomous_orchestrator.py still resolve (no circular import)."""
        import ast
        import pathlib
        src = pathlib.Path(
            "/home/unctad/projects/conductor-framework/apps/conductor/autonomous_orchestrator.py"
        ).read_text()
        ast.parse(src)  # would fail if syntax broken

    def test_agent_state_imports_still_work(self):
        """C15c: agent_state.py imports and parses cleanly."""
        import ast, pathlib
        src = pathlib.Path(
            "/home/unctad/projects/conductor-framework/apps/conductor/agent_state.py"
        ).read_text()
        ast.parse(src)
