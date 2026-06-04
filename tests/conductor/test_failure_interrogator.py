"""Phase 3 — Failure Interrogation Layer: mock tests.

M1. Each matcher individually:
    - mid_run_blocked:        blocked-during-run branch → FACT; unrelated → None.
    - wordlist_exhausted:     full-list branch, no block → FACT; block signal → None.
    - missing_csrf_token:     csrf reason in exhaustion_record → FACT; unrelated → None.
    - requires_session_first: explicit auth-required signal → FACT; normal exhaust → None.

M2. Loop integration: STUCK → interrogate → fact emitted → lands in agent_state.facts →
    planner re-runs and selects a different concept (the one unlocked by that fact).

M3. No-fact path: interrogate() returns None → STUCK terminal; planner not re-called.

M4. Attempt cap: after MAX_INTERROGATIONS STUCKs the interrogator is bypassed;
    terminal STUCK fires.

G1. Generality: unmatched failure (none of the four matchers know it) → None, STUCK.

S1. Existing solved-path still works: solved=True → action=solved immediately; probe
    detection still seeds ip_block_detected (no interaction with interrogation).
"""
from __future__ import annotations

import copy
import pytest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

from apps.conductor.failure_interrogator import (
    FACT_MID_RUN_BLOCKED,
    FACT_WORDLIST_EXHAUSTED,
    FACT_MISSING_CSRF_TOKEN,
    FACT_REQUIRES_SESSION_FIRST,
    MAX_INTERROGATIONS,
    budget_remaining,
    interrogate,
    _match_mid_run_blocked,
    _match_wordlist_exhausted,
    _match_missing_csrf_token,
    _match_requires_session_first,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

@dataclass
class _Branch:
    """Minimal BranchRecord stub for matcher tests."""
    engine_id: str = "credential_brute"
    state: str = "exhausted"
    exhaustion_record: "dict | None" = None
    stage_log: "list[dict]" = field(default_factory=list)
    artifact: "dict | None" = None
    artifact_type: "str | None" = None
    branch_id: str = "exb_test_001"
    investigation_id: str = "inv-test"
    finding_id: str = "fnd-test"
    technique_class: str = "brute_force"
    operator_params: dict = field(default_factory=dict)
    created_at: str = "2026-06-03T00:00:00Z"
    updated_at: str = "2026-06-03T00:00:01Z"


def _state(facts=None, artifacts=None, interrogation_attempts=0):
    return {
        "goal": {
            "objective": "test",
            "success_conditions": ["valid_credentials_found"],
            "provided_self_user": None,
            "target_user": "carlos",
        },
        "facts": list(facts or []),
        "artifacts": {
            "credentials": list((artifacts or {}).get("credentials", [])),
            "sessions":    list((artifacts or {}).get("sessions", [])),
            "tokens":      [],
            "files":       [],
        },
        "pending":   [],
        "completed": [],
        "current_position": {"authentication": "none", "privilege": "none",
                             "access_scope": [], "execution": "none"},
        "planner_log": [],
        "solved": False,
        "interrogation_attempts": interrogation_attempts,
        "interrogation_log": [],
    }


# ── M1a: mid_run_blocked matcher ──────────────────────────────────────────────

class TestMatchMidRunBlocked:

    def test_fires_on_blocked_during_brute(self):
        """M1a: branch with 'blocked' in negative_evidence.reason → FACT."""
        branch = _Branch(
            engine_id="credential_brute",
            exhaustion_record={
                "technique_class": "brute_force",
                "negative_evidence": {"reason": "blocked_by_rate_limit", "attempts": 5},
            },
        )
        result = _match_mid_run_blocked([branch], _state())
        assert result == FACT_MID_RUN_BLOCKED, (
            f"blocked_by_rate_limit must return FACT_MID_RUN_BLOCKED; got {result!r}"
        )

    def test_fires_on_lockout_keyword(self):
        """M1a: 'lockout' in reason → FACT."""
        branch = _Branch(
            engine_id="credential_brute_counter_reset",
            exhaustion_record={
                "negative_evidence": {"reason": "account_lockout_detected"},
            },
        )
        result = _match_mid_run_blocked([branch], _state())
        assert result == FACT_MID_RUN_BLOCKED

    def test_does_not_fire_for_probe_engine(self):
        """M1a: login_protection_probe exhaustion → None (probe sets ip_block_detected)."""
        branch = _Branch(
            engine_id="login_protection_probe",
            exhaustion_record={"negative_evidence": {"reason": "blocked"}},
        )
        result = _match_mid_run_blocked([branch], _state())
        assert result is None, "Probe exhaustion must NOT trigger mid_run_blocked"

    def test_does_not_fire_for_unrelated_exhaust(self):
        """M1a: normal credential mismatch exhaustion → None."""
        branch = _Branch(
            exhaustion_record={
                "payloads_tried": ["pw1", "pw2"],
                "negative_evidence": {"reason": "no_match"},
            },
        )
        result = _match_mid_run_blocked([branch], _state())
        assert result is None

    def test_does_not_fire_for_succeeded_branch(self):
        """M1a: succeeded branches are ignored."""
        branch = _Branch(
            state="succeeded",
            exhaustion_record={"negative_evidence": {"reason": "blocked"}},
        )
        result = _match_mid_run_blocked([branch], _state())
        assert result is None


# ── M1b: wordlist_exhausted matcher ───────────────────────────────────────────

class TestMatchWordlistExhausted:

    def test_fires_when_payloads_tried_and_no_block(self):
        """M1b: payloads tried, no block signal → FACT."""
        branch = _Branch(
            exhaustion_record={
                "payloads_tried": ["password1", "password2", "letmein"],
                "negative_evidence": {"reason": "no_valid_credential"},
            },
        )
        result = _match_wordlist_exhausted([branch], _state())
        assert result == FACT_WORDLIST_EXHAUSTED, (
            f"Full wordlist with no block must return FACT_WORDLIST_EXHAUSTED; got {result!r}"
        )

    def test_fires_on_no_signal_found_flag(self):
        """M1b: oracle engine with no_signal_found=True → FACT."""
        branch = _Branch(
            engine_id="username_enum",
            exhaustion_record={"no_signal_found": True, "oracle_strategy": "timing"},
        )
        result = _match_wordlist_exhausted([branch], _state())
        assert result == FACT_WORDLIST_EXHAUSTED

    def test_does_not_fire_when_block_signal_present(self):
        """M1b: payloads_tried + blocked reason → None (mid_run_blocked fires first)."""
        branch = _Branch(
            exhaustion_record={
                "payloads_tried": ["pw1"],
                "negative_evidence": {"reason": "blocked_by_rate_limit"},
            },
        )
        result = _match_wordlist_exhausted([branch], _state())
        assert result is None, "Block signal must suppress wordlist_exhausted"

    def test_does_not_fire_on_empty_payloads_tried(self):
        """M1b: no payloads tried (early abort) → None."""
        branch = _Branch(
            exhaustion_record={
                "payloads_tried": [],
                "negative_evidence": {"reason": "no_match"},
            },
        )
        result = _match_wordlist_exhausted([branch], _state())
        assert result is None


# ── M1c: missing_csrf_token matcher ───────────────────────────────────────────

class TestMatchMissingCsrfToken:

    def test_fires_on_csrf_in_reason(self):
        """M1c: 'csrf' in negative_evidence.reason → FACT."""
        branch = _Branch(
            exhaustion_record={
                "negative_evidence": {"reason": "csrf_extraction_failed"},
            },
        )
        result = _match_missing_csrf_token([branch], _state())
        assert result == FACT_MISSING_CSRF_TOKEN, (
            f"csrf_extraction_failed must return FACT_MISSING_CSRF_TOKEN; got {result!r}"
        )

    def test_stage_log_scan_removed_does_not_fire(self):
        """M1c: stage_log scan was removed (Workstream A audit 2026-06-04).
        'csrf' in a stage_log entry NO LONGER triggers the matcher — only
        exhaustion_record.reason is inspected.
        """
        branch = _Branch(
            exhaustion_record=None,   # no exhaustion_record at all
            stage_log=[
                {"state": "running", "at": "2026-06-03T00:00:00Z"},
                {"state": "exhausted", "at": "2026-06-03T00:00:01Z",
                 "message": "csrf token extraction failed — invalid response"},
            ],
        )
        result = _match_missing_csrf_token([branch], _state())
        # Stage-log scan removed → must return None even though 'csrf' is in stage_log
        assert result is None, (
            "Stage-log scan was removed after Workstream A audit; "
            "only exhaustion_record.reason is inspected for CSRF signals."
        )

    def test_does_not_fire_on_unrelated_exhaust(self):
        """M1c: no CSRF mention → None."""
        branch = _Branch(
            exhaustion_record={"negative_evidence": {"reason": "no_match"}},
        )
        result = _match_missing_csrf_token([branch], _state())
        assert result is None

    def test_does_not_fire_for_succeeded_branch(self):
        """M1c: succeeded branches with csrf in artifact are ignored."""
        branch = _Branch(
            state="succeeded",
            stage_log=[{"state": "succeeded", "csrf_token": "abc123"}],
        )
        result = _match_missing_csrf_token([branch], _state())
        assert result is None


# ── M1d: requires_session_first matcher ───────────────────────────────────────

class TestMatchRequiresSessionFirst:

    def test_fires_on_requires_auth_reason(self):
        """M1d: 'requires_auth' in exhaustion_record.reason → FACT."""
        branch = _Branch(
            engine_id="access_control",
            exhaustion_record={
                "negative_evidence": {"reason": "requires_auth"},
            },
        )
        result = _match_requires_session_first([branch], _state())
        assert result == FACT_REQUIRES_SESSION_FIRST, (
            f"requires_auth must return FACT_REQUIRES_SESSION_FIRST; got {result!r}"
        )

    def test_fires_on_session_required_engine_with_no_session(self):
        """M1d: js_spider exhausted and no session in artifacts → FACT."""
        branch = _Branch(
            engine_id="js_spider",
            exhaustion_record={"negative_evidence": {"reason": "no_match"}},
        )
        result = _match_requires_session_first([branch], _state(artifacts={}))
        assert result == FACT_REQUIRES_SESSION_FIRST

    def test_does_not_fire_when_session_present(self):
        """M1d: js_spider exhausted BUT session artifact exists → None."""
        branch = _Branch(
            engine_id="js_spider",
            exhaustion_record={"negative_evidence": {"reason": "no_match"}},
        )
        result = _match_requires_session_first(
            [branch],
            _state(artifacts={"credentials": [{"username": "carlos"}]}),
        )
        assert result is None

    def test_does_not_fire_for_normal_brute_exhaust(self):
        """M1d: normal credential_brute exhaustion → None."""
        branch = _Branch(
            engine_id="credential_brute",
            exhaustion_record={"payloads_tried": ["pw1"], "negative_evidence": {"reason": "no_match"}},
        )
        result = _match_requires_session_first([branch], _state())
        assert result is None


# ── M1 top-level: interrogate() dispatches to first matcher that fires ─────────

class TestInterrogateDispatch:

    def test_returns_first_matching_fact(self):
        """interrogate(): mid_run_blocked fires first when present."""
        branch = _Branch(exhaustion_record={"negative_evidence": {"reason": "blocked"}})
        fact = interrogate([branch], _state())
        assert fact == FACT_MID_RUN_BLOCKED

    def test_returns_none_when_nothing_matches(self):
        """G1: unrecognised failure pattern → None (interrogator does not guess)."""
        branch = _Branch(
            exhaustion_record={"negative_evidence": {"reason": "unknown_exotic_signal_xyz"}},
        )
        fact = interrogate([branch], _state())
        assert fact is None, (
            "interrogate() must return None for unknown failure signals"
        )

    def test_does_not_raise_on_empty_branches(self):
        """G1: no branches → None (no crash)."""
        assert interrogate([], _state()) is None

    def test_does_not_raise_on_none_exhaustion_record(self):
        """G1: branch with exhaustion_record=None → graceful None."""
        branch = _Branch(exhaustion_record=None)
        assert interrogate([branch], _state()) is None


# ── M2: loop integration — STUCK → interrogate → fact → re-plan ───────────────

class _AsyncNullLock:
    """Minimal async context manager for mocking _get_state_lock."""
    async def __aenter__(self): return self
    async def __aexit__(self, *_): pass


def _make_async_null_lock(*args, **kwargs):
    """Factory so each _get_state_lock(...) call gets a fresh lock instance."""
    return _AsyncNullLock()


class TestLoopIntegration:

    @pytest.mark.asyncio
    async def test_m2_stuck_triggers_interrogation_and_replan(self):
        """M2: planner STUCK → interrogation emits fact → agent_state.facts updated →
        planner re-runs.

        Mocks `interrogate` directly (matchers tested in M1) to isolate the loop's
        response to an interrogation result.  Branch-loading is bypassed because
        BranchReader cannot be instantiated on host (aiosqlite absent).
        """
        from apps.conductor.autonomous_orchestrator import run_planner_loop

        WORDLIST_CONCEPT = "CONCEPT-TARGETED-ENUM-RETRY"

        _shared_state = {
            "goal": {"objective": "test", "success_conditions": [],
                     "provided_self_user": None, "target_user": None},
            "facts": [],
            "artifacts": {"credentials": [], "sessions": [], "tokens": [], "files": []},
            "pending": [],  # empty → STUCK on first call
            "ruled_out": [],
            "completed": [],
            "current_position": {"authentication": "none", "privilege": "none",
                                 "access_scope": [], "execution": "none"},
            "planner_log": [],
            "solved": False,
            "interrogation_attempts": 0,
            "interrogation_log": [],
        }

        async def _load_state(inv_id): return copy.deepcopy(_shared_state)
        async def _save_state(inv_id, state):
            _shared_state.clear(); _shared_state.update(state)

        class _FakeSpec:
            concept_id = WORDLIST_CONCEPT
            priority = 60

        # Mock a stub BranchReader that returns an empty list (no aiosqlite needed)
        class _FakeBR:
            def __init__(self, db_path=None): pass
            async def list_for_investigation(self, inv_id): return []

        with (
            patch("apps.conductor.agent_state.load_agent_state_async",
                  new=AsyncMock(side_effect=_load_state)),
            patch("apps.conductor.agent_state.save_agent_state_async",
                  new=AsyncMock(side_effect=_save_state)),
            patch("apps.conductor.agent_state.get_or_init_agent_state_async",
                  new=AsyncMock(side_effect=_load_state)),
            patch("apps.conductor.agent_state._get_state_lock",
                  side_effect=_make_async_null_lock),
            # Mock interrogate to return a fact directly (matchers tested in M1)
            patch("apps.conductor.failure_interrogator.interrogate",
                  return_value=FACT_WORDLIST_EXHAUSTED),
            # Mock BranchReader to avoid aiosqlite on host
            patch("apps.conductor.exploitation.branch_store.BranchReader",
                  new=_FakeBR),
            patch("apps.conductor.graph_resolver.resolve_branches",
                  return_value=[_FakeSpec()]),
        ):
            result = await run_planner_loop(
                investigation_id="inv-m2",
                target="https://example.com",
                max_iterations=5,
                operator_params={},
            )

        facts = _shared_state.get("facts", [])
        assert FACT_WORDLIST_EXHAUSTED in facts, (
            f"FACT_WORDLIST_EXHAUSTED must be in agent_state.facts; got {facts!r}"
        )
        ilog = _shared_state.get("interrogation_log", [])
        assert len(ilog) >= 1
        assert ilog[0]["fact"] == FACT_WORDLIST_EXHAUSTED


# ── M3: no-fact path — interrogation yields nothing → STUCK terminal ──────────

class TestNoFactPath:

    @pytest.mark.asyncio
    async def test_m3_no_fact_returns_stuck(self):
        """M3: interrogate() returns None → loop returns action='stuck'."""
        from apps.conductor.autonomous_orchestrator import run_planner_loop

        _shared_state = {
            "goal": {"objective": "t", "success_conditions": [],
                     "provided_self_user": None, "target_user": None},
            "facts": [], "artifacts": {"credentials": [], "sessions": [], "tokens": [], "files": []},
            "pending": [], "ruled_out": [], "completed": [],
            "current_position": {"authentication": "none", "privilege": "none",
                                 "access_scope": [], "execution": "none"},
            "planner_log": [], "solved": False,
            "interrogation_attempts": 0, "interrogation_log": [],
        }

        async def _load(inv_id): return copy.deepcopy(_shared_state)
        async def _save(inv_id, s): _shared_state.clear(); _shared_state.update(s)

        # Branch with unrecognised failure → interrogate returns None
        _unknown_branch = _Branch(
            exhaustion_record={"negative_evidence": {"reason": "exotic_unknown_failure_xyz"}},
        )

        class _FakeBR2:
            def __init__(self, db_path=None): pass
            async def list_for_investigation(self, inv_id): return []

        with (
            patch("apps.conductor.agent_state.load_agent_state_async", new=AsyncMock(side_effect=_load)),
            patch("apps.conductor.agent_state.save_agent_state_async", new=AsyncMock(side_effect=_save)),
            patch("apps.conductor.agent_state.get_or_init_agent_state_async", new=AsyncMock(side_effect=_load)),
            patch("apps.conductor.agent_state._get_state_lock",
                  side_effect=_make_async_null_lock),
            # Mock interrogate to return None — tests the no-fact path
            patch("apps.conductor.failure_interrogator.interrogate",
                  return_value=None),
            patch("apps.conductor.exploitation.branch_store.BranchReader",
                  new=_FakeBR2),
            patch("apps.conductor.graph_resolver.resolve_branches", return_value=[]),
        ):
            result = await run_planner_loop(
                investigation_id="inv-m3",
                target="https://example.com",
                max_iterations=3,
                operator_params={},
            )

        assert result["action"] == "stuck", (
            f"No-fact path must return action='stuck'; got {result['action']!r}"
        )
        # Planner_log must note the interrogation attempt
        plog = _shared_state.get("planner_log", [])
        assert any("INTERROGATE" in entry for entry in plog), (
            f"planner_log must contain an INTERROGATE entry; got {plog!r}"
        )


# ── M4: attempt cap ────────────────────────────────────────────────────────────

class TestAttemptCap:

    def test_budget_remaining_false_at_cap(self):
        """M4: interrogation_attempts >= MAX_INTERROGATIONS → budget_remaining=False."""
        state_at_cap = _state(interrogation_attempts=MAX_INTERROGATIONS)
        assert not budget_remaining(state_at_cap), (
            f"budget_remaining must be False when attempts >= {MAX_INTERROGATIONS}"
        )

    def test_budget_remaining_true_below_cap(self):
        """M4: attempts < MAX_INTERROGATIONS → budget_remaining=True."""
        state_below = _state(interrogation_attempts=MAX_INTERROGATIONS - 1)
        assert budget_remaining(state_below)

    @pytest.mark.asyncio
    async def test_m4_cap_prevents_further_interrogation(self):
        """M4: after MAX_INTERROGATIONS, STUCK fires without calling interrogate()."""
        from apps.conductor.autonomous_orchestrator import run_planner_loop

        _shared_state = {
            "goal": {"objective": "t", "success_conditions": [],
                     "provided_self_user": None, "target_user": None},
            "facts": [],
            "artifacts": {"credentials": [], "sessions": [], "tokens": [], "files": []},
            "pending": [], "ruled_out": [], "completed": [],
            "current_position": {"authentication": "none", "privilege": "none",
                                 "access_scope": [], "execution": "none"},
            "planner_log": [], "solved": False,
            "interrogation_attempts": MAX_INTERROGATIONS,  # already at cap
            "interrogation_log": [],
        }

        _interrogate_calls = []

        async def _load(inv_id): return copy.deepcopy(_shared_state)
        async def _save(inv_id, s): _shared_state.clear(); _shared_state.update(s)

        def _mock_interrogate(branches, state):
            _interrogate_calls.append(1)
            return FACT_WORDLIST_EXHAUSTED  # would emit fact if called

        with (
            patch("apps.conductor.agent_state.load_agent_state_async", new=AsyncMock(side_effect=_load)),
            patch("apps.conductor.agent_state.save_agent_state_async", new=AsyncMock(side_effect=_save)),
            patch("apps.conductor.agent_state.get_or_init_agent_state_async", new=AsyncMock(side_effect=_load)),
            patch("apps.conductor.agent_state._get_state_lock",
                  return_value=__import__("contextlib").asynccontextmanager(
                      lambda: (x for x in [None])
                  )()),
            patch("apps.conductor.exploitation.branch_store.BranchReader.list_for_investigation",
                  new=AsyncMock(return_value=[])),
            patch("apps.conductor.failure_interrogator.interrogate", side_effect=_mock_interrogate),
            patch("apps.conductor.graph_resolver.resolve_branches", return_value=[]),
        ):
            result = await run_planner_loop(
                investigation_id="inv-m4",
                target="https://example.com",
                max_iterations=3,
                operator_params={},
            )

        assert result["action"] == "stuck", "At cap, must return stuck without re-planning"
        assert len(_interrogate_calls) == 0, (
            "interrogate() must NOT be called when budget is exhausted"
        )


# ── G1: Generality — unmatched failure yields None ────────────────────────────

class TestGenerality:

    def test_g1_unmatched_failure_yields_no_fact(self):
        """G1: deliberate unrecognised signal → None (matchers are pattern-driven)."""
        # Random response patterns not in any matcher
        branch = _Branch(
            engine_id="credential_brute",
            exhaustion_record={
                "payloads_tried": [],
                "negative_evidence": {"reason": "unknown_server_behaviour_abc123"},
                "exotic_field": "something_unrecognised",
            },
        )
        result = interrogate([branch], _state())
        assert result is None, (
            "Unrecognised failure must yield None — interrogator never guesses"
        )

    def test_g1_empty_exhaustion_record_yields_none(self):
        """G1: exhaustion_record is {} → all matchers fail cleanly."""
        branch = _Branch(exhaustion_record={})
        assert interrogate([branch], _state()) is None

    def test_g1_all_matchers_return_none_for_probe_engine(self):
        """G1: probe exhaustion doesn't fire any non-probe matcher."""
        branch = _Branch(
            engine_id="login_protection_probe",
            exhaustion_record={
                "negative_evidence": {"reason": "blocked"},  # would fire mid_run_blocked for any other engine
            },
        )
        # mid_run_blocked is suppressed for probe engines
        assert _match_mid_run_blocked([branch], _state()) is None
        # Others also shouldn't fire on this probe exhaustion
        assert _match_wordlist_exhausted([branch], _state()) is None


# ── S1: Pre-existing paths untouched ─────────────────────────────────────────

class TestPreExistingPaths:

    def test_s1_solved_state_returns_immediately(self):
        """S1: solved=True in state → plan_next_step returns solved without interrogation."""
        from apps.conductor.planner import plan_next_step
        state = _state()
        state["solved"] = True
        state["solved_reason"] = "discovered credentials for 'carlos'"
        decision = plan_next_step(state)
        assert decision.action == "solved"

    def test_s1_interrogation_does_not_affect_execute_path(self):
        """S1: planner with reachable concept returns execute — interrogation not involved."""
        from apps.conductor.planner import plan_next_step
        state = _state()
        state["pending"] = [{"concept": "CONCEPT-CREDENTIAL-BRUTE", "priority": 85}]
        decision = plan_next_step(state)
        assert decision.action == "execute"
        assert decision.concept_id == "CONCEPT-CREDENTIAL-BRUTE"

    def test_s1_default_agent_state_has_interrogation_fields(self):
        """S1: default_agent_state includes new Phase 3 tracking fields."""
        from apps.conductor.agent_state import default_agent_state
        state = default_agent_state()
        assert "interrogation_attempts" in state, (
            "default_agent_state must include interrogation_attempts"
        )
        assert "interrogation_log" in state, (
            "default_agent_state must include interrogation_log"
        )
        assert state["interrogation_attempts"] == 0
        assert state["interrogation_log"] == []
