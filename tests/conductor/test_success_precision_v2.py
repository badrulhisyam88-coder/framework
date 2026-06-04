"""Phase 2 success precision v2 — Three-path false-positive closure.

FIX 1 (objective-level provided_self_user):
  F1-1.  planner_run sets provided_self_user in goal from operator_params.
  F1-2.  plain credential_brute capture: with provided_self_user=wiener objective-level,
          wiener credential classified provided → NOT solved. (Path A false-positive dies.)
  F1-3.  provided_self_user visible to non-counter-reset engine captures (general).

FIX 2 (remove fact-fallback):
  F2-1.  artifacts.credentials empty + credential_obtained in facts → NOT solved.
  F2-2.  The specific old-diagnostic scenario: facts=['credential_obtained'] + empty creds
          → NOT solved (Path B false-positive dies).
  F2-3.  Ambiguous state (fact, no artifact) → not-yet-solved, no false SOLVED.

FIX 3 (credential facts coupled to artifact landing):
  F3-1.  evaluate_verdict with no artifact: credential_obtained NOT in state_changes.
  F3-2.  evaluate_verdict with real artifact: credential_obtained IS in state_changes.
  F3-3.  Path C: fact+bucket are consistent — fact applies iff artifact also applies.

NEGATIVE (real discovered credential still solves):
  N1.    Discovered credential (non-provided username) → SOLVED with specific message.
  N2.    No provided_self_user set + credential captured → SOLVED (backward compat).
  N3.    Fix 3 did not break real solves: captured credential lands fact AND bucket.

NO HARDCODING:
  HC1.   No wiener/peter/carlos literals in agent_state.py or leaf_evaluator.py.
  HC2.   planner_run Fix 1 reads provided_self_user from operator_params (no literals).
"""
from __future__ import annotations

import pytest
from pathlib import Path
from dataclasses import dataclass

_AGENT  = Path(__file__).resolve().parents[2] / "apps/conductor/agent_state.py"
_EVAL   = Path(__file__).resolve().parents[2] / "apps/conductor/leaf_evaluator.py"
_ROUTES = Path(__file__).resolve().parents[2] / "apps/investigation_workspace/api/routes.py"


# ── FIX 1 — objective-level provided_self_user ────────────────────────────────

class TestFix1ObjectiveLevel:

    def test_fix1_in_planner_run_source(self):
        """F1-1: planner_run stores provided_self_user from operator_params in goal."""
        src = _ROUTES.read_text()
        assert "provided_self_user" in src and "operator_params" in src, (
            "planner_run must store provided_self_user from operator_params"
        )
        # The fix writes to goal, not just passes params through
        assert '_f1_state["goal"]["provided_self_user"]' in src or \
               "goal']['provided_self_user']" in src, (
            "Fix 1 must write provided_self_user into goal dict"
        )

    def test_path_a_false_positive_dies_with_objective_context(self):
        """F1-2: plain brute captures wiener; provided_self_user=wiener at goal level → NOT solved.
        This is Path A: the wiener:peter false positive on the plain-brute path.
        """
        from apps.conductor.agent_state import check_success, default_agent_state, _tag_credential_origin
        state = default_agent_state()
        state["goal"]["success_conditions"] = ["valid_credentials_found"]
        state["goal"]["provided_self_user"] = "wiener"    # set at objective level, not in engine

        # Plain credential_brute captures wiener (the provided self-login)
        cred = _tag_credential_origin({"username": "wiener", "password": "peter"}, state["goal"])
        state["artifacts"]["credentials"].append(cred)
        # Fact also set (as if engine ran)
        state["facts"].append("credential_obtained")
        state["facts"].append("session_authenticated")

        solved, reason = check_success(state)
        assert not solved, (
            "Path A: plain brute capturing wiener MUST NOT solve when provided_self_user=wiener. "
            f"Got solved={solved}, reason={reason!r}"
        )

    def test_fix1_general_visible_to_any_engine(self):
        """F1-3: provided_self_user set at objective level is visible to any engine's tagging."""
        from apps.conductor.agent_state import _tag_credential_origin
        goal = {"provided_self_user": "self_account", "target_user": "target_account"}

        # Non-counter-reset engine captures 'self_account'
        cred_self = _tag_credential_origin({"username": "self_account", "password": "pw"}, goal)
        assert cred_self["origin"] == "provided", (
            "Any engine's capture of the provided self-account must be tagged 'provided'"
        )

        # Non-counter-reset engine captures 'target_account'
        cred_target = _tag_credential_origin({"username": "target_account", "password": "pw"}, goal)
        assert cred_target["origin"] == "discovered", (
            "Any engine's capture of the target account must be tagged 'discovered'"
        )


# ── FIX 2 — fact-fallback removed ────────────────────────────────────────────

class TestFix2FactFallbackRemoved:

    def test_path_b_false_positive_dies(self):
        """F2-1/F2-2: artifacts.credentials empty + credential_obtained in facts → NOT solved.
        Path B: the diagnostic scenario that fired SOLVED with the generic message.
        """
        from apps.conductor.agent_state import check_success, default_agent_state
        state = default_agent_state()
        state["goal"]["success_conditions"] = ["valid_credentials_found"]
        # Simulate the exact diagnostic state from investigation f50bb5f5
        state["facts"] = ["credential_obtained", "session_authenticated", "endpoints_discovered"]
        state["artifacts"]["credentials"] = []   # EMPTY — the diagnostic condition

        solved, reason = check_success(state)
        assert not solved, (
            "Path B: bare credential_obtained fact with empty credentials bucket "
            "MUST NOT fire SOLVED. "
            f"Got solved={solved}, reason={reason!r}"
        )

    def test_fact_fallback_code_removed(self):
        """F2-3: the bare-fact fallback path is removed from _has_discovered_credential source."""
        src = _AGENT.read_text()
        # The old fallback line must NOT be present
        assert 'return "credential_obtained" in (s.get("facts") or [])' not in src, (
            "The bare credential_obtained fact-fallback must be removed from "
            "_has_discovered_credential (Fix 2)"
        )
        # Fix 2 comment must be present
        assert "Fix 2" in src, "Fix 2 comment must be present in agent_state.py"


# ── FIX 3 — credential facts coupled to artifact ─────────────────────────────

class TestFix3CredentialFactsCoupled:

    def _make_verdict(self, state_changes, artifacts_captured):
        @dataclass
        class _V:
            match_kind: str = "known"
            goal_advanced: bool = True
            state_changes: list = None
            artifacts_captured: dict = None
            unlocks: list = None
            rules_out: list = None
            def __post_init__(self):
                if self.state_changes is None: self.state_changes = []
                if self.artifacts_captured is None: self.artifacts_captured = {}
                if self.unlocks is None: self.unlocks = []
                if self.rules_out is None: self.rules_out = []
        return _V(state_changes=state_changes, artifacts_captured=artifacts_captured)

    def test_no_artifact_no_credential_fact(self):
        """F3-1: evaluate_verdict with no artifact → credential_obtained NOT in state_changes."""
        from apps.conductor.leaf_evaluator import _evaluate_verdict
        from unittest.mock import patch

        # Patch the vault concept fields to return credential-related state_changes
        fake_fields = {
            "state_changes":      ["credential_obtained", "session_authenticated"],
            "artifacts_captured": ["credentials", "sessions"],
            "unlocks":            [],
            "rules_out":          [],
        }
        with patch("apps.conductor.leaf_evaluator._load_concept_agent_fields",
                   return_value=fake_fields):
            verdict = _evaluate_verdict(
                engine_id  = "credential_brute",
                concept_id = "CONCEPT-CREDENTIAL-BRUTE",
                artifact   = {},       # EMPTY — no artifact captured
                state      = "succeeded",
                finding_id = "",
            )

        assert "credential_obtained" not in verdict.state_changes, (
            "Fix 3: credential_obtained must NOT be in state_changes when artifact is empty/None"
        )
        assert "session_authenticated" not in verdict.state_changes, (
            "Fix 3: session_authenticated must NOT be in state_changes when artifact is empty/None"
        )

    def test_real_artifact_includes_credential_fact(self):
        """F3-2: evaluate_verdict with real artifact → credential_obtained IS in state_changes."""
        from apps.conductor.leaf_evaluator import _evaluate_verdict
        from unittest.mock import patch

        fake_fields = {
            "state_changes":      ["credential_obtained", "session_authenticated"],
            "artifacts_captured": ["credentials", "sessions"],
            "unlocks":            [],
            "rules_out":          [],
        }
        real_artifact = {"artifact_type": "captured_session", "username": "carlos", "password": "secret"}
        with patch("apps.conductor.leaf_evaluator._load_concept_agent_fields",
                   return_value=fake_fields):
            verdict = _evaluate_verdict(
                engine_id  = "credential_brute",
                concept_id = "CONCEPT-CREDENTIAL-BRUTE",
                artifact   = real_artifact,   # REAL artifact
                state      = "succeeded",
                finding_id = "",
            )

        assert "credential_obtained" in verdict.state_changes, (
            "Fix 3: credential_obtained MUST be in state_changes when real artifact is captured"
        )
        assert "credentials" in verdict.artifacts_captured, (
            "Fix 3: credentials bucket must be populated in artifacts_captured"
        )

    def test_path_c_fact_and_bucket_consistent(self):
        """F3-3: after _apply_verdict_in_place with real capture, both fact and bucket are set."""
        from apps.conductor.agent_state import _apply_verdict_in_place, default_agent_state
        from apps.conductor.leaf_evaluator import _evaluate_verdict
        from unittest.mock import patch

        state = default_agent_state()
        state["goal"]["provided_self_user"] = "wiener"

        fake_fields = {
            "state_changes":      ["credential_obtained", "session_authenticated"],
            "artifacts_captured": ["credentials", "sessions"],
            "unlocks":            [],
            "rules_out":          [],
        }
        real_artifact = {"artifact_type": "captured_session", "username": "carlos", "password": "pw"}
        with patch("apps.conductor.leaf_evaluator._load_concept_agent_fields",
                   return_value=fake_fields):
            verdict = _evaluate_verdict("credential_brute", "CONCEPT-CREDENTIAL-BRUTE",
                                        real_artifact, "succeeded", "")

        _apply_verdict_in_place(state, verdict, "CONCEPT-CREDENTIAL-BRUTE", "credential_brute", "succeeded")

        # Both fact and bucket must be populated
        assert "credential_obtained" in state["facts"], (
            "credential_obtained fact must be in STATE when real credential captured"
        )
        creds = state["artifacts"]["credentials"]
        assert len(creds) == 1, "credential must land in artifacts.credentials bucket"
        assert creds[0].get("username") == "carlos"

    def test_fix3_comment_in_source(self):
        """F3: Fix 3 comment is present in leaf_evaluator.py."""
        src = _EVAL.read_text()
        assert "Fix 3" in src, "Fix 3 comment must be present in leaf_evaluator.py"
        assert "_CREDENTIAL_FACTS" in src, "_CREDENTIAL_FACTS frozenset must be defined"


# ── NEGATIVE — real discovered credential still solves ───────────────────────

class TestNegativeRealSolvesWork:

    def test_discovered_credential_solves_with_specific_message(self):
        """N1: genuine discovered target credential → SOLVED with specific message."""
        from apps.conductor.agent_state import check_success, default_agent_state
        state = default_agent_state()
        state["goal"]["success_conditions"] = ["valid_credentials_found"]
        state["goal"]["provided_self_user"] = "wiener"
        state["goal"]["target_user"]        = "carlos"
        state["artifacts"]["credentials"].append({
            "username": "carlos", "password": "secret", "origin": "discovered",
        })
        solved, reason = check_success(state)
        assert solved, "Genuine discovered credential for target must fire SOLVED"
        assert "carlos" in reason, f"Reason must name the discovered target; got: {reason!r}"

    def test_backward_compat_no_provided_self_set(self):
        """N2: no provided_self_user set → any capture is the objective (backward compat)."""
        from apps.conductor.agent_state import check_success, default_agent_state
        state = default_agent_state()
        state["goal"]["success_conditions"] = ["valid_credentials_found"]
        # No provided_self_user set — backward compat: any credential is the objective
        state["artifacts"]["credentials"].append({"username": "anyone", "password": "pw"})
        solved, _ = check_success(state)
        assert solved, "Backward compat: any credential fires SOLVED when no provided_self_user"

    def test_fix3_did_not_break_real_solve_end_to_end(self):
        """N3: full end-to-end: real capture lands BOTH fact AND bucket (fixes are paired)."""
        from apps.conductor.agent_state import _apply_verdict_in_place, check_success, default_agent_state
        from apps.conductor.leaf_evaluator import _evaluate_verdict
        from unittest.mock import patch

        state = default_agent_state()
        state["goal"]["success_conditions"] = ["valid_credentials_found"]
        # No provided_self — backward compat: any capture is the objective

        fake_fields = {
            "state_changes":      ["credential_obtained", "session_authenticated"],
            "artifacts_captured": ["credentials"],
            "unlocks":            [],
            "rules_out":          [],
        }
        real_artifact = {"artifact_type": "captured_session", "username": "found_target", "password": "pw"}
        with patch("apps.conductor.leaf_evaluator._load_concept_agent_fields",
                   return_value=fake_fields):
            verdict = _evaluate_verdict("credential_brute", "CONCEPT-CREDENTIAL-BRUTE",
                                        real_artifact, "succeeded", "")

        _apply_verdict_in_place(state, verdict, "CONCEPT-CREDENTIAL-BRUTE", "credential_brute", "succeeded")

        # Both fact and bucket populated (Fixes 2+3 are paired)
        assert "credential_obtained" in state["facts"]
        assert state["artifacts"]["credentials"]

        # check_success must fire SOLVED
        solved, reason = check_success(state)
        assert solved, "Real captured credential must fire SOLVED via the artifacts bucket path"
        assert "found_target" in reason, f"reason must include username; got: {reason!r}"


# ── NO HARDCODING ─────────────────────────────────────────────────────────────

class TestNoHardcoding:

    def test_no_hardcoded_usernames_agent_state(self):
        """HC1: no wiener/peter/carlos literals in agent_state.py code."""
        code = "\n".join(
            ln for ln in _AGENT.read_text().splitlines()
            if not ln.strip().startswith("#")
        )
        for name in ("wiener", "peter", "carlos"):
            assert name.lower() not in code.lower(), (
                f"Hardcoded username {name!r} in agent_state.py"
            )

    def test_no_hardcoded_usernames_leaf_evaluator(self):
        """HC1b: no wiener/peter/carlos literals in leaf_evaluator.py code."""
        code = "\n".join(
            ln for ln in _EVAL.read_text().splitlines()
            if not ln.strip().startswith("#")
        )
        for name in ("wiener", "peter", "carlos"):
            assert name.lower() not in code.lower(), (
                f"Hardcoded username {name!r} in leaf_evaluator.py"
            )

    def test_fix1_reads_from_operator_params_not_literals(self):
        """HC2: Fix 1 in planner_run reads provided_self_user from operator_params (no literals)."""
        src = _ROUTES.read_text()
        # The fix should reference operator_params, not a hardcoded string
        assert '_op.get("provided_self_user")' in src or \
               "operator_params.get(\"provided_self_user\")" in src or \
               "_op.get('provided_self_user')" in src, (
            "Fix 1 must read provided_self_user from operator_params dict, not hardcoded"
        )
        # No lab-specific usernames
        for name in ("wiener", "carlos", "peter"):
            assert name not in src[src.find("# Fix 1"):src.find("# Fix 1") + 1000].lower(), (
                f"Fix 1 must not hardcode {name!r}"
            )
