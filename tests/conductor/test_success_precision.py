"""Phase 2 — Success precision: objective-aware check_success.

Vocab conformance:
  VC1.  New goal fields (provided_self_user / target_user) use lowercase_underscore.
  VC2.  Credential artifact origin field: "provided" | "discovered" (strings, not enums).
  VC3.  valid_credentials_found success condition still present in _SUCCESS_PREDICATES.
  VC4.  No hardcoded lab usernames (wiener/peter/carlos) in agent_state source.

Tagging:
  T1.   _tag_credential_origin: provided_self_user set + match → origin=provided.
  T2.   _tag_credential_origin: provided_self_user set + no-match → origin=discovered.
  T3.   _tag_credential_origin: neither set → origin=discovered (backward compat).
  T4.   _tag_credential_origin: target_user matches → origin=discovered.
  T5.   Tagging is case-insensitive.

Discovered credential detection:
  DC1.  _has_discovered_credential: origin=discovered → True.
  DC2.  _has_discovered_credential: origin=provided only → False.
  DC3.  _has_discovered_credential: mixed provided + discovered → True.
  DC4.  _has_discovered_credential: no origin, no provided_self_user → True (backward compat).
  DC5.  _has_discovered_credential: empty credentials → False (falls to fact check).

Success check (the core fix):
  S1.   PROVIDED-ONLY capture → check_success does NOT fire SOLVED.
  S2.   DISCOVERED capture → check_success DOES fire SOLVED.
  S3.   The wiener:peter false-positive reproduced then fixed:
        provided_self_user=wiener, credential=(wiener,peter) → NOT solved.
  S4.   Discovered credential fires SOLVED with specific reason including username.
  S5.   No credentials at all → not solved.
  S6.   Fact-only (credential_obtained) + provided-only credentials → not solved.
  S7.   Ambiguous (no provided_self set) + credential present → solved (backward compat).

current_position fix:
  CP1.  provided-only credential capture → authentication stays "none".
  CP2.  discovered credential capture → authentication advances to "authenticated".

Zone C messaging:
  ZC1.  solved_reason includes the target username for discovered creds.
  ZC2.  solved_reason NOT set when only provided credential captured.

No hardcoding:
  HC1.  No "wiener" / "peter" / "carlos" in agent_state.py source (case-insensitive).
"""
from __future__ import annotations

import pytest
from pathlib import Path

_SRC = Path(__file__).resolve().parents[2] / "apps/conductor/agent_state.py"


# ── Vocab conformance ─────────────────────────────────────────────────────────

class TestVocabConformance:

    def test_goal_fields_lowercase_underscore(self):
        """VC1: new goal fields use lowercase_underscore (not camelCase)."""
        src = _SRC.read_text()
        assert "provided_self_user" in src
        assert "target_user" in src
        # NOT camelCase
        assert "providedSelfUser" not in src
        assert "targetUser" not in src

    def test_origin_values_are_strings(self):
        """VC2: origin values are plain strings 'provided' and 'discovered'."""
        src = _SRC.read_text()
        assert '"provided"' in src or "'provided'" in src
        assert '"discovered"' in src or "'discovered'" in src

    def test_valid_credentials_found_in_predicates(self):
        """VC3: valid_credentials_found predicate still exists."""
        src = _SRC.read_text()
        assert "valid_credentials_found" in src
        assert "_SUCCESS_PREDICATES" in src

    def test_no_hardcoded_lab_usernames(self):
        """VC4: no hardcoded lab usernames in agent_state."""
        src = _SRC.read_text()
        # Strip comment lines to avoid false positives from diagnostic notes
        code_lines = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))
        for name in ("wiener", "peter", "carlos"):
            assert name.lower() not in code_lines.lower(), (
                f"hardcoded lab username {name!r} found in agent_state.py"
            )


# ── Tagging ───────────────────────────────────────────────────────────────────

class TestTagging:

    def test_provided_self_match(self):
        """T1: username matches provided_self_user → origin=provided."""
        from apps.conductor.agent_state import _tag_credential_origin
        goal = {"provided_self_user": "alice", "target_user": None}
        result = _tag_credential_origin({"username": "alice", "password": "pw"}, goal)
        assert result["origin"] == "provided"

    def test_provided_self_no_match(self):
        """T2: username does NOT match provided_self_user → origin=discovered."""
        from apps.conductor.agent_state import _tag_credential_origin
        goal = {"provided_self_user": "alice", "target_user": None}
        result = _tag_credential_origin({"username": "bob", "password": "pw"}, goal)
        assert result["origin"] == "discovered"

    def test_no_context_backward_compat(self):
        """T3: no provided_self_user or target_user → origin=discovered (backward compat)."""
        from apps.conductor.agent_state import _tag_credential_origin
        goal = {"provided_self_user": None, "target_user": None}
        result = _tag_credential_origin({"username": "anyone", "password": "pw"}, goal)
        assert result["origin"] == "discovered"

    def test_target_user_match(self):
        """T4: username matches target_user → origin=discovered."""
        from apps.conductor.agent_state import _tag_credential_origin
        goal = {"provided_self_user": "alice", "target_user": "bob"}
        result = _tag_credential_origin({"username": "bob", "password": "pw"}, goal)
        assert result["origin"] == "discovered"

    def test_case_insensitive(self):
        """T5: tagging is case-insensitive."""
        from apps.conductor.agent_state import _tag_credential_origin
        goal = {"provided_self_user": "Alice", "target_user": None}
        result_lower = _tag_credential_origin({"username": "alice", "password": "pw"}, goal)
        result_upper = _tag_credential_origin({"username": "ALICE", "password": "pw"}, goal)
        assert result_lower["origin"] == "provided"
        assert result_upper["origin"] == "provided"

    def test_original_dict_unchanged(self):
        """T5b: tagging returns a new dict; original is unchanged."""
        from apps.conductor.agent_state import _tag_credential_origin
        original = {"username": "alice", "password": "pw"}
        goal = {"provided_self_user": "alice"}
        result = _tag_credential_origin(original, goal)
        assert "origin" not in original, "original dict must not be mutated"
        assert result is not original


# ── Discovered credential detection ──────────────────────────────────────────

class TestDiscoveredCredentialDetection:

    def _make_state(self, creds, provided_self=None, facts=None):
        from apps.conductor.agent_state import default_agent_state
        s = default_agent_state()
        s["artifacts"]["credentials"] = creds
        if provided_self:
            s["goal"]["provided_self_user"] = provided_self
        if facts:
            s["facts"] = facts
        return s

    def test_discovered_origin_true(self):
        """DC1: origin=discovered → True."""
        from apps.conductor.agent_state import _has_discovered_credential
        s = self._make_state([{"username": "bob", "password": "pw", "origin": "discovered"}])
        assert _has_discovered_credential(s)

    def test_provided_only_false(self):
        """DC2: origin=provided only → False."""
        from apps.conductor.agent_state import _has_discovered_credential
        s = self._make_state([{"username": "alice", "password": "pw", "origin": "provided"}],
                              provided_self="alice")
        assert not _has_discovered_credential(s)

    def test_mixed_provided_discovered_true(self):
        """DC3: mixed provided + discovered → True."""
        from apps.conductor.agent_state import _has_discovered_credential
        s = self._make_state([
            {"username": "alice", "password": "pw", "origin": "provided"},
            {"username": "bob",   "password": "pw", "origin": "discovered"},
        ], provided_self="alice")
        assert _has_discovered_credential(s)

    def test_no_origin_no_provided_self_backward_compat(self):
        """DC4: no origin tag, no provided_self → True (backward compat)."""
        from apps.conductor.agent_state import _has_discovered_credential
        s = self._make_state([{"username": "anyone", "password": "pw"}])
        assert _has_discovered_credential(s)

    def test_empty_credentials_uses_fact(self):
        """DC5: Fix 2 — empty credentials list + credential_obtained fact → False.
        The fact-fallback was removed; a classifiable credential object is required.
        """
        from apps.conductor.agent_state import _has_discovered_credential
        s = self._make_state([], facts=["credential_obtained"])
        # Fix 2: fact alone is no longer sufficient — must have classifiable credential
        assert not _has_discovered_credential(s), (
            "Fix 2: empty credentials + credential_obtained fact must return False"
        )

    def test_empty_credentials_no_fact_false(self):
        """DC5b: empty credentials + no fact → False."""
        from apps.conductor.agent_state import _has_discovered_credential
        s = self._make_state([])
        assert not _has_discovered_credential(s)


# ── Success check (the core fix) ──────────────────────────────────────────────

class TestSuccessCheckObjectiveAware:

    def _state_with_cred(self, username, origin, provided_self=None, target_user=None):
        from apps.conductor.agent_state import default_agent_state
        s = default_agent_state()
        s["goal"]["success_conditions"] = ["valid_credentials_found"]
        if provided_self:
            s["goal"]["provided_self_user"] = provided_self
        if target_user:
            s["goal"]["target_user"] = target_user
        s["artifacts"]["credentials"].append({
            "username": username, "password": "pw", "origin": origin,
        })
        return s

    def test_provided_only_not_solved(self):
        """S1: provided-only credential → NOT solved."""
        from apps.conductor.agent_state import check_success
        s = self._state_with_cred("alice", "provided", provided_self="alice")
        solved, _ = check_success(s)
        assert not solved, "provided-only credential must NOT satisfy valid_credentials_found"

    def test_discovered_credential_solved(self):
        """S2: discovered credential → SOLVED."""
        from apps.conductor.agent_state import check_success
        s = self._state_with_cred("bob", "discovered", provided_self="alice")
        solved, reason = check_success(s)
        assert solved, "discovered credential must satisfy valid_credentials_found"
        assert "bob" in reason, f"reason must include discovered username; got: {reason!r}"

    def test_wiener_peter_false_positive_fixed(self):
        """S3: THE CORE FIX — wiener:peter as provided self-login does NOT fire SOLVED.

        Reproduces the previously-observed false positive, then verifies it's now fixed.
        Before fix: brute finding wiener:peter → SOLVED (wrong; wiener:peter = provided creds).
        After fix: SOLVED only fires when a non-provided credential is discovered.
        """
        from apps.conductor.agent_state import check_success
        s = {
            "goal": {
                "objective": "obtain credentials / access",
                "success_conditions": ["valid_credentials_found"],
                "provided_self_user": "wiener",  # operator's own account, NOT the objective
                "target_user": None,
            },
            "facts": ["credential_obtained"],  # fact was set (old behavior)
            "artifacts": {
                "credentials": [{
                    "username": "wiener", "password": "peter",
                    "origin": "provided",  # tagged as provided self-login
                }],
                "sessions": [], "tokens": [], "files": [],
            },
            "current_position": {"authentication": "none", "privilege": "none",
                                  "access_scope": [], "execution": "none"},
        }
        solved, reason = check_success(s)
        assert not solved, (
            "wiener:peter (provided self-login) must NOT satisfy valid_credentials_found — "
            f"this was the false-positive that masked real verification. reason={reason!r}"
        )

    def test_solved_reason_specific(self):
        """S4: discovered credential fires SOLVED with reason including username."""
        from apps.conductor.agent_state import check_success
        s = self._state_with_cred("carlos", "discovered", provided_self="wiener")
        solved, reason = check_success(s)
        assert solved
        assert "carlos" in reason.lower(), (
            f"solved reason must include discovered username 'carlos'; got: {reason!r}"
        )

    def test_no_credentials_not_solved(self):
        """S5: no credentials → not solved."""
        from apps.conductor.agent_state import check_success, default_agent_state
        s = default_agent_state()
        s["goal"]["success_conditions"] = ["valid_credentials_found"]
        solved, _ = check_success(s)
        assert not solved

    def test_fact_only_with_provided_credential_not_solved(self):
        """S6: fact + provided-only credential → not solved (fact alone not sufficient)."""
        from apps.conductor.agent_state import check_success
        s = self._state_with_cred("wiener", "provided", provided_self="wiener")
        # The fact was set too
        s["facts"].append("credential_obtained")
        solved, _ = check_success(s)
        assert not solved, (
            "credential_obtained fact + provided-only credential must NOT solve"
        )

    def test_ambiguous_no_provided_self_solves(self):
        """S7: no provided_self set + credential present → solved (backward compat)."""
        from apps.conductor.agent_state import check_success, default_agent_state
        s = default_agent_state()
        s["goal"]["success_conditions"] = ["valid_credentials_found"]
        s["artifacts"]["credentials"].append({"username": "someone", "password": "pw"})
        # No provided_self_user set — backward compat: any capture is the objective
        solved, _ = check_success(s)
        assert solved, "when no provided_self_user is set, any capture satisfies the objective"


# ── current_position fix ──────────────────────────────────────────────────────

class TestCurrentPositionFix:

    def _apply_with_cred(self, username, origin, provided_self=None):
        from dataclasses import dataclass
        from apps.conductor.agent_state import _apply_verdict_in_place, default_agent_state

        @dataclass
        class _V:
            match_kind:         str  = "known"
            goal_advanced:      bool = True
            state_changes:      list = None
            artifacts_captured: dict = None
            unlocks:            list = None
            rules_out:          list = None
            def __post_init__(self):
                if self.state_changes is None:
                    self.state_changes = ["credential_obtained", "session_authenticated"]
                if self.artifacts_captured is None:
                    self.artifacts_captured = {
                        "credentials": {"username": username, "password": "pw", "origin": origin},
                        "sessions": {"username": username, "password": "pw", "origin": origin},
                    }
                if self.unlocks is None:
                    self.unlocks = []
                if self.rules_out is None:
                    self.rules_out = []

        state = default_agent_state()
        state["goal"]["success_conditions"] = ["valid_credentials_found"]
        if provided_self:
            state["goal"]["provided_self_user"] = provided_self
        _apply_verdict_in_place(
            state, _V(), "CONCEPT-CREDENTIAL-BRUTE", "credential_brute", "succeeded"
        )
        return state

    def test_provided_credential_auth_stays_none(self):
        """CP1: provided credential → authentication stays 'none'."""
        state = self._apply_with_cred("wiener", "provided", provided_self="wiener")
        auth = state["current_position"]["authentication"]
        assert auth == "none", (
            f"authentication must not advance on provided self-login; got {auth!r}"
        )

    def test_discovered_credential_auth_advances(self):
        """CP2: discovered credential → authentication advances to 'authenticated'."""
        state = self._apply_with_cred("carlos", "discovered", provided_self="wiener")
        auth = state["current_position"]["authentication"]
        assert auth == "authenticated", (
            f"authentication must advance to 'authenticated' for discovered credential; got {auth!r}"
        )


# ── Zone C messaging ──────────────────────────────────────────────────────────

class TestZoneCMessaging:

    def test_solved_reason_includes_username(self):
        """ZC1: solved_reason includes the discovered username."""
        from apps.conductor.agent_state import _apply_verdict_in_place, default_agent_state
        from dataclasses import dataclass

        @dataclass
        class _V:
            match_kind:         str  = "known"
            goal_advanced:      bool = True
            state_changes:      list = None
            artifacts_captured: dict = None
            unlocks:            list = None
            rules_out:          list = None
            def __post_init__(self):
                if self.state_changes is None: self.state_changes = ["credential_obtained"]
                if self.artifacts_captured is None:
                    self.artifacts_captured = {
                        "credentials": {"username": "target_victim", "password": "pw", "origin": "discovered"},
                    }
                if self.unlocks is None: self.unlocks = []
                if self.rules_out is None: self.rules_out = []

        state = default_agent_state()
        state["goal"]["success_conditions"] = ["valid_credentials_found"]
        state["goal"]["provided_self_user"] = "operator_self"
        _apply_verdict_in_place(state, _V(), "CONCEPT-CREDENTIAL-BRUTE", "cred_brute", "succeeded")

        assert state.get("solved") is True
        reason = state.get("solved_reason", "")
        assert "target_victim" in reason, (
            f"solved_reason must include the discovered target username; got: {reason!r}"
        )

    def test_provided_only_no_solved_reason(self):
        """ZC2: provided-only credential capture → solved NOT set → no solved_reason."""
        from apps.conductor.agent_state import _apply_verdict_in_place, default_agent_state
        from dataclasses import dataclass

        @dataclass
        class _V:
            match_kind:         str  = "known"
            goal_advanced:      bool = True
            state_changes:      list = None
            artifacts_captured: dict = None
            unlocks:            list = None
            rules_out:          list = None
            def __post_init__(self):
                if self.state_changes is None: self.state_changes = ["credential_obtained"]
                if self.artifacts_captured is None:
                    self.artifacts_captured = {
                        "credentials": {"username": "provided_self", "password": "pw", "origin": "provided"},
                    }
                if self.unlocks is None: self.unlocks = []
                if self.rules_out is None: self.rules_out = []

        state = default_agent_state()
        state["goal"]["success_conditions"] = ["valid_credentials_found"]
        state["goal"]["provided_self_user"] = "provided_self"
        _apply_verdict_in_place(state, _V(), "CONCEPT-CREDENTIAL-BRUTE", "cred_brute", "succeeded")

        assert not state.get("solved"), (
            "provided-only credential must NOT set solved=True"
        )
        assert not state.get("solved_reason"), "no solved_reason when not solved"


# ── No hardcoding ─────────────────────────────────────────────────────────────

class TestNoHardcoding:

    def test_no_lab_usernames_in_source(self):
        """HC1: agent_state.py has no hardcoded lab-specific usernames."""
        src = _SRC.read_text()
        code = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))
        for name in ("wiener", "peter", "carlos"):
            assert name.lower() not in code.lower(), (
                f"hardcoded lab username {name!r} found in agent_state.py"
            )
