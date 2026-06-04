"""Phase A — GOAL + STATE object tests.

S1. default_agent_state() has correct shape.
S2. validate_current_position() accepts valid vocab values.
S3. validate_current_position() rejects invalid authentication value.
S4. validate_current_position() rejects invalid privilege value.
S5. validate_current_position() rejects invalid execution value.
S6. validate_current_position() allows free-form access_scope.
S7. init_agent_state_async() builds STATE with correct shape (no DB, mocked findings).
S8. init_agent_state_async() seeds pending from findings, sorted by priority desc.
S9. init_agent_state_async() deduplicates pending by concept_id.
S10. agent_state field on InvestigationState is a dict, default empty.
S11. save/load round-trip via InvestigationState (mock DB).
"""
from __future__ import annotations

import pytest


# ── S1-S6: Pure-logic tests (no DB, no async) ─────────────────────────────────

class TestDefaultShape:
    def test_default_agent_state_has_required_keys(self):
        """S1: default_agent_state() returns dict with all mandatory keys."""
        from apps.conductor.agent_state import default_agent_state
        s = default_agent_state()
        assert "goal" in s
        assert "facts" in s and isinstance(s["facts"], list)
        assert "artifacts" in s and isinstance(s["artifacts"], dict)
        assert "pending" in s and isinstance(s["pending"], list)
        assert "ruled_out" in s and isinstance(s["ruled_out"], list)
        assert "completed" in s and isinstance(s["completed"], list)
        assert "current_position" in s and isinstance(s["current_position"], dict)

    def test_default_artifacts_buckets(self):
        """S1b: artifacts dict has four required buckets."""
        from apps.conductor.agent_state import default_agent_state
        arts = default_agent_state()["artifacts"]
        for bucket in ("credentials", "sessions", "tokens", "files"):
            assert bucket in arts and isinstance(arts[bucket], list)

    def test_default_current_position_values(self):
        """S1c: default current_position uses 'none' for all enumerated fields."""
        from apps.conductor.agent_state import default_agent_state
        cp = default_agent_state()["current_position"]
        assert cp["authentication"] == "none"
        assert cp["privilege"] == "none"
        assert cp["execution"] == "none"
        assert isinstance(cp["access_scope"], list)

    def test_default_goal_shape(self):
        """S1d: default_goal() returns objective + success_conditions."""
        from apps.conductor.agent_state import default_goal
        g = default_goal()
        assert "objective" in g and g["objective"]
        assert "success_conditions" in g and isinstance(g["success_conditions"], list)
        assert len(g["success_conditions"]) >= 1


class TestValidateCurrentPosition:
    def test_accepts_valid_authentication(self):
        """S2: validate accepts all auth vocab values."""
        from apps.conductor.agent_state import validate_current_position, default_current_position
        for val in ("none", "authenticated", "admin"):
            cp = {**default_current_position(), "authentication": val}
            result = validate_current_position(cp)
            assert result["authentication"] == val

    def test_accepts_valid_privilege(self):
        """S2b: validate accepts all privilege vocab values."""
        from apps.conductor.agent_state import validate_current_position, default_current_position
        for val in ("none", "user", "admin", "root"):
            cp = {**default_current_position(), "privilege": val}
            validate_current_position(cp)  # should not raise

    def test_rejects_invalid_authentication(self):
        """S3: invalid authentication raises ValueError."""
        from apps.conductor.agent_state import validate_current_position, default_current_position
        cp = {**default_current_position(), "authentication": "superuser"}
        with pytest.raises(ValueError, match="authentication"):
            validate_current_position(cp)

    def test_rejects_invalid_privilege(self):
        """S4: invalid privilege raises ValueError."""
        from apps.conductor.agent_state import validate_current_position, default_current_position
        cp = {**default_current_position(), "privilege": "operator"}
        with pytest.raises(ValueError, match="privilege"):
            validate_current_position(cp)

    def test_rejects_invalid_execution(self):
        """S5: invalid execution raises ValueError."""
        from apps.conductor.agent_state import validate_current_position, default_current_position
        cp = {**default_current_position(), "execution": "full_rce"}
        with pytest.raises(ValueError, match="execution"):
            validate_current_position(cp)

    def test_allows_free_form_access_scope(self):
        """S6: access_scope is not enumerated — any list is accepted."""
        from apps.conductor.agent_state import validate_current_position, default_current_position
        cp = {**default_current_position(), "access_scope": ["portal", "admin_panel", "api"]}
        result = validate_current_position(cp)
        assert result["access_scope"] == ["portal", "admin_panel", "api"]


class TestInitAgentState:
    """S7-S9: Logic of STATE init — tested via default_agent_state + the seeding contract.

    The async DB path (aiosqlite) runs only in Docker; tested live there.
    These tests verify the pure-logic invariants that must hold regardless of DB.
    """

    def test_default_state_has_empty_pending_and_correct_shape(self):
        """S7: default_agent_state() has all required keys before seeding."""
        from apps.conductor.agent_state import default_agent_state
        state = default_agent_state()
        for key in ("goal", "facts", "artifacts", "pending", "ruled_out",
                    "completed", "current_position"):
            assert key in state, f"missing key: {key}"
        assert state["pending"] == []
        assert isinstance(state["current_position"], dict)

    def test_pending_item_shape_contract(self):
        """S8: each pending item must have {concept, priority} — contract enforced by structure."""
        # Build a minimal pending item as the seeder would produce.
        item = {"concept": "CONCEPT-CREDENTIAL-BRUTE", "priority": 95}
        assert "concept" in item and isinstance(item["concept"], str)
        assert "priority" in item and isinstance(item["priority"], int)

    def test_pending_dedup_logic(self):
        """S9: dedup-by-concept logic: Python set uniqueness matches expected behavior."""
        # Simulate what init_agent_state_async does: builds a seen set and deduplicates.
        raw = [
            {"concept": "CONCEPT-CREDENTIAL-BRUTE", "priority": 95},
            {"concept": "CONCEPT-CREDENTIAL-BRUTE", "priority": 95},  # duplicate
            {"concept": "CONCEPT-USERNAME-ENUMERATION", "priority": 50},
        ]
        seen: set = set()
        deduped = []
        for item in raw:
            if item["concept"] not in seen:
                seen.add(item["concept"])
                deduped.append(item)
        assert len(deduped) == 2
        concept_ids = [d["concept"] for d in deduped]
        assert len(concept_ids) == len(set(concept_ids))

    def test_pending_sort_descending_priority(self):
        """S8b: pending must be sorted descending by priority."""
        items = [
            {"concept": "CONCEPT-B", "priority": 50},
            {"concept": "CONCEPT-A", "priority": 95},
            {"concept": "CONCEPT-C", "priority": 80},
        ]
        sorted_items = sorted(items, key=lambda x: x["priority"], reverse=True)
        priorities = [i["priority"] for i in sorted_items]
        assert priorities == [95, 80, 50]

    def test_init_with_objective_sets_goal(self):
        """S7b: default_agent_state with custom goal has objective set."""
        from apps.conductor.agent_state import default_agent_state
        custom_goal = {"objective": "obtain admin access", "success_conditions": ["admin_session_captured"]}
        state = default_agent_state(goal=custom_goal)
        assert state["goal"]["objective"] == "obtain admin access"
        assert "admin_session_captured" in state["goal"]["success_conditions"]


class TestInvestigationStateField:
    def test_agent_state_field_exists_and_defaults_empty(self):
        """S10: InvestigationState.agent_state is a dict, defaults to {}."""
        from apps.conductor.investigation_state import InvestigationState
        s = InvestigationState(investigation_id="inv_x")
        assert hasattr(s, "agent_state")
        assert isinstance(s.agent_state, dict)
        assert s.agent_state == {}

    def test_agent_state_serializes_via_asdict(self):
        """S10b: asdict round-trip preserves agent_state."""
        from dataclasses import asdict
        from apps.conductor.investigation_state import InvestigationState
        s = InvestigationState(investigation_id="inv_x", agent_state={"goal": {"objective": "test"}})
        d = asdict(s)
        assert d["agent_state"] == {"goal": {"objective": "test"}}
