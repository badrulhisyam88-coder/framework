"""Phase B — Evaluator VERDICT tests.

V1. evaluate_verdict: known concept → match_kind="known", correct state_changes from vault.
V2. evaluate_verdict: known concept → unlocks populated from vault.
V3. evaluate_verdict: known concept + artifact → artifacts_captured mapped to correct bucket.
V4. evaluate_verdict: unknown concept → match_kind="no_concept_match".
V5. evaluate_verdict: empty concept_id → no_concept_match.
V6. Verdict.goal_advanced=True when state="succeeded".
V7. Verdict.goal_advanced=False when state="exhausted" and no artifact.
V8. evaluate_leaf() regression: still returns LeafClassification (behavior unchanged).
V9. Vault back-compat: concept without new fields still loads cleanly (no state_changes key → empty).
V10. _load_concept_agent_fields: credential-brute has state_changes from vault.
V11. _load_concept_agent_fields: concept without agent fields returns empty dict cleanly.
"""
from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import patch


class TestVerdict:
    """V1-V7: evaluate_verdict() produces correct VERDICT objects."""

    def _mock_concept_fields(self, state_changes=None, artifacts_captured=None, unlocks=None, rules_out=None):
        return {
            "state_changes":      state_changes or ["cred_obtained"],
            "artifacts_captured": artifacts_captured or ["credentials"],
            "unlocks":            unlocks or [{"concept": "CONCEPT-ACCESS-CONTROL", "priority": 80}],
            "rules_out":          rules_out or [],
        }

    def test_known_concept_returns_known_verdict(self):
        """V1: known concept → match_kind='known' and state_changes populated."""
        from apps.conductor.leaf_evaluator import evaluate_verdict
        with patch("apps.conductor.leaf_evaluator._load_concept_agent_fields",
                   return_value=self._mock_concept_fields(state_changes=["credential_obtained"])):
            v = evaluate_verdict(
                engine_id="credential_brute",
                concept_id="CONCEPT-CREDENTIAL-BRUTE",
                artifact={"username": "wiener", "password": "peter"},
                state="succeeded",
            )
        assert v.match_kind == "known"
        assert "credential_obtained" in v.state_changes

    def test_known_concept_returns_unlocks(self):
        """V2: known concept → unlocks populated from vault."""
        from apps.conductor.leaf_evaluator import evaluate_verdict
        with patch("apps.conductor.leaf_evaluator._load_concept_agent_fields",
                   return_value=self._mock_concept_fields(
                       unlocks=[{"concept": "CONCEPT-ACCESS-CONTROL", "priority": 80}])):
            v = evaluate_verdict("credential_brute", "CONCEPT-CREDENTIAL-BRUTE",
                                 artifact={"username": "w"}, state="succeeded")
        assert len(v.unlocks) == 1
        assert v.unlocks[0]["concept"] == "CONCEPT-ACCESS-CONTROL"
        assert v.unlocks[0]["priority"] == 80

    def test_artifact_mapped_to_bucket(self):
        """V3: artifact object mapped into artifacts_captured[bucket]."""
        from apps.conductor.leaf_evaluator import evaluate_verdict
        art = {"username": "wiener", "password": "peter"}
        with patch("apps.conductor.leaf_evaluator._load_concept_agent_fields",
                   return_value=self._mock_concept_fields(artifacts_captured=["credentials"])):
            v = evaluate_verdict("credential_brute", "CONCEPT-CREDENTIAL-BRUTE",
                                 artifact=art, state="succeeded")
        assert "credentials" in v.artifacts_captured
        assert v.artifacts_captured["credentials"] == art

    def test_unknown_concept_returns_no_concept_match(self):
        """V4: concept not in vault → match_kind='no_concept_match'."""
        from apps.conductor.leaf_evaluator import evaluate_verdict
        with patch("apps.conductor.leaf_evaluator._load_concept_agent_fields", return_value={}):
            v = evaluate_verdict("some_engine", "CONCEPT-DOES-NOT-EXIST",
                                 artifact=None, state="exhausted")
        assert v.match_kind == "no_concept_match"
        assert not v.goal_advanced
        assert v.state_changes == []
        assert v.unlocks == []

    def test_empty_concept_id_returns_no_concept_match(self):
        """V5: empty concept_id → no_concept_match immediately."""
        from apps.conductor.leaf_evaluator import evaluate_verdict
        v = evaluate_verdict("engine", "", artifact=None, state="exhausted")
        assert v.match_kind == "no_concept_match"

    def test_goal_advanced_true_on_succeeded(self):
        """V6: goal_advanced=True when state='succeeded'."""
        from apps.conductor.leaf_evaluator import evaluate_verdict
        with patch("apps.conductor.leaf_evaluator._load_concept_agent_fields",
                   return_value=self._mock_concept_fields()):
            v = evaluate_verdict("credential_brute", "CONCEPT-CREDENTIAL-BRUTE",
                                 artifact={"u": "w"}, state="succeeded")
        assert v.goal_advanced is True

    def test_goal_advanced_false_on_exhausted_no_artifact(self):
        """V7: goal_advanced=False when state='exhausted' and artifact=None."""
        from apps.conductor.leaf_evaluator import evaluate_verdict
        with patch("apps.conductor.leaf_evaluator._load_concept_agent_fields",
                   return_value=self._mock_concept_fields(artifacts_captured=[])):
            v = evaluate_verdict("credential_brute", "CONCEPT-CREDENTIAL-BRUTE",
                                 artifact=None, state="exhausted")
        assert v.goal_advanced is False


class TestLeafEvaluatorRegression:
    """V8: evaluate_leaf() behavior is unchanged (no regression)."""

    def test_evaluate_leaf_still_returns_leaf_classification(self):
        """V8: evaluate_leaf returns LeafClassification (existing behavior intact)."""
        from apps.conductor.leaf_evaluator import evaluate_leaf, LeafClassification
        with patch("apps.conductor.leaf_evaluator._evaluate") as mock_eval:
            mock_eval.return_value = LeafClassification(
                kind="inconclusive", concept_id="CONCEPT-X",
                reason="mocked", stem_engines=[], none_yet_gaps=[],
            )
            result = evaluate_leaf("engine", "CONCEPT-X", artifact=None, state="exhausted")
        assert isinstance(result, LeafClassification)
        assert result.kind == "inconclusive"

    def test_evaluate_leaf_never_returns_verdict(self):
        """V8b: evaluate_leaf never returns a Verdict — types are distinct."""
        from apps.conductor.leaf_evaluator import evaluate_leaf, LeafClassification, Verdict
        with patch("apps.conductor.leaf_evaluator._evaluate") as mock_eval:
            mock_eval.return_value = LeafClassification(
                kind="terminal", concept_id="C",
                reason="ok", stem_engines=[], none_yet_gaps=[],
            )
            result = evaluate_leaf("e", "C", None, "succeeded")
        assert isinstance(result, LeafClassification)
        assert not isinstance(result, Verdict)


class TestVaultBackCompat:
    """V9-V11: vault schema extension is backward-compatible."""

    def test_concept_without_new_fields_still_loads(self):
        """V9: concept file without state_changes/unlocks → _load_concept_agent_fields returns {}."""
        import tempfile, os
        from pathlib import Path as P
        md = "---\nid: CONCEPT-TEST\ntitle: Test\n---\n# Test\nNo agent fields.\n"
        with tempfile.TemporaryDirectory() as tmp:
            concepts_dir = P(tmp) / "concepts"
            concepts_dir.mkdir()
            (concepts_dir / "concept-test.md").write_text(md)
            with patch.dict(os.environ, {"KNOWLEDGE_VAULT_PATH": tmp}):
                from importlib import reload
                import apps.conductor.leaf_evaluator as lev
                reload(lev)
                result = lev._load_concept_agent_fields("CONCEPT-TEST")
        # Must not raise; returns empty or partial dict
        assert isinstance(result, dict)
        # All expected agent fields absent → evaluate_verdict would return no_concept_match
        assert result.get("state_changes", None) is None or result.get("state_changes", []) == []

    def test_credential_brute_concept_has_state_changes(self):
        """V10: concept-credential-brute.md has state_changes in vault (real file check)."""
        import os
        from pathlib import Path as P
        vault_path = P(os.environ.get("KNOWLEDGE_VAULT_PATH", "/app/knowledge-vault"))
        concept_path = vault_path / "concepts" / "concept-credential-brute.md"
        if not concept_path.exists():
            pytest.skip("vault not mounted — skipping live concept check")
        import yaml
        txt = concept_path.read_text()
        close = txt.find("\n---", 3)
        fm = yaml.safe_load(txt[3:close])
        assert "state_changes" in fm, "concept-credential-brute.md missing state_changes"
        assert isinstance(fm["state_changes"], list) and len(fm["state_changes"]) > 0
        assert "unlocks" in fm, "concept-credential-brute.md missing unlocks"

    def test_load_concept_agent_fields_missing_file_returns_empty(self):
        """V11: concept not on disk → {} returned cleanly, no exception."""
        import os
        with patch.dict(os.environ, {"KNOWLEDGE_VAULT_PATH": "/nonexistent/path"}):
            from apps.conductor.leaf_evaluator import _load_concept_agent_fields
            result = _load_concept_agent_fields("CONCEPT-NONEXISTENT")
        assert result == {}
