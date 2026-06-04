"""Seam 6: RuleResult.evidence_gap() does NOT terminate the rule chain.

Pattern: EVIDENCE-GAP NON-TERMINATION
  Bug risk: A future refactor of FilterOrchestrator._evaluate() could treat
  is_evidence_gap=True as first-match-wins, returning immediately when a gap
  rule fires. This would silently leave all gap-blocked findings as 'pending'
  even when a later rule can still classify them.

  Test assertion: After an evidence_gap rule fires, subsequent rules must still
  be evaluated. The chain terminates only on a non-gap matched result.

REGRESSION INDICATOR: If _evaluate() is changed to return early on is_evidence_gap:
  - test_chain_continues_after_evidence_gap: status would be None, not "validated"
  - test_regression_evidence_gap_not_first_match_wins: same — "dropped" becomes None
"""
from __future__ import annotations

from unittest.mock import patch

from apps.conductor.events.bus import EventBus
from apps.conductor.orchestrators.filter import FilterOrchestrator
from apps.conductor.rules.base import RuleResult


def _gap(reason: str = "field missing"):
    class R:
        id = "mock_gap"
        def evaluate(self, f, af): return RuleResult.evidence_gap(reason)
    return R()


def _classify(status: str, reason: str = "classified"):
    class R:
        id = f"mock_{status}"
        def evaluate(self, f, af): return RuleResult(matched=True, status=status, reason=reason)
    return R()


def _no_match():
    class R:
        id = "mock_no_match"
        def evaluate(self, f, af): return RuleResult(matched=False)
    return R()


def _finding():
    return {"id": "fnd_test001", "category": "service_detected", "evidence": {}}


def _filter():
    return FilterOrchestrator("inv-test", EventBus())


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_chain_continues_after_evidence_gap():
    """Positive baseline: [gap, validate]. Validate fires; both status and block_reason set."""
    chain = [_gap("service_version missing"), _classify("validated")]
    with patch("apps.conductor.orchestrators.filter.REGISTERED_RULES", chain):
        status, reason, gaps, block_reason = _filter()._evaluate(_finding(), [])

    assert status == "validated"
    assert block_reason == "service_version missing"


def test_regression_evidence_gap_not_first_match_wins():
    """Regression guard: evidence_gap MUST NOT terminate the chain.

    Chain: [gap, no_match, drop]. If _evaluate returned early on is_evidence_gap,
    status would be None. This assertion catches that regression immediately.
    """
    chain = [_gap("evidence absent"), _no_match(), _classify("dropped")]
    with patch("apps.conductor.orchestrators.filter.REGISTERED_RULES", chain):
        status, _, _, _ = _filter()._evaluate(_finding(), [])

    assert status == "dropped", (
        "evidence_gap terminated the chain — status is None instead of 'dropped'. "
        "Check _evaluate() for early return on is_evidence_gap=True."
    )


def test_multiple_evidence_gaps_first_gap_reason_captured():
    """Two gap rules, no classify rule. Only the first gap reason is stored.

    Current implementation ('if block_reason is None: block_reason = result.reason'):
    subsequent gap reasons are silently discarded. Status remains None (pending).
    This documents the actual behavior; a future change to accumulate all gaps
    would need to update this test and _evaluate() together.
    """
    chain = [_gap("gap 1"), _gap("gap 2"), _no_match()]
    with patch("apps.conductor.orchestrators.filter.REGISTERED_RULES", chain):
        status, _, _, block_reason = _filter()._evaluate(_finding(), [])

    assert status is None
    assert block_reason == "gap 1"


def test_gap_and_classify_both_recorded():
    """Chain: [gap, classify]. Result carries BOTH the classify outcome AND the gap reason.

    A gap-blocked finding classified by a later rule gets both validation_status
    (from classify) and enumeration_block_reason (from gap) in the returned tuple.
    """
    chain = [_gap("missing evidence"), _classify("incomplete", "needs operator input")]
    with patch("apps.conductor.orchestrators.filter.REGISTERED_RULES", chain):
        status, reason, gaps, block_reason = _filter()._evaluate(_finding(), [])

    assert status == "incomplete"
    assert reason == "needs operator input"
    assert block_reason == "missing evidence"
