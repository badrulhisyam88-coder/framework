"""Phase 45 — Suggested next actions for findings.

The runtime does not auto-expand findings into attack branches. Instead,
each finding type carries a small static catalog of suggested next
actions; the operator picks one and the system kicks off a real
execution run for the chosen action.

This is the operator-guided branching model: the system reasons, then
the operator decides. Deterministic — same finding_type always offers
the same suggestions.
"""
