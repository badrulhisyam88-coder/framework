"""Branch state derivation (Phase 19 Part E).

Pure functions — no I/O, no autonomy. Given the existing lifecycle / evidence
/ milestone / defensive-snapshot signals, derive the visible BranchState for
each node. Every transition carries an explicit `why` so the operator can
audit the rendering.

State precedence (higher overrides lower):

    locked < available < active < completed < evidence_attached
                                            < remediation_pending
                                            < regression
"""
from __future__ import annotations

from dataclasses import dataclass

from apps.investigation_workspace.branch.model import BranchState

# Precedence ordering used when a node has multiple signals. Higher index
# wins, mirroring the ordering in the BranchState enum docstring.
_STATE_PRECEDENCE: dict[BranchState, int] = {
    BranchState.LOCKED:               0,
    BranchState.AVAILABLE:            1,
    BranchState.ACTIVE:               2,
    BranchState.COMPLETED:            3,
    BranchState.EVIDENCE_ATTACHED:    4,
    BranchState.REMEDIATION_PENDING:  5,
    BranchState.VERIFICATION_RUNNING: 6,
    BranchState.VERIFIED:             7,
    BranchState.REGRESSION:           8,
}


@dataclass(frozen=True)
class StateDerivation:
    """Result of a state computation — state + the rationale."""

    state: BranchState
    why: str


def derive_action_state(
    *,
    lifecycle_state: str | None,
    evidence_count: int,
    parent_unlocked: bool,
) -> StateDerivation:
    """Map an action's lifecycle state into a branch state.

    Inputs come from the existing `feed/lifecycle.py` derivation:
        not_started | in_progress | evidence_captured | completed | abandoned
    """
    if not parent_unlocked:
        return StateDerivation(
            BranchState.LOCKED,
            why="Parent investigation step not yet completed.",
        )
    if lifecycle_state in (None, "not_started"):
        return StateDerivation(
            BranchState.AVAILABLE,
            why="Action recommended for this finding but not yet approved.",
        )
    if lifecycle_state == "in_progress":
        return StateDerivation(
            BranchState.ACTIVE,
            why="Action approved; guidance is open and awaiting evidence.",
        )
    if lifecycle_state == "evidence_captured":
        return StateDerivation(
            BranchState.EVIDENCE_ATTACHED,
            why=f"Captured {evidence_count} evidence artifact(s) for this step.",
        )
    if lifecycle_state == "completed":
        if evidence_count > 0:
            return StateDerivation(
                BranchState.EVIDENCE_ATTACHED,
                why=f"Step completed with {evidence_count} evidence artifact(s).",
            )
        return StateDerivation(
            BranchState.COMPLETED,
            why="Step marked complete (no evidence artifact attached).",
        )
    if lifecycle_state == "abandoned":
        return StateDerivation(
            BranchState.AVAILABLE,
            why="Step was abandoned; can be re-approved.",
        )
    return StateDerivation(
        BranchState.AVAILABLE,
        why="Default state — no lifecycle signal recorded.",
    )


def derive_milestone_state(*, achieved: bool, parent_unlocked: bool) -> StateDerivation:
    """Milestones either confirm an objective or remain available."""
    if not parent_unlocked:
        return StateDerivation(
            BranchState.LOCKED,
            why="Milestone gated by an upstream investigation step.",
        )
    if achieved:
        return StateDerivation(
            BranchState.EVIDENCE_ATTACHED,
            why="Operator confirmed this CTF / lab objective.",
        )
    return StateDerivation(
        BranchState.AVAILABLE,
        why="Objective offered; operator has not yet marked it achieved.",
    )


def derive_remediation_state(
    *,
    is_documented: bool,
    approval_status: str | None,
    evidence_count: int,
    has_regression: bool,
) -> StateDerivation:
    """Phase 21 — remediation branch lifecycle (defensive verification flow).

    Inputs (all deterministic, from existing data):
      - is_documented:    cluster_id has a CLUSTER_TO_DEFENSIVE_ACTIONS entry
      - approval_status:  ApprovalService status for the defensive action_id
                          (None | 'pending' | 'approved' | 'completed' | 'rejected')
      - evidence_count:   artifacts captured against this action_id
      - has_regression:   action_id appears in the regression set computed
                          from PostureComparison.regressed themes

    State precedence:
      has_regression                  → REGRESSION       (always wins)
      approval.completed              → VERIFIED
      approval.approved               → VERIFICATION_RUNNING
      approval.pending / no approval  → REMEDIATION_PENDING (verification_pending)
      not documented                  → AVAILABLE
    """
    if has_regression:
        return StateDerivation(
            BranchState.REGRESSION,
            why="Posture snapshot comparison detected regression on this defensive action's theme.",
        )
    if approval_status == "completed":
        return StateDerivation(
            BranchState.VERIFIED,
            why=(
                f"Verification marked complete with {evidence_count} evidence artifact(s)."
                if evidence_count > 0
                else "Verification marked complete (no evidence artifact attached)."
            ),
        )
    if approval_status == "approved":
        return StateDerivation(
            BranchState.VERIFICATION_RUNNING,
            why=(
                f"Verification approved; {evidence_count} evidence artifact(s) so far."
                if evidence_count > 0
                else "Verification approved; awaiting evidence."
            ),
        )
    if is_documented:
        return StateDerivation(
            BranchState.REMEDIATION_PENDING,
            why="Remediation concept documented; defensive verification not yet started.",
        )
    return StateDerivation(
        BranchState.AVAILABLE,
        why="Remediation branch open; operator has not yet engaged.",
    )


def derive_discovery_state(*, child_states: list[BranchState]) -> StateDerivation:
    """A discovery node's aggregate state is the strongest signal from its
    immediate children (actions / milestones / remediation)."""
    if not child_states:
        return StateDerivation(
            BranchState.AVAILABLE,
            why="Discovery has no recommended steps wired up yet.",
        )
    strongest = max(child_states, key=lambda s: _STATE_PRECEDENCE[s])
    why_lookup = {
        BranchState.REGRESSION:           "A downstream remediation regressed.",
        BranchState.VERIFIED:             "At least one downstream remediation is verified.",
        BranchState.VERIFICATION_RUNNING: "A downstream verification is in progress.",
        BranchState.REMEDIATION_PENDING:  "Remediation guidance is open for this discovery.",
        BranchState.EVIDENCE_ATTACHED:    "Evidence captured for at least one downstream step.",
        BranchState.COMPLETED:            "All downstream steps marked complete.",
        BranchState.ACTIVE:               "At least one downstream step is in progress.",
        BranchState.AVAILABLE:            "Steps recommended but none started.",
        BranchState.LOCKED:               "All downstream steps are gated.",
    }
    return StateDerivation(
        strongest,
        why=why_lookup[strongest],
    )


def aggregate_branch_state(node_states: list[BranchState]) -> BranchState:
    """Top-of-branch aggregate — used for the branch badge."""
    if not node_states:
        return BranchState.AVAILABLE
    return max(node_states, key=lambda s: _STATE_PRECEDENCE[s])


def state_badge_text(state: BranchState) -> str:
    """Phase 33 — plain-English operator-facing state label.

    Single source of truth. Replaces engineering enum names with human
    vocabulary the operator can read at a glance. Internal `state.value`
    still drives CSS data-state attributes (styling), but no operator-
    facing surface should render the raw enum value anymore.
    """
    return {
        BranchState.LOCKED:               "Locked",
        BranchState.AVAILABLE:            "Ready",
        BranchState.ACTIVE:               "In progress",
        BranchState.COMPLETED:            "Done",
        BranchState.EVIDENCE_ATTACHED:    "Evidence captured",
        BranchState.REMEDIATION_PENDING:  "Needs verification",
        BranchState.VERIFICATION_RUNNING: "Verifying",
        BranchState.VERIFIED:             "Verified",
        BranchState.REGRESSION:           "Regressed",
    }[state]


def state_icon(state: BranchState) -> str:
    """Single-glyph icon — stays inline with the existing icon vocabulary
    used in feed/builder.py."""
    return {
        BranchState.LOCKED:               "◌",
        BranchState.AVAILABLE:            "○",
        BranchState.ACTIVE:               "▶",
        BranchState.COMPLETED:            "✓",
        BranchState.EVIDENCE_ATTACHED:    "⬡",
        BranchState.REMEDIATION_PENDING:  "⛨",
        BranchState.VERIFICATION_RUNNING: "◐",
        BranchState.VERIFIED:             "✓",
        BranchState.REGRESSION:           "⚠",
    }[state]


# ── Defensive confidence indicators (Phase 21 Part J) ─────────────────────


def defensive_confidence_glyph(state: BranchState) -> str:
    """Stable glyph for remediation/defensive states only.

    Returns "" for non-remediation states so callers can branch on it.
    Glyphs match the Phase 21 spec:
        ⚠  mitigation unverified  → REMEDIATION_PENDING
        ◐  partial verification   → VERIFICATION_RUNNING
        ✓  remediation verified   → VERIFIED
        ✕  regression detected    → REGRESSION
    """
    return {
        BranchState.REMEDIATION_PENDING:  "⚠",
        BranchState.VERIFICATION_RUNNING: "◐",
        BranchState.VERIFIED:             "✓",
        BranchState.REGRESSION:           "✕",
    }.get(state, "")


def defensive_confidence_label(state: BranchState) -> str:
    """Human label paired with `defensive_confidence_glyph()`."""
    return {
        BranchState.REMEDIATION_PENDING:  "mitigation unverified",
        BranchState.VERIFICATION_RUNNING: "partial verification",
        BranchState.VERIFIED:             "remediation verified",
        BranchState.REGRESSION:           "regression detected",
    }.get(state, "")
