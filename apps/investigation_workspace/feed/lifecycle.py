"""Action lifecycle derivation — read-only over guided_action_approvals + evidence.

Five lifecycle states reflecting investigation continuity:

    not_started       no approval requested
    in_progress       approval pending or approved, no evidence yet
    evidence_captured approval approved AND linked evidence exists
    completed         approval marked completed
    abandoned         approval rejected

This is a derived view — no new persistence. The mapping is deterministic:
ApprovalService.complete() advances to 'completed'; an evidence artifact whose
guided_action_id matches an approved action advances to 'evidence_captured'.
"""

from __future__ import annotations

from dataclasses import dataclass

from apps.investigation_core.evidence.models.artifact import EvidenceArtifact
from apps.investigation_core.guided_actions.models.approval import (
    ActionApproval,
    ApprovalStatus,
)

# One of: not_started | in_progress | evidence_captured | completed | abandoned
LifecycleState = str


LIFECYCLE_LABELS: dict[str, str] = {
    "not_started":       "Not started",
    "in_progress":       "In progress",
    "evidence_captured": "Evidence captured",
    "completed":         "Completed",
    "abandoned":         "Abandoned",
}

LIFECYCLE_ICONS: dict[str, str] = {
    "not_started":       "○",
    "in_progress":       "▶",
    "evidence_captured": "⬡",
    "completed":         "✓",
    "abandoned":         "✗",
}


@dataclass
class ActionLifecycle:
    state: LifecycleState
    label: str
    icon: str
    evidence_count: int = 0
    approval: ActionApproval | None = None


def derive_lifecycle(
    approval: ActionApproval | None,
    action_evidence: list[EvidenceArtifact],
) -> ActionLifecycle:
    """Map (approval, related_evidence) → lifecycle state."""
    ev_count = len(action_evidence)
    if approval is None:
        state = "not_started"
    elif approval.status == ApprovalStatus.COMPLETED:
        state = "completed"
    elif approval.status == ApprovalStatus.REJECTED:
        state = "abandoned"
    elif approval.status in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED):
        state = "evidence_captured" if ev_count > 0 else "in_progress"
    else:
        state = "in_progress"

    return ActionLifecycle(
        state=state,
        label=LIFECYCLE_LABELS[state],
        icon=LIFECYCLE_ICONS[state],
        evidence_count=ev_count,
        approval=approval,
    )
