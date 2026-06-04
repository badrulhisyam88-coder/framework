"""Validates that a guided action completion request is well-formed."""

from __future__ import annotations

from apps.investigation_core.guided_actions.models.approval import (
    ActionApproval,
    ApprovalStatus,
)


class OutcomeValidationError(ValueError):
    pass


def validate_completion_request(
    approval: ActionApproval | None,
    *,
    evidence_ids: list[str] | None = None,
) -> None:
    if approval is None:
        raise OutcomeValidationError("No approval record found. Approve the action first.")
    if approval.status == ApprovalStatus.PENDING:
        raise OutcomeValidationError("Action has not been approved yet.")
    if approval.status == ApprovalStatus.REJECTED:
        raise OutcomeValidationError("Action was rejected and cannot be completed.")
    if approval.status == ApprovalStatus.COMPLETED:
        raise OutcomeValidationError("Action already completed.")
    if approval.status == ApprovalStatus.APPROVED:
        # Optionally require at least one evidence reference
        if evidence_ids is not None and len(evidence_ids) == 0:
            raise OutcomeValidationError(
                "At least one evidence artifact is required to complete this action."
            )
