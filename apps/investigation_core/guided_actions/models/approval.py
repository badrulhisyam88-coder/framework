"""ActionApproval — records explicit human approval for a guided action."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class ApprovalStatus(StrEnum):
    PENDING = "pending"       # Awaiting user review
    APPROVED = "approved"     # User approved; guidance unlocked
    REJECTED = "rejected"     # User declined; no guidance shown
    COMPLETED = "completed"   # Action executed and evidence captured
    EXPIRED = "expired"       # Approval stale (investigation resolved)


class ActionApproval(BaseModel):
    approval_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    action_id: str
    finding_id: str | None = None

    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: datetime = Field(default_factory=datetime.utcnow)
    reviewed_at: datetime | None = None
    completed_at: datetime | None = None

    notes: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)  # evidence_ids
