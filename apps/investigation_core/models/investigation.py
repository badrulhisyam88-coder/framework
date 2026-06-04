"""Investigation domain model."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field

from apps.investigation_core.taxonomy.stages import WorkflowStage


class InvestigationStatus(StrEnum):
    ACTIVE = "active"
    RESOLVED = "resolved"
    ARCHIVED = "archived"


class Investigation(BaseModel):
    investigation_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    status: InvestigationStatus = InvestigationStatus.ACTIVE
    workflow_stage: WorkflowStage = WorkflowStage.DISCOVERY
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # Target IPs / hostnames this investigation covers.
    targets: list[str] = Field(default_factory=list)

    # Finding IDs sourced from the validation module.
    findings: list[str] = Field(default_factory=list)

    # Arbitrary evidence references (vault markdown paths, report IDs, etc.).
    evidence_refs: list[str] = Field(default_factory=list)

    # Learning path IDs in progress or completed.
    active_learning_paths: list[str] = Field(default_factory=list)
    completed_learning_paths: list[str] = Field(default_factory=list)

    notes: str | None = None
