"""InvestigationCampaign — operational storyline grouping investigations."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field

from apps.investigation_core.campaigns.models.objective import CampaignObjective


class CampaignStatus(StrEnum):
    PLANNING  = "planning"
    ACTIVE    = "active"
    PAUSED    = "paused"
    COMPLETED = "completed"


CAMPAIGN_STATUS_LABELS: dict[str, str] = {
    CampaignStatus.PLANNING:  "Planning",
    CampaignStatus.ACTIVE:    "Active",
    CampaignStatus.PAUSED:    "Paused",
    CampaignStatus.COMPLETED: "Completed",
}


class CampaignStage(StrEnum):
    RECON                = "recon"
    VALIDATION           = "validation"
    EXPLOITATION_THEORY  = "exploitation_theory"
    EVIDENCE_CONSOLIDATION = "evidence_consolidation"
    REMEDIATION_REVIEW   = "remediation_review"
    DEFENSIVE_REVIEW     = "defensive_review"
    KNOWLEDGE_SYNTHESIS  = "knowledge_synthesis"


STAGE_ORDER: list[CampaignStage] = [
    CampaignStage.RECON,
    CampaignStage.VALIDATION,
    CampaignStage.EXPLOITATION_THEORY,
    CampaignStage.EVIDENCE_CONSOLIDATION,
    CampaignStage.REMEDIATION_REVIEW,
    CampaignStage.DEFENSIVE_REVIEW,
    CampaignStage.KNOWLEDGE_SYNTHESIS,
]

STAGE_LABELS: dict[str, str] = {
    CampaignStage.RECON:                  "Reconnaissance",
    CampaignStage.VALIDATION:             "Validation",
    CampaignStage.EXPLOITATION_THEORY:    "Exploitation Theory",
    CampaignStage.EVIDENCE_CONSOLIDATION: "Evidence Consolidation",
    CampaignStage.REMEDIATION_REVIEW:     "Remediation Review",
    CampaignStage.DEFENSIVE_REVIEW:       "Defensive Review",
    CampaignStage.KNOWLEDGE_SYNTHESIS:    "Knowledge Synthesis",
}


class InvestigationCampaign(BaseModel):
    campaign_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str = ""
    status: CampaignStatus = CampaignStatus.PLANNING
    objectives: list[CampaignObjective] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str = "user"
