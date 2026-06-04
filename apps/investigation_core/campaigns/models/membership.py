"""CampaignMembership — links one investigation into a campaign with stage + lineage."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from pydantic import BaseModel, Field

from apps.investigation_core.campaigns.models.campaign import CampaignStage


class CampaignMembership(BaseModel):
    membership_id: str = Field(default_factory=lambda: str(uuid4()))
    campaign_id: str
    investigation_id: str
    stage: CampaignStage = CampaignStage.RECON
    sequence_order: int = 0
    # Optional parent_investigation_id — records "this investigation was spawned
    # FROM that one" so the campaign timeline can show chaining.
    parent_investigation_id: str | None = None
    joined_at: datetime = Field(default_factory=datetime.utcnow)
    notes: str | None = None
