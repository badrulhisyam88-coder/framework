"""Campaign objectives — high-level goals tracked across member investigations.

Objectives are SOFT — they don't gate progression. They give campaigns
directionality and a place to surface "what are we trying to demonstrate".
A sub-objective is considered satisfied when any of its trigger criteria are
met across the member investigations:

  - any milestone with matching objective_key is achieved, OR
  - any finding with matching finding_type is captured AND linked evidence exists.

The check is performed at snapshot time by `CampaignService.progress_snapshot`.
"""

from __future__ import annotations

from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class ObjectiveStatus(StrEnum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED   = "completed"


class SubObjective(BaseModel):
    sub_objective_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    # Match criteria — at least one must be true at snapshot time
    milestone_keys: list[str] = Field(default_factory=list)
    finding_types: list[str]  = Field(default_factory=list)
    # Derived at snapshot time, persisted for last-known status
    status: ObjectiveStatus = ObjectiveStatus.NOT_STARTED
    evidence_required: bool = False


class CampaignObjective(BaseModel):
    objective_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str = ""
    sub_objectives: list[SubObjective] = Field(default_factory=list)
    status: ObjectiveStatus = ObjectiveStatus.NOT_STARTED
