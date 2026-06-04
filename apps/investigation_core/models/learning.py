"""Learning path domain models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class LearningPathStatus(StrEnum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ABANDONED = "abandoned"


class GuidedStep(BaseModel):
    step_id: str
    title: str
    explanation: str
    why_this_matters: str
    expected_evidence: str
    learner_input: str | None = None
    completion_validation: str
    next_step: str | None = None  # step_id, or None if this is the last step


class LearningPath(BaseModel):
    path_id: str
    title: str
    difficulty: str  # beginner | intermediate | advanced
    finding_types: list[str]     # finding type strings that trigger recommendation
    required_skills: list[str]
    learning_objectives: list[str]
    guided_steps: list[GuidedStep]
    completion_checks: list[str]
    next_paths: list[str] = Field(default_factory=list)  # path_ids to suggest after

    def step_by_id(self, step_id: str) -> GuidedStep | None:
        return next((s for s in self.guided_steps if s.step_id == step_id), None)


class LearningPathProgress(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    path_id: str
    status: LearningPathStatus = LearningPathStatus.ACTIVE
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    current_step_index: int = 0
    completed_steps: list[str] = Field(default_factory=list)  # step_ids


class PathRecommendation(BaseModel):
    """A path recommended for an investigation, with match context."""
    path: LearningPath
    matched_finding_types: list[str]
    already_started: bool = False
    already_completed: bool = False
