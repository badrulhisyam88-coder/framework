"""SkillMastery — per-investigation mastery record for a skill."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class MasteryStatus(StrEnum):
    LOCKED = "locked"           # Prerequisites not met
    AVAILABLE = "available"     # Prerequisites met; not started
    IN_PROGRESS = "in_progress" # Some evidence / partial completion
    COMPLETED = "completed"     # All requirements met
    MASTERED = "mastered"       # Fully mastered (confidence = 1.0 + validated)


MASTERY_STATUS_ORDER: dict[str, int] = {
    MasteryStatus.LOCKED: 0,
    MasteryStatus.AVAILABLE: 1,
    MasteryStatus.IN_PROGRESS: 2,
    MasteryStatus.COMPLETED: 3,
    MasteryStatus.MASTERED: 4,
}

MASTERY_STATUS_LABELS: dict[str, str] = {
    MasteryStatus.LOCKED: "Locked",
    MasteryStatus.AVAILABLE: "Available",
    MasteryStatus.IN_PROGRESS: "In Progress",
    MasteryStatus.COMPLETED: "Completed",
    MasteryStatus.MASTERED: "Mastered",
}


class SkillMastery(BaseModel):
    mastery_id: str = Field(default_factory=lambda: str(uuid4()))
    skill_id: str
    investigation_id: str

    status: MasteryStatus = MasteryStatus.LOCKED

    # References to evidence, paths, and actions that contributed
    evidence_refs: list[str] = Field(default_factory=list)          # evidence_ids
    completed_learning_paths: list[str] = Field(default_factory=list)  # path_ids
    completed_actions: list[str] = Field(default_factory=list)      # action_ids

    # 0.0–1.0: computed from evidence + learning + action completion
    confidence_score: float = 0.0

    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: datetime | None = None
    validated_at: datetime | None = None
