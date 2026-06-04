"""TimelineEvent domain model."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from apps.investigation_core.taxonomy.stages import EventType


class TimelineEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    event_type: EventType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    actor: str = "system"  # "user" | "system"
    summary: str
    detail: dict[str, Any] = Field(default_factory=dict)
