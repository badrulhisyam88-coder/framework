"""NormalizedFinding — canonical cross-scanner finding format."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class NormalizedFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    scan_id: str
    investigation_id: str
    source_scanner: str          # nmap | zap | nuclei

    finding_type: str            # canonical type from our taxonomy
    severity: str                # critical | high | medium | low | info
    title: str
    description: str = ""

    target: str
    port: int | None = None
    endpoint: str | None = None  # URL path, e.g. /login

    evidence_refs: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)
    related_cwes: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    raw_data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    # Resolved after normalization — links back into investigation_core
    related_skills: list[str] = Field(default_factory=list)
    related_learning_paths: list[str] = Field(default_factory=list)
    related_guided_actions: list[str] = Field(default_factory=list)
