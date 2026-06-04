"""ScanExecution — lifecycle record for a single scanner run."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanExecution(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    scanner_type: str          # nmap | zap | nuclei
    target: str
    profile: str = "quick_web_scan"
    status: ScanStatus = ScanStatus.QUEUED

    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None

    findings_count: int = 0
    evidence_refs: list[str] = Field(default_factory=list)
    raw_result_ref: str | None = None    # path or key to raw output
    config: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    group_id: str | None = None          # links this scan to an InvestigationRun

    @property
    def is_terminal(self) -> bool:
        return self.status in (
            ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED
        )

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
