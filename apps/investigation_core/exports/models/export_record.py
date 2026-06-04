"""ExportRecord — tracks generated knowledge exports."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class ExportStatus(StrEnum):
    GENERATED = "generated"
    FAILED = "failed"


class ExportRecord(BaseModel):
    export_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    export_type: str = "investigation_summary"
    file_path: str | None = None     # absolute path on disk
    vault_path: str | None = None    # relative to vault root
    status: ExportStatus = ExportStatus.GENERATED
    generated_at: datetime = Field(default_factory=datetime.utcnow)
