"""EvidenceArtifact domain model."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class ArtifactType(StrEnum):
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    SCREENSHOT = "screenshot"
    PAYLOAD_ATTEMPT = "payload_attempt"
    EXTRACTED_CREDENTIAL = "extracted_credential"
    RESPONSE_DIFF = "response_diff"
    TERMINAL_OUTPUT = "terminal_output"
    NOTE = "note"


ARTIFACT_TYPE_LABELS: dict[str, str] = {
    ArtifactType.HTTP_REQUEST: "HTTP Request",
    ArtifactType.HTTP_RESPONSE: "HTTP Response",
    ArtifactType.SCREENSHOT: "Screenshot",
    ArtifactType.PAYLOAD_ATTEMPT: "Payload Attempt",
    ArtifactType.EXTRACTED_CREDENTIAL: "Extracted Credential",
    ArtifactType.RESPONSE_DIFF: "Response Diff",
    ArtifactType.TERMINAL_OUTPUT: "Terminal Output",
    ArtifactType.NOTE: "Note",
}

# Which types have code/raw content (rendered in <pre>)
PREFORMATTED_TYPES: frozenset[ArtifactType] = frozenset({
    ArtifactType.HTTP_REQUEST,
    ArtifactType.HTTP_RESPONSE,
    ArtifactType.PAYLOAD_ATTEMPT,
    ArtifactType.RESPONSE_DIFF,
    ArtifactType.TERMINAL_OUTPUT,
})


class EvidenceArtifact(BaseModel):
    evidence_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    finding_id: str | None = None
    learning_path_id: str | None = None
    guided_action_id: str | None = None

    artifact_type: ArtifactType
    title: str
    description: str = ""

    # The actual captured content — raw text, payload, URL, note body, etc.
    content: str = ""

    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str = "user"

    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    @property
    def is_preformatted(self) -> bool:
        return self.artifact_type in PREFORMATTED_TYPES

    @property
    def type_label(self) -> str:
        return ARTIFACT_TYPE_LABELS.get(self.artifact_type, str(self.artifact_type))
