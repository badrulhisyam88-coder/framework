"""EvidenceCapturer — factory helpers for creating common artifact types."""

from __future__ import annotations

from typing import Any

from apps.investigation_core.evidence.models.artifact import ArtifactType, EvidenceArtifact


class EvidenceCapturer:
    """Thin factory — builds EvidenceArtifact instances without persisting them.

    Call EvidenceService.capture() to persist.
    """

    @staticmethod
    def http_request(
        investigation_id: str,
        title: str,
        content: str,
        *,
        finding_id: str | None = None,
        guided_action_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        actor: str = "user",
    ) -> EvidenceArtifact:
        return EvidenceArtifact(
            investigation_id=investigation_id,
            finding_id=finding_id,
            guided_action_id=guided_action_id,
            artifact_type=ArtifactType.HTTP_REQUEST,
            title=title,
            content=content,
            created_by=actor,
            metadata=metadata or {},
            tags=tags or [],
        )

    @staticmethod
    def payload_attempt(
        investigation_id: str,
        title: str,
        payload: str,
        *,
        finding_id: str | None = None,
        guided_action_id: str | None = None,
        description: str = "",
        outcome: str = "",
        actor: str = "user",
    ) -> EvidenceArtifact:
        return EvidenceArtifact(
            investigation_id=investigation_id,
            finding_id=finding_id,
            guided_action_id=guided_action_id,
            artifact_type=ArtifactType.PAYLOAD_ATTEMPT,
            title=title,
            description=description,
            content=payload,
            created_by=actor,
            metadata={"outcome": outcome} if outcome else {},
        )

    @staticmethod
    def terminal_output(
        investigation_id: str,
        title: str,
        output: str,
        *,
        finding_id: str | None = None,
        guided_action_id: str | None = None,
        command: str = "",
        actor: str = "user",
    ) -> EvidenceArtifact:
        return EvidenceArtifact(
            investigation_id=investigation_id,
            finding_id=finding_id,
            guided_action_id=guided_action_id,
            artifact_type=ArtifactType.TERMINAL_OUTPUT,
            title=title,
            content=output,
            created_by=actor,
            metadata={"command": command} if command else {},
        )

    @staticmethod
    def note(
        investigation_id: str,
        title: str,
        body: str,
        *,
        finding_id: str | None = None,
        guided_action_id: str | None = None,
        tags: list[str] | None = None,
        actor: str = "user",
    ) -> EvidenceArtifact:
        return EvidenceArtifact(
            investigation_id=investigation_id,
            finding_id=finding_id,
            guided_action_id=guided_action_id,
            artifact_type=ArtifactType.NOTE,
            title=title,
            content=body,
            created_by=actor,
            tags=tags or [],
        )

    @staticmethod
    def response_diff(
        investigation_id: str,
        title: str,
        diff_content: str,
        *,
        finding_id: str | None = None,
        guided_action_id: str | None = None,
        description: str = "",
        actor: str = "user",
    ) -> EvidenceArtifact:
        return EvidenceArtifact(
            investigation_id=investigation_id,
            finding_id=finding_id,
            guided_action_id=guided_action_id,
            artifact_type=ArtifactType.RESPONSE_DIFF,
            title=title,
            description=description,
            content=diff_content,
            created_by=actor,
        )
