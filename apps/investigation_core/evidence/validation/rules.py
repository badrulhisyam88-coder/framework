"""Validation rules for EvidenceArtifact before persistence."""

from __future__ import annotations

from apps.investigation_core.evidence.models.artifact import ArtifactType, EvidenceArtifact

_CONTENT_REQUIRED: frozenset[ArtifactType] = frozenset({
    ArtifactType.HTTP_REQUEST,
    ArtifactType.HTTP_RESPONSE,
    ArtifactType.PAYLOAD_ATTEMPT,
    ArtifactType.TERMINAL_OUTPUT,
    ArtifactType.RESPONSE_DIFF,
    ArtifactType.NOTE,
})

_MAX_CONTENT_LEN = 64_000  # ~64 KB per artifact
_MAX_TITLE_LEN = 200


class ArtifactValidationError(ValueError):
    pass


def validate_artifact(artifact: EvidenceArtifact) -> None:
    """Raise ArtifactValidationError if the artifact is invalid."""
    if not artifact.title.strip():
        raise ArtifactValidationError("Evidence title is required.")
    if len(artifact.title) > _MAX_TITLE_LEN:
        raise ArtifactValidationError(
            f"Title too long (max {_MAX_TITLE_LEN} chars)."
        )
    if artifact.artifact_type in _CONTENT_REQUIRED and not artifact.content.strip():
        raise ArtifactValidationError(
            f"Content is required for artifact type '{artifact.artifact_type}'."
        )
    if len(artifact.content) > _MAX_CONTENT_LEN:
        raise ArtifactValidationError(
            f"Content too long (max {_MAX_CONTENT_LEN} chars)."
        )
