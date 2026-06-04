"""Evidence quality scoring — deterministic heuristics over EvidenceArtifact rows.

This is NOT AI grading. Each rule is a single conditional with a fixed weight.
A future maintainer can audit the weights table and reproduce any score by hand.
"""

from __future__ import annotations

from apps.investigation_core.evidence.models.artifact import EvidenceArtifact
from apps.investigation_core.memory.models.evidence_quality import (
    ArtifactQualityScore,
    EvidenceQualitySnapshot,
)

# ── Per-artifact rule weights (max 100) ────────────────────────────────────
# Adjust here — never embed weights elsewhere.

_W_TITLE_SHORT       = 5    # title ≥ 3 chars
_W_TITLE_DESCRIPTIVE = 10   # title ≥ 12 chars (more informative)
_W_DESC_BRIEF        = 5    # description 1–29 chars
_W_DESC_DETAILED     = 15   # description ≥ 30 chars
_W_CONTENT_MIN       = 10   # content ≥ 10 chars
_W_CONTENT_SUBSTANT  = 25   # content ≥ 50 chars
_W_LINKED_FINDING    = 15
_W_LINKED_ACTION     = 15
# Phase 59a — _W_LINKED_OBJECTIVE removed alongside the milestone subsystem.
# No evidence artifact will carry metadata.objective_key anymore (the only
# emitter was the milestone create_milestone route, now deleted).
_W_TAGS              = 5    # ≥ 2 tags
_W_TYPE_APPROPRIATE  = 5    # preformatted type has multiline / structured content

_PREFORMATTED_TYPES = {
    "http_request", "http_response", "payload_attempt",
    "response_diff", "terminal_output",
}


def score_artifact(artifact: EvidenceArtifact) -> ArtifactQualityScore:
    """Return a deterministic 0–100 quality score with strengths and weaknesses."""
    score = 0
    strengths: list[str] = []
    weaknesses: list[str] = []

    # Title
    title = (artifact.title or "").strip()
    if len(title) >= 12:
        score += _W_TITLE_DESCRIPTIVE
        strengths.append("descriptive title")
    elif len(title) >= 3:
        score += _W_TITLE_SHORT
    else:
        weaknesses.append("title too short")

    # Description
    desc = (artifact.description or "").strip()
    if len(desc) >= 30:
        score += _W_DESC_DETAILED
        strengths.append("detailed description")
    elif len(desc) > 0:
        score += _W_DESC_BRIEF
    else:
        weaknesses.append("missing description")

    # Content
    content = (artifact.content or "").strip()
    if len(content) >= 50:
        score += _W_CONTENT_SUBSTANT
        strengths.append("substantial content")
    elif len(content) >= 10:
        score += _W_CONTENT_MIN
    else:
        weaknesses.append("content too thin")

    # Finding linkage
    if artifact.finding_id:
        score += _W_LINKED_FINDING
        strengths.append("linked to finding")
    else:
        weaknesses.append("not linked to a finding")

    # Guided action linkage
    if artifact.guided_action_id:
        score += _W_LINKED_ACTION
        strengths.append("linked to investigation action")
    else:
        weaknesses.append("not linked to an action")

    # Phase 59a — CTF-objective-linkage scoring component removed
    # alongside the milestone subsystem.

    # Tags
    if artifact.tags and len(artifact.tags) >= 2:
        score += _W_TAGS

    # Type-appropriate content shape
    a_type = str(artifact.artifact_type)
    if a_type in _PREFORMATTED_TYPES:
        if "\n" in content or len(content) >= 30:
            score += _W_TYPE_APPROPRIATE
        else:
            weaknesses.append(
                f"{a_type} expected structured content (multi-line / payload-shaped)"
            )

    return ArtifactQualityScore(
        evidence_id=artifact.evidence_id,
        artifact_type=a_type,
        score=min(100, score),
        strengths=strengths,
        weaknesses=weaknesses,
    )


def score_investigation_evidence(
    artifacts: list[EvidenceArtifact],
) -> EvidenceQualitySnapshot:
    """Aggregate per-artifact scores into an investigation-wide snapshot."""
    snap = EvidenceQualitySnapshot(total_artifacts=len(artifacts))
    if not artifacts:
        snap.reasons.append("No evidence captured yet")
        return snap

    per: list[ArtifactQualityScore] = [score_artifact(a) for a in artifacts]
    snap.per_artifact = per

    # Overall: arithmetic mean
    snap.overall_score = round(sum(p.score for p in per) / len(per))

    # By-type averages
    by_type_scores: dict[str, list[int]] = {}
    for p in per:
        by_type_scores.setdefault(p.artifact_type, []).append(p.score)
    snap.by_type_avg = {
        t: round(sum(s) / len(s)) for t, s in by_type_scores.items()
    }
    snap.type_diversity = len(by_type_scores)

    # Strong/weak buckets
    for t, avg in snap.by_type_avg.items():
        if avg >= 75:
            snap.strong_types.append(t)
        elif avg < 50:
            snap.weak_types.append(t)

    # Top reasons surfaced to the user
    if snap.overall_score >= 75:
        snap.reasons.append(
            f"Average quality {snap.overall_score}/100 across "
            f"{snap.total_artifacts} artifact(s)"
        )
    elif snap.overall_score >= 50:
        snap.reasons.append(
            f"Average quality {snap.overall_score}/100 — room to improve "
            "linkage and description detail"
        )
    else:
        snap.reasons.append(
            f"Average quality {snap.overall_score}/100 — thin evidence; "
            "add finding/action linkage and more detail"
        )

    if snap.weak_types:
        snap.reasons.append(
            "Weak artifact types: " + ", ".join(sorted(snap.weak_types))
        )
    if snap.type_diversity == 1:
        snap.reasons.append(
            "Single artifact type captured — mix screenshots, payloads, and notes"
        )

    return snap
