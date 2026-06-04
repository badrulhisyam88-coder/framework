"""MasteryValidator — deterministic mastery scoring and status derivation.

Mastery is NOT just clicking "complete". It requires:
- Evidence artifacts that match the skill's requirements
- Related learning path OR guided action completion
"""

from __future__ import annotations

from dataclasses import dataclass

from apps.investigation_core.progression.models.mastery import MasteryStatus
from apps.investigation_core.skills.models.skill import Skill


@dataclass
class MasteryScore:
    evidence_score: float      # 0–1: fraction of evidence requirements met
    learning_score: float      # 0 or 1: any related path completed
    action_score: float        # 0 or 1: any related action completed
    confidence: float          # weighted composite
    derived_status: MasteryStatus
    missing_evidence: list[str]  # human-readable gaps


_EVIDENCE_WEIGHT = 0.50
_LEARNING_WEIGHT = 0.25
_ACTION_WEIGHT = 0.25


def compute_mastery_score(
    skill: Skill,
    evidence_artifact_types: list[str],       # artifact_type strings captured so far
    completed_learning_path_ids: list[str],
    completed_action_ids: list[str],
    current_status: MasteryStatus = MasteryStatus.LOCKED,
) -> MasteryScore:
    """Compute a deterministic mastery score for a skill."""

    # Evidence score — fraction of requirements satisfied
    if not skill.evidence_requirements:
        ev_score = 1.0
        missing: list[str] = []
    else:
        satisfied = 0
        missing = []
        type_counts: dict[str, int] = {}
        for t in evidence_artifact_types:
            type_counts[t] = type_counts.get(t, 0) + 1

        for req in skill.evidence_requirements:
            actual = type_counts.get(req.artifact_type, 0)
            if actual >= req.minimum_count:
                satisfied += 1
            else:
                needed = req.minimum_count - actual
                missing.append(
                    f"{req.artifact_type} ×{needed} — {req.description}"
                    if req.description else f"{req.artifact_type} ×{needed}"
                )
        ev_score = satisfied / len(skill.evidence_requirements)

    # Learning score
    related_paths = set(skill.related_learning_paths)
    lrn_score = 1.0 if related_paths and any(
        p in related_paths for p in completed_learning_path_ids
    ) else (1.0 if not related_paths else 0.0)

    # Action score
    related_actions = set(skill.related_guided_actions)
    act_score = 1.0 if related_actions and any(
        a in related_actions for a in completed_action_ids
    ) else (1.0 if not related_actions else 0.0)

    confidence = (
        ev_score * _EVIDENCE_WEIGHT
        + lrn_score * _LEARNING_WEIGHT
        + act_score * _ACTION_WEIGHT
    )

    # Status derivation — must respect current status (can't go backwards)
    if current_status == MasteryStatus.MASTERED:
        derived = MasteryStatus.MASTERED
    elif confidence >= 1.0:
        derived = MasteryStatus.MASTERED
    elif confidence >= 0.75:
        derived = MasteryStatus.COMPLETED
    elif confidence >= 0.1:
        derived = MasteryStatus.IN_PROGRESS
    elif current_status in (MasteryStatus.AVAILABLE, MasteryStatus.IN_PROGRESS):
        derived = current_status
    else:
        derived = MasteryStatus.LOCKED

    return MasteryScore(
        evidence_score=round(ev_score, 3),
        learning_score=round(lrn_score, 3),
        action_score=round(act_score, 3),
        confidence=round(confidence, 3),
        derived_status=derived,
        missing_evidence=missing,
    )


class MasteryValidator:
    @staticmethod
    def score(
        skill: Skill,
        evidence_artifact_types: list[str],
        completed_learning_path_ids: list[str],
        completed_action_ids: list[str],
        current_status: MasteryStatus = MasteryStatus.LOCKED,
    ) -> MasteryScore:
        return compute_mastery_score(
            skill,
            evidence_artifact_types,
            completed_learning_path_ids,
            completed_action_ids,
            current_status,
        )
