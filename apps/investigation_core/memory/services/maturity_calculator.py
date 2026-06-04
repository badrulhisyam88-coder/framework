"""Per-category maturity calculation — deterministic and traceable.

The scoring weights are exposed as module constants so a maintainer can
explain any maturity level by reading the table.
"""

from __future__ import annotations

from apps.investigation_core.memory.categories import category_label
from apps.investigation_core.memory.models.memory import (
    CategoryMaturity,
    MaturityLevel,
)

# Per-signal weights — the maturity level is derived from the sum.
_W_MILESTONE_ACHIEVED = 3
_W_ACTION_COMPLETED   = 4
_W_SKILL_MASTERED     = 5
_W_SKILL_IN_PROGRESS  = 2
_W_EVIDENCE_PRESENT   = 1

# Level thresholds — inclusive lower bounds.
_LEVEL_THRESHOLDS = [
    (25, MaturityLevel.ADVANCED),
    (10, MaturityLevel.INTERMEDIATE),
    (3,  MaturityLevel.BEGINNER),
]


def compute_category_maturity(
    category: str,
    *,
    findings_count: int,
    milestones_achieved: int,
    actions_completed: int,
    actions_abandoned: int,
    skills_in_progress: int,
    skills_completed: int,
    evidence_count: int,
) -> CategoryMaturity:
    """Derive a maturity record from raw counts. Returns a fully-explained record."""
    score = (
        milestones_achieved * _W_MILESTONE_ACHIEVED
        + actions_completed * _W_ACTION_COMPLETED
        + skills_completed * _W_SKILL_MASTERED
        + skills_in_progress * _W_SKILL_IN_PROGRESS
        + (_W_EVIDENCE_PRESENT if evidence_count > 0 else 0)
    )

    level = MaturityLevel.EXPOSURE_ONLY
    for threshold, lvl in _LEVEL_THRESHOLDS:
        if score >= threshold:
            level = lvl
            break

    reasoning = _build_reasoning(
        score=score,
        milestones_achieved=milestones_achieved,
        actions_completed=actions_completed,
        actions_abandoned=actions_abandoned,
        skills_completed=skills_completed,
        skills_in_progress=skills_in_progress,
        evidence_count=evidence_count,
    )

    return CategoryMaturity(
        category=category,
        label=category_label(category),
        level=level,
        findings_count=findings_count,
        milestones_achieved=milestones_achieved,
        actions_completed=actions_completed,
        actions_abandoned=actions_abandoned,
        skills_in_progress=skills_in_progress,
        skills_completed=skills_completed,
        evidence_count=evidence_count,
        score=score,
        reasoning=reasoning,
    )


def _build_reasoning(
    *,
    score: int,
    milestones_achieved: int,
    actions_completed: int,
    actions_abandoned: int,
    skills_completed: int,
    skills_in_progress: int,
    evidence_count: int,
) -> list[str]:
    bits: list[str] = []
    if milestones_achieved:
        bits.append(
            f"{milestones_achieved} milestone(s) "
            f"({milestones_achieved * _W_MILESTONE_ACHIEVED} pts)"
        )
    if actions_completed:
        bits.append(
            f"{actions_completed} action(s) completed "
            f"({actions_completed * _W_ACTION_COMPLETED} pts)"
        )
    if skills_completed:
        bits.append(
            f"{skills_completed} skill(s) mastered "
            f"({skills_completed * _W_SKILL_MASTERED} pts)"
        )
    if skills_in_progress:
        bits.append(
            f"{skills_in_progress} skill(s) in progress "
            f"({skills_in_progress * _W_SKILL_IN_PROGRESS} pts)"
        )
    if evidence_count:
        bits.append(f"{evidence_count} artifact(s) (+{_W_EVIDENCE_PRESENT} pt)")
    if actions_abandoned:
        bits.append(f"{actions_abandoned} action(s) abandoned (no penalty)")

    line = ("Maturity score " + str(score) + ": " + ", ".join(bits)) if bits else (
        "Maturity score 0 — findings present but no investigation activity yet"
    )
    return [line]
