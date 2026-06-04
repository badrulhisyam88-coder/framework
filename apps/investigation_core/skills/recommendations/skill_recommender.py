"""SkillRecommender — deterministic next-skill recommendation engine."""

from __future__ import annotations

from dataclasses import dataclass

from apps.investigation_core.skills.graph.skill_graph import SkillGraph, skill_graph
from apps.investigation_core.skills.models.skill import DIFFICULTY_ORDER, Skill


@dataclass
class SkillRecommendation:
    skill: Skill
    is_available: bool      # prerequisites met
    is_in_progress: bool
    is_completed: bool
    is_mastered: bool
    matched_finding_types: list[str]
    confidence_score: float  # 0.0–1.0 from mastery record


class SkillRecommender:
    def __init__(self, graph: SkillGraph | None = None) -> None:
        self._graph = graph or skill_graph

    def recommend(
        self,
        finding_types: list[str],
        *,
        mastery_by_skill: dict[str, object] | None = None,
    ) -> list[SkillRecommendation]:
        """Return ordered skill recommendations for an investigation.

        mastery_by_skill: {skill_id: SkillMastery} — current mastery state.
        Skills are ordered: in-progress first, then available, then locked;
        within each group by difficulty ascending.
        """
        mastery = mastery_by_skill or {}
        relevant_skills = self._graph.skills_for_finding_types(finding_types)

        # Derive completed set for prerequisite checking
        completed_ids: set[str] = {
            sid for sid, m in mastery.items()
            if hasattr(m, "status") and str(m.status) in ("completed", "mastered")
        }

        recommendations: list[SkillRecommendation] = []
        for skill in relevant_skills:
            m = mastery.get(skill.skill_id)
            status = str(m.status) if m and hasattr(m, "status") else "locked"
            score = float(m.confidence_score) if m and hasattr(m, "confidence_score") else 0.0

            prereqs_met = self._graph.are_prerequisites_met(
                skill.skill_id, completed_ids
            )
            matched = [ft for ft in finding_types if ft.lower() in [
                rf.lower() for rf in skill.related_findings
            ]]

            recommendations.append(SkillRecommendation(
                skill=skill,
                is_available=prereqs_met and status in ("locked", "available"),
                is_in_progress=status == "in_progress",
                is_completed=status == "completed",
                is_mastered=status == "mastered",
                matched_finding_types=matched,
                confidence_score=score,
            ))

        # Sort: in-progress > available (not done) > completed/mastered > locked
        def _rank(r: SkillRecommendation) -> tuple:
            if r.is_mastered:
                return (3, DIFFICULTY_ORDER.get(str(r.skill.difficulty), 0))
            if r.is_completed:
                return (2, DIFFICULTY_ORDER.get(str(r.skill.difficulty), 0))
            if r.is_in_progress:
                return (0, DIFFICULTY_ORDER.get(str(r.skill.difficulty), 0))
            if r.is_available:
                return (1, DIFFICULTY_ORDER.get(str(r.skill.difficulty), 0))
            return (4, DIFFICULTY_ORDER.get(str(r.skill.difficulty), 0))

        recommendations.sort(key=_rank)
        return recommendations

    def next_skill(
        self,
        finding_types: list[str],
        mastery_by_skill: dict[str, object] | None = None,
    ) -> Skill | None:
        """Return the single best next skill to work on, or None."""
        recs = self.recommend(finding_types, mastery_by_skill=mastery_by_skill)
        # Prefer in-progress, then available beginner, then available intermediate
        for r in recs:
            if r.is_in_progress:
                return r.skill
        for r in recs:
            if r.is_available and not r.is_completed and not r.is_mastered:
                return r.skill
        return None
