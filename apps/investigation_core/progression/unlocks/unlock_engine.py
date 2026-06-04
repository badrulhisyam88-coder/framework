"""UnlockEngine — deterministic prerequisite checking and skill availability transitions."""

from __future__ import annotations

from apps.investigation_core.progression.models.mastery import MasteryStatus, SkillMastery
from apps.investigation_core.skills.graph.skill_graph import SkillGraph, skill_graph
from apps.investigation_core.skills.models.skill import Skill


class UnlockEngine:
    def __init__(self, graph: SkillGraph | None = None) -> None:
        self._graph = graph or skill_graph

    def compute_available_skills(
        self,
        finding_types: list[str],
        mastery_records: list[SkillMastery],
    ) -> list[str]:
        """Return skill_ids that should be made available (status=available).

        A skill becomes available when:
        1. It is relevant to the investigation's finding types (or has no findings filter)
        2. All its prerequisites are completed/mastered
        3. It is currently locked
        """
        mastery_by_skill: dict[str, MasteryStatus] = {
            m.skill_id: m.status for m in mastery_records
        }
        completed_ids: set[str] = {
            sid for sid, status in mastery_by_skill.items()
            if status in (MasteryStatus.COMPLETED, MasteryStatus.MASTERED)
        }

        # Skills relevant to current findings
        relevant_skill_ids: set[str] = {
            s.skill_id
            for s in self._graph.skills_for_finding_types(finding_types)
        }
        # Also include skills whose prerequisites lead to relevant skills
        for skill in self._graph.all_skills():
            for prereq_id in skill.prerequisites:
                if skill.skill_id in relevant_skill_ids:
                    relevant_skill_ids.add(prereq_id)

        newly_available: list[str] = []
        for skill_id in relevant_skill_ids:
            current_status = mastery_by_skill.get(skill_id, MasteryStatus.LOCKED)
            if current_status not in (MasteryStatus.LOCKED,):
                continue  # already available/in-progress/completed
            if self._graph.are_prerequisites_met(skill_id, completed_ids):
                newly_available.append(skill_id)

        return newly_available

    def newly_unlocked_by_completion(
        self,
        completed_skill_id: str,
        mastery_records: list[SkillMastery],
    ) -> list[Skill]:
        """Return skills unlocked as a direct result of completing completed_skill_id."""
        completed_ids: set[str] = {
            m.skill_id
            for m in mastery_records
            if m.status in (MasteryStatus.COMPLETED, MasteryStatus.MASTERED)
        }
        completed_ids.add(completed_skill_id)

        already_available: set[str] = {
            m.skill_id
            for m in mastery_records
            if m.status != MasteryStatus.LOCKED
        }

        result: list[Skill] = []
        for dependent in self._graph.dependents_of(completed_skill_id):
            if dependent.skill_id in already_available:
                continue
            if self._graph.are_prerequisites_met(dependent.skill_id, completed_ids):
                result.append(dependent)
        return result
