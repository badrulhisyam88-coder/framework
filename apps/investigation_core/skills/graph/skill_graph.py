"""SkillGraph — deterministic directed skill dependency graph.

All skill definitions are static config. The graph is built once in memory
and never mutated. Learner progress is tracked separately in SkillMastery records.
"""

from __future__ import annotations

from apps.investigation_core.skills.models.skill import Skill
from apps.investigation_core.skills.taxonomy import ALL_SKILLS


class SkillGraph:
    """In-memory directed acyclic graph of skill dependencies."""

    def __init__(self, skills: list[Skill]) -> None:
        self._skills: dict[str, Skill] = {s.skill_id: s for s in skills}
        # Reverse index: skill_id → set of skills that have it as a prerequisite
        self._dependents: dict[str, set[str]] = {s: set() for s in self._skills}
        for skill in skills:
            for prereq in skill.prerequisites:
                self._dependents.setdefault(prereq, set()).add(skill.skill_id)

        # Finding-type → skill ids that match
        self._by_finding_type: dict[str, list[str]] = {}
        for skill in skills:
            for ft in skill.related_findings:
                self._by_finding_type.setdefault(ft.lower(), []).append(skill.skill_id)

    def get(self, skill_id: str) -> Skill | None:
        return self._skills.get(skill_id)

    def all_skills(self) -> list[Skill]:
        return list(self._skills.values())

    def prerequisites_of(self, skill_id: str) -> list[Skill]:
        skill = self._skills.get(skill_id)
        if not skill:
            return []
        return [self._skills[p] for p in skill.prerequisites if p in self._skills]

    def dependents_of(self, skill_id: str) -> list[Skill]:
        """Skills that become unlockable once this skill is completed."""
        return [
            self._skills[sid]
            for sid in self._dependents.get(skill_id, set())
            if sid in self._skills
        ]

    def skills_for_finding_type(self, finding_type: str) -> list[Skill]:
        return [
            self._skills[sid]
            for sid in self._by_finding_type.get(finding_type.lower(), [])
            if sid in self._skills
        ]

    def skills_for_finding_types(self, finding_types: list[str]) -> list[Skill]:
        seen: set[str] = set()
        result: list[Skill] = []
        for ft in finding_types:
            for skill in self.skills_for_finding_type(ft):
                if skill.skill_id not in seen:
                    seen.add(skill.skill_id)
                    result.append(skill)
        return result

    def are_prerequisites_met(
        self,
        skill_id: str,
        completed_skill_ids: set[str],
    ) -> bool:
        """Return True if all prerequisites of skill_id are in completed_skill_ids."""
        skill = self._skills.get(skill_id)
        if not skill:
            return False
        return all(p in completed_skill_ids for p in skill.prerequisites)

    def skills_unlockable_by(
        self,
        completed_skill_ids: set[str],
        currently_available_ids: set[str],
    ) -> list[Skill]:
        """Return skills that should become available given the completed set.

        A skill becomes available when:
        - All its prerequisites are in completed_skill_ids
        - It is not already available/in-progress/completed
        """
        result: list[Skill] = []
        for skill in self._skills.values():
            if skill.skill_id in currently_available_ids:
                continue
            if skill.skill_id in completed_skill_ids:
                continue
            if self.are_prerequisites_met(skill.skill_id, completed_skill_ids):
                result.append(skill)
        return result

    def topological_order(self) -> list[Skill]:
        """Return skills in topological order (prerequisites before dependents)."""
        visited: set[str] = set()
        order: list[str] = []

        def visit(sid: str) -> None:
            if sid in visited:
                return
            visited.add(sid)
            skill = self._skills.get(sid)
            if skill:
                for prereq in skill.prerequisites:
                    visit(prereq)
            order.append(sid)

        for sid in self._skills:
            visit(sid)

        return [self._skills[sid] for sid in order if sid in self._skills]


# Module-level singleton
skill_graph = SkillGraph(ALL_SKILLS)
