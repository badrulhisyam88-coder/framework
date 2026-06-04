"""PathRegistry — lookup all learning paths by ID or finding type."""

from __future__ import annotations

from apps.investigation_core.learning.paths import ALL_PATHS
from apps.investigation_core.models.learning import LearningPath


class PathRegistry:
    """Singleton-style in-memory registry of all configured learning paths."""

    def __init__(self) -> None:
        self._by_id: dict[str, LearningPath] = {p.path_id: p for p in ALL_PATHS}
        # Index: normalised finding type → list of paths
        self._by_finding_type: dict[str, list[LearningPath]] = {}
        for path in ALL_PATHS:
            for ft in path.finding_types:
                self._by_finding_type.setdefault(ft.lower(), []).append(path)

    def get(self, path_id: str) -> LearningPath | None:
        return self._by_id.get(path_id)

    def all_paths(self) -> list[LearningPath]:
        return list(self._by_id.values())

    def paths_for_finding_type(self, finding_type: str) -> list[LearningPath]:
        return self._by_finding_type.get(finding_type.lower(), [])

    def paths_for_finding_types(self, finding_types: list[str]) -> dict[str, list[LearningPath]]:
        """Return {finding_type: [paths]} for all matching types."""
        return {
            ft: self.paths_for_finding_type(ft)
            for ft in finding_types
            if self.paths_for_finding_type(ft)
        }


# Module-level singleton — import and use directly.
registry = PathRegistry()
