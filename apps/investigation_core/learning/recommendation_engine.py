"""RecommendationEngine — deterministic path recommendations from finding types."""

from __future__ import annotations

from apps.investigation_core.learning.path_registry import PathRegistry, registry
from apps.investigation_core.models.learning import LearningPath, PathRecommendation


class RecommendationEngine:
    def __init__(self, path_registry: PathRegistry | None = None) -> None:
        self._registry = path_registry or registry

    def recommend(
        self,
        finding_types: list[str],
        *,
        active_path_ids: list[str] | None = None,
        completed_path_ids: list[str] | None = None,
    ) -> list[PathRecommendation]:
        """Return ranked learning path recommendations for the given finding types.

        Paths are deduplicated. A path matching more finding types ranks higher.
        """
        active_ids = set(active_path_ids or [])
        completed_ids = set(completed_path_ids or [])

        # path_id → set of matched finding types
        match_map: dict[str, set[str]] = {}
        for ft in finding_types:
            for path in self._registry.paths_for_finding_type(ft):
                match_map.setdefault(path.path_id, set()).add(ft)

        recommendations: list[PathRecommendation] = []
        for path_id, matched_fts in match_map.items():
            path = self._registry.get(path_id)
            if path is None:
                continue
            recommendations.append(
                PathRecommendation(
                    path=path,
                    matched_finding_types=sorted(matched_fts),
                    already_started=path_id in active_ids,
                    already_completed=path_id in completed_ids,
                )
            )

        # Sort: not-yet-started first, then by number of matched types (descending).
        recommendations.sort(
            key=lambda r: (
                1 if r.already_completed else (0 if not r.already_started else 0),
                -len(r.matched_finding_types),
            )
        )
        return recommendations

    def recommend_next_after_completion(self, completed_path_id: str) -> list[LearningPath]:
        """Return the suggested follow-on paths after completing a given path."""
        path = self._registry.get(completed_path_id)
        if not path:
            return []
        return [p for pid in path.next_paths if (p := self._registry.get(pid))]
