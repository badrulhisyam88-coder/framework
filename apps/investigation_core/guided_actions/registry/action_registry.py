"""ActionRegistry — lookup guided actions by ID or finding type."""

from __future__ import annotations

from apps.investigation_core.guided_actions.models.action import GuidedAction
from apps.investigation_core.guided_actions.registry.actions import ALL_ACTIONS


class ActionRegistry:
    def __init__(self) -> None:
        self._by_id: dict[str, GuidedAction] = {a.action_id: a for a in ALL_ACTIONS}
        self._by_finding_type: dict[str, list[GuidedAction]] = {}
        for action in ALL_ACTIONS:
            for ft in action.finding_types:
                self._by_finding_type.setdefault(ft.lower(), []).append(action)

    def get(self, action_id: str) -> GuidedAction | None:
        return self._by_id.get(action_id)

    def all_actions(self) -> list[GuidedAction]:
        return list(self._by_id.values())

    def actions_for_finding_type(self, finding_type: str) -> list[GuidedAction]:
        return self._by_finding_type.get(finding_type.lower(), [])

    def actions_for_finding_types(
        self, finding_types: list[str]
    ) -> dict[str, list[GuidedAction]]:
        return {
            ft: self.actions_for_finding_type(ft)
            for ft in finding_types
            if self.actions_for_finding_type(ft)
        }


action_registry = ActionRegistry()
