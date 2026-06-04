"""Investigation stage transition rules."""

from __future__ import annotations

from apps.investigation_core.taxonomy.stages import WorkflowStage

# Valid forward transitions: stage → set of reachable next stages.
# An investigation may skip stages (e.g. go straight from detection to learning
# if no validation step is needed), but it cannot go backwards.
_TRANSITIONS: dict[WorkflowStage, set[WorkflowStage]] = {
    WorkflowStage.DISCOVERY: {
        WorkflowStage.DETECTION,
        WorkflowStage.RESOLVED,
    },
    WorkflowStage.DETECTION: {
        WorkflowStage.VALIDATION,
        WorkflowStage.LEARNING,
        WorkflowStage.RESOLVED,
    },
    WorkflowStage.VALIDATION: {
        WorkflowStage.LEARNING,
        WorkflowStage.RESOLVED,
    },
    WorkflowStage.LEARNING: {
        WorkflowStage.KNOWLEDGE_EXPORT,
        WorkflowStage.RESOLVED,
    },
    WorkflowStage.KNOWLEDGE_EXPORT: {
        WorkflowStage.RESOLVED,
    },
    WorkflowStage.RESOLVED: set(),  # terminal
}


class TransitionError(ValueError):
    pass


class InvestigationStateMachine:
    """Validates and enforces stage transitions."""

    @staticmethod
    def can_transition(current: WorkflowStage, target: WorkflowStage) -> bool:
        return target in _TRANSITIONS.get(current, set())

    @staticmethod
    def transition(current: WorkflowStage, target: WorkflowStage) -> WorkflowStage:
        if not InvestigationStateMachine.can_transition(current, target):
            raise TransitionError(
                f"Cannot transition from {current!r} to {target!r}. "
                f"Allowed: {_TRANSITIONS.get(current, set())}"
            )
        return target

    @staticmethod
    def auto_advance(
        current: WorkflowStage,
        *,
        has_findings: bool,
        has_validated: bool,
        learning_started: bool,
        knowledge_exported: bool,
    ) -> WorkflowStage:
        """Return the stage the investigation should be in given current data signals.

        This is used by InvestigationService to advance stage lazily when
        new events are recorded.
        """
        if knowledge_exported:
            return WorkflowStage.KNOWLEDGE_EXPORT
        if learning_started:
            return WorkflowStage.LEARNING
        if has_validated:
            return WorkflowStage.VALIDATION
        if has_findings:
            return WorkflowStage.DETECTION
        return current
