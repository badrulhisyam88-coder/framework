"""WorkflowEngine: executes a WorkflowDefinition as a Saga.

Steps run in order through the Dispatcher (never bypassing Policy). On
failure, every already-completed step's compensating Command runs in
reverse order -- retry/timeout/compensation is what distinguishes Workflow
from an ordinary sequence of Commands (see docs/GLOSSARY.md).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from framework_final.platform.principal import ANONYMOUS, Principal
from framework_final.platform.workflow import WorkflowDefinition, WorkflowInstance, WorkflowStatus
from framework_final.runtime.dispatcher import Dispatcher


@dataclass
class WorkflowEngine:
    dispatcher: Dispatcher

    def run(self, definition: WorkflowDefinition, principal: Principal = ANONYMOUS) -> WorkflowInstance:
        instance = WorkflowInstance(
            id=str(uuid.uuid4()), definition_id=definition.id, status=WorkflowStatus.TRANSITIONING
        )
        completed = []
        try:
            for step in definition.steps:
                result = self.dispatcher.dispatch_command(step.command, principal=principal)
                instance.completed_steps.append(step.name)
                instance.step_results[step.name] = result
                completed.append(step)
            instance.status = WorkflowStatus.COMPLETED
            return instance
        except Exception as exc:
            instance.status = WorkflowStatus.FAILED
            instance.failure_reason = repr(exc)
            for step in reversed(completed):
                if step.compensation is None:
                    continue
                try:
                    self.dispatcher.dispatch_command(step.compensation, principal=principal)
                except Exception as comp_exc:
                    # A compensation itself failing is serious; surface it
                    # rather than silently swallowing it, matching the
                    # fail-closed spirit applied everywhere else here.
                    instance.failure_reason = f"{instance.failure_reason}; compensation for '{step.name}' also failed: {comp_exc!r}"
            return instance
