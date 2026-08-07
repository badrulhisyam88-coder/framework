"""ExampleTaskModule: the one demonstration Module, proving the full stack
-- Entity, Contract (Command + Query), Event, Policy, Concept Model -- works
end to end. Not part of the platform itself; see docs/ARCHITECTURE.md.

Note how it reaches its required Capability: through `container.capability(
"example_logging")`, resolved by Runtime at construction time -- never by
importing examples.example_capability directly. That is what "invoked only
through Contracts" means in practice, and it is what
platform/dependency_rules.py:check_examples_isolation verifies.
"""

from __future__ import annotations

from typing import Any

from framework_final.platform.contract import Command, ContractId, Query
from framework_final.platform.event import Event
from framework_final.platform.module import ModuleBase
from framework_final.platform.policy import PolicyRule
from framework_final.runtime.container import Container

from .entities import Task
from .policies import create_task_policy, list_tasks_policy


class ExampleTaskModule(ModuleBase):
    module_id = "example_task_module"

    def __init__(self, container: Container) -> None:
        self._tasks: dict[str, Task] = {}
        self._logging = container.capability("example_logging")

    def handle_command(self, command: Command) -> tuple[Any, list[Event]]:
        name = command.contract_id.name
        if name == "create_task":
            return self._create_task(command)
        raise NotImplementedError(f"{self.module_id} has no handler for command '{name}'")

    def _create_task(self, command: Command) -> tuple[dict[str, Any], list[Event]]:
        task = Task(
            title=command.payload["title"],
            assignee_principal_id=command.payload["assignee_principal_id"],
        )
        self._tasks[task.id] = task

        self._logging.handle_command(
            Command(
                contract_id=ContractId(owner_id="example_logging", name="log_event"),
                payload={"level": "info", "message": f"task created: {task.id}"},
            )
        )

        event = Event(
            event_type="example_task_module.task_created",
            payload={
                "task_id": task.id,
                "title": task.title,
                "assignee_principal_id": task.assignee_principal_id,
            },
            published_by=self.module_id,
        )
        return {"task_id": task.id}, [event]

    def handle_query(self, query: Query) -> Any:
        name = query.contract_id.name
        if name == "list_tasks":
            assignee = query.parameters.get("assignee_principal_id")
            tasks = [t for t in self._tasks.values() if assignee is None or t.assignee_principal_id == assignee]
            return [{"task_id": t.id, "title": t.title, "done": t.done} for t in tasks]
        raise NotImplementedError(f"{self.module_id} has no handler for query '{name}'")

    def policy_rules(self) -> dict[str, PolicyRule]:
        return {
            "create_task": create_task_policy,
            "list_tasks": list_tasks_policy,
        }
