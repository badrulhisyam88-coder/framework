"""Policy rules for example_task_module. Rule *content* is owned by the
Module; Platform only owns the enforcement seam (runtime/policy_enforcer.py).
"""

from __future__ import annotations

from framework_final.platform.policy import PolicyResult
from framework_final.platform.principal import Principal


def create_task_policy(principal: Principal, command_name: str, entity: object) -> PolicyResult:
    """Any active Principal may create a Task -- deliberately permissive
    for the example; a real Application would likely restrict this further
    (e.g. to Principals with a specific role).
    """
    if not principal.is_active():
        return PolicyResult.deny("principal is not active")
    return PolicyResult.allow()


def list_tasks_policy(principal: Principal, command_name: str, entity: object) -> PolicyResult:
    if not principal.is_active():
        return PolicyResult.deny("principal is not active")
    return PolicyResult.allow()
