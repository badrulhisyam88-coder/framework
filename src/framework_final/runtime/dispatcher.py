"""Dispatcher: the Command/Query execution pipeline.

Command: resolve owner -> Policy check (fail-closed) -> handler -> publish
resulting Events. A Command's entry point is always a Module's Contract --
a Capability is only ever invoked *from within* a Module's own handler
(via container.capability(id)), never dispatched to directly from outside,
since it is already downstream of that Module's own Policy gate.

Query: resolve owner -> Policy check only if the owner is a Module (a
Capability has no Policy rules of its own, consistent with Capabilities
never owning Concept Model entries either) -> handler -> return.
"""

from __future__ import annotations

from dataclasses import dataclass

from framework_final.platform.module import ModuleBase
from framework_final.platform.contract import Command, Query
from framework_final.platform.policy import PolicyResult
from framework_final.platform.principal import ANONYMOUS, Principal
from framework_final.runtime.container import Container
from framework_final.runtime.event_bus import EventBus
from framework_final.runtime.policy_enforcer import PolicyEnforcer


class CommandDenied(PermissionError):
    def __init__(self, result: PolicyResult) -> None:
        super().__init__(result.reason)
        self.result = result


class InvalidDispatch(TypeError):
    pass


@dataclass
class Dispatcher:
    container: Container
    event_bus: EventBus
    policy_enforcer: PolicyEnforcer

    def dispatch_command(self, command: Command, principal: Principal = ANONYMOUS):
        owner = self.container.owner_of_contract(str(command.contract_id))
        if not isinstance(owner, ModuleBase):
            raise InvalidDispatch(
                f"{command.contract_id} is owned by a Capability, not a Module -- "
                "a Capability Command is invoked from within a Module's handler, "
                "not dispatched to directly"
            )
        decision = self.policy_enforcer.evaluate(owner, principal, command.contract_id.name)
        if not decision.allowed:
            raise CommandDenied(decision)
        result, events = owner.handle_command(command)
        for event in events:
            self.event_bus.publish(event)
        return result

    def dispatch_query(self, query: Query, principal: Principal = ANONYMOUS):
        owner = self.container.owner_of_contract(str(query.contract_id))
        if isinstance(owner, ModuleBase):
            decision = self.policy_enforcer.evaluate(owner, principal, query.contract_id.name)
            if not decision.allowed:
                raise CommandDenied(decision)
        return owner.handle_query(query)
