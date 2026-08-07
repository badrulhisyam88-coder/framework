"""Module: the Meta-Model type. Platform defines both the *descriptor*
shape (what a Module must declare in Registry) and the *behavioral*
contract (ModuleBase) any concrete implementation must satisfy.

Both live here, not in a separate modules/ package, for the same reason as
Capability (see platform/capability.py) -- Runtime needs ModuleBase to
orchestrate Modules at all. Concrete Module implementations live in
/examples, subclassing ModuleBase directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from framework_final.platform.contract import Command, Query
from framework_final.platform.event import Event
from framework_final.platform.policy import PolicyRule


class ModuleStatus(str, Enum):
    PROPOSED = "proposed"
    REGISTERED = "registered"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REMOVED = "removed"


@dataclass(frozen=True)
class ModuleDescriptor:
    """A Module owns Entities, Contracts, Events, business logic, and its own
    Concept Model entries -- nothing outside. It must never declare a
    dependency on another Module directly, only on that Module's published
    Contract or Event (see consumed_contracts / subscribed_events).
    """

    id: str
    owner: str
    published_contracts: tuple[str, ...] = field(default_factory=tuple)
    consumed_contracts: tuple[str, ...] = field(default_factory=tuple)
    published_events: tuple[str, ...] = field(default_factory=tuple)
    subscribed_events: tuple[str, ...] = field(default_factory=tuple)
    required_capabilities: tuple[str, ...] = field(default_factory=tuple)
    status: ModuleStatus = ModuleStatus.PROPOSED


class ModuleBase(ABC):
    """Every Module implements this. `module_id` must match the `id`
    declared in this Module's own registry.yaml. A concrete implementation
    must never import a sibling example (enforced by
    dependency_rules.check_examples_isolation) -- a Module depends on
    another Module only through that Module's published Contract or Event,
    brokered by Runtime, never a direct Python import.
    """

    module_id: str

    @abstractmethod
    def handle_command(self, command: Command) -> tuple[Any, list[Event]]:
        """Execute one Command this Module publishes.

        Returns (result, events) -- the Events this execution produced. A
        Module never publishes Events directly; Runtime's dispatcher is
        responsible for publishing them after the Command commits, which is
        what keeps Command-execution and Event-publication auditable in one
        seam.
        """

    def handle_query(self, query: Query) -> Any:
        raise NotImplementedError(f"{self.module_id} does not implement any Query")

    def on_event(self, event: Event) -> None:
        """Called by Runtime for every Event this Module has subscribed to.
        Default is a no-op -- override only for Modules that react to other
        Modules' Events.
        """

    def policy_rules(self) -> dict[str, PolicyRule]:
        """command_name -> rule callable. Runtime's policy_enforcer looks
        these up before invoking handle_command. Default: no rules, which
        means every Command on this Module denies by default (fail-closed)
        until the Module explicitly supplies one -- matching
        registry/validator.py's policy_coverage check, which flags a
        Command with no declared Policy rather than letting it silently
        rely on the default deny.
        """
        return {}
