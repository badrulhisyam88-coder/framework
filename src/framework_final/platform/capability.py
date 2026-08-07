"""Capability: the Meta-Model type. Platform defines both the *descriptor*
shape (what a Capability must declare in Registry) and the *behavioral*
contract (CapabilityBase) any concrete implementation must satisfy.

Both live here, not in a separate capabilities/ package, because Runtime
needs to reference CapabilityBase to orchestrate Capabilities at all --
that need is exactly what "Platform defines what a Capability must declare
to be valid" means in practice (see docs/ARCHITECTURE.md, the type-vs-layer
note). Concrete Capability *implementations* live in /examples, subclassing
CapabilityBase directly; there is no intermediate framework package.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from framework_final.platform.contract import Command, Query


class CapabilityStatus(str, Enum):
    REGISTERED = "registered"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REMOVED = "removed"


@dataclass(frozen=True)
class CapabilityDescriptor:
    """What Platform requires a Capability to declare about itself. Must
    never reference a Module -- a Capability that needs to is not actually
    domain-agnostic, and should not be a Capability.
    """

    id: str
    owner: str
    fulfills_contracts: tuple[str, ...] = field(default_factory=tuple)
    status: CapabilityStatus = CapabilityStatus.REGISTERED


class CapabilityBase(ABC):
    """Every Capability implements this. `capability_id` must match the
    `id` declared in this Capability's own registry.yaml -- Runtime uses it
    to bind the two together at boot (see runtime/boot.py). A concrete
    implementation must never import from a Module or a sibling example
    (enforced by dependency_rules.check_examples_isolation) -- "invoked
    only through Contracts" means a Capability never even sees a Module's
    code, only Command/Query objects.
    """

    capability_id: str

    def on_activate(self) -> None:
        """Called once by Runtime when bound into a running Application."""

    def on_deactivate(self) -> None:
        """Called once by Runtime on graceful shutdown."""

    def health_check(self) -> bool:
        """Cheap liveness check Runtime can call generically across every
        Capability, regardless of what it does internally.
        """
        return True

    @abstractmethod
    def handle_command(self, command: Command) -> Any:
        """Execute one Command declared by this Capability's Contract."""

    def handle_query(self, query: Query) -> Any:
        """Execute one Query declared by this Capability's Contract.
        Default raises -- most Capabilities only need Commands.
        """
        raise NotImplementedError(f"{self.capability_id} does not implement any Query")
