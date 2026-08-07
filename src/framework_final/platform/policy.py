"""Policy: a rule governing whether a Principal may invoke a given Command
against a given Entity.

Platform owns the enforcement seam -- every Command passes through Policy
before executing (see runtime/dispatcher.py). Rule *content* is owned by the
Module, or by a Policy-evaluation Capability. Fails closed: an unresolved
decision is always a deny, never an allow.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Protocol

from framework_final.platform.principal import Principal


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @staticmethod
    def deny(reason: str = "no matching policy") -> "PolicyResult":
        return PolicyResult(decision=Decision.DENY, reason=reason)

    @staticmethod
    def allow(reason: str = "") -> "PolicyResult":
        return PolicyResult(decision=Decision.ALLOW, reason=reason)


PolicyRule = Callable[[Principal, str, object], "PolicyResult"]
"""A Policy rule: (principal, command_id, entity_or_none) -> PolicyResult.

Kept as a plain callable rather than a rules-DSL by design: the Concept
Model and Policy deliberately stay this lightweight instead of claiming
ontology-grade inference we would never actually build (see
docs/ARCHITECTURE.md, "why not Ontology").
"""


class Policy(Protocol):
    """What a Module or Policy-evaluation Capability must provide: a way to
    evaluate the rule bound to a given command_id.
    """

    def evaluate(
        self, principal: Principal, command_id: str, entity: object = None
    ) -> PolicyResult: ...
