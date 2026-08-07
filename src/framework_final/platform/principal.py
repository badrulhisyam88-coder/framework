"""Principal: an identity that can be authenticated and authorized to invoke
a Command.

Deliberately distinct from Python's own notion of a concurrency "actor" and
from any specific auth technology (that terminology collision is why this
platform calls the concept Principal, not Actor -- see docs/GLOSSARY.md). A
Principal is generic by rule -- it must never carry domain-specific fields
(no "PatientPrincipal"). Domain identity concerns belong to a Module's own
Entity, which may *reference* a Principal by id but is never one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PrincipalStatus(str, Enum):
    PROVISIONED = "provisioned"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEPROVISIONED = "deprovisioned"


@dataclass(frozen=True)
class Principal:
    """A caller: human or system. `roles` is the only domain-agnostic
    grouping mechanism Platform provides; Policy rules are what actually
    decide whether a given Principal may invoke a given Command.
    """

    id: str
    status: PrincipalStatus = PrincipalStatus.ACTIVE
    roles: frozenset[str] = field(default_factory=frozenset)

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def is_active(self) -> bool:
        return self.status is PrincipalStatus.ACTIVE


ANONYMOUS = Principal(id="anonymous", status=PrincipalStatus.ACTIVE, roles=frozenset())
"""The Principal used when no authenticated caller is available. Carries no
roles, so it is denied by every Policy that isn't explicitly opted open --
fail-closed by construction, not by convention.
"""
