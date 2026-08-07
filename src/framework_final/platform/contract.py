"""Contract: a versioned, published, governed interface at a boundary.

Carries exactly one operation-kind: Command (a request to change state, one
handler, synchronous result) or Query (a read of a projection, no side
effects). This is the *only* sanctioned mechanism for cross-boundary
communication -- there is no separate "Action" or "View" concept in this
platform; both are folded in here as operation-kinds of one governed
artifact (see docs/GLOSSARY.md, retired terms).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ContractKind(str, Enum):
    COMMAND = "command"
    QUERY = "query"


class ContractStatus(str, Enum):
    PROPOSED = "proposed"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


@dataclass(frozen=True)
class ContractId:
    """A Contract's stable identity is (owner_id, name, major_version) --
    never the display name alone, matching the identity-vs-label discipline
    the Concept Model also follows.
    """

    owner_id: str
    name: str
    major_version: int = 1

    def __str__(self) -> str:
        return f"{self.owner_id}.{self.name}.v{self.major_version}"


@dataclass(frozen=True)
class Contract:
    id: ContractId
    kind: ContractKind
    status: ContractStatus = ContractStatus.PROPOSED
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    produces_events: tuple[str, ...] = field(default_factory=tuple)
    """Event types a Command on this Contract may emit. Must be empty for a
    Query -- a Query must never have side effects.
    """

    def __post_init__(self) -> None:
        if self.kind is ContractKind.QUERY and self.produces_events:
            raise ValueError(
                f"Contract {self.id} is a Query but declares produces_events; "
                "a Query must never have side effects."
            )


@dataclass(frozen=True)
class Command:
    """A request to change state, addressed to one handler, expecting a
    synchronous result. Named as an imperative (CreateTask), never past
    tense -- the Event this Command may produce is what gets the past tense
    (TaskCreated).
    """

    contract_id: ContractId
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Query:
    """A request to read a projection of state. No side effects, no Events."""

    contract_id: ContractId
    parameters: dict[str, Any] = field(default_factory=dict)
