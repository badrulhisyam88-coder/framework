"""The Registry schema. These pydantic models *are* the schema -- there is no
separate hand-maintained JSON-Schema file duplicating the same shape, since
any duplicated declarative content is itself a drift risk (see
docs/ARCHITECTURE.md).

A Contract/Event is declared nested inside the Module or Capability that
owns it, never in a separate file -- so understanding one Module never
requires reading more than its own registry.yaml.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

ContractKindLiteral = Literal["command", "query"]
ContractStatusLiteral = Literal["proposed", "published", "deprecated", "retired"]
ModuleStatusLiteral = Literal["proposed", "registered", "active", "deprecated", "removed"]
CapabilityStatusLiteral = Literal["registered", "active", "deprecated", "removed"]
ApplicationStatusLiteral = Literal["initialized", "composed", "running", "retired"]
ConceptStatusLiteral = Literal["active", "deprecated", "removed"]
MetaModelType = Literal["Entity", "Principal", "Event", "Policy", "Contract", "Workflow"]


class ContractRecord(BaseModel):
    """One operation-kind (Command or Query) published by its owning Module
    or Capability. Full identity is `<owner_id>.<name>.v<major_version>`,
    computed by the owner -- never stored redundantly here.
    """

    name: str
    kind: ContractKindLiteral
    major_version: int = 1
    status: ContractStatusLiteral = "proposed"
    description: str = ""
    produces_events: list[str] = Field(default_factory=list)


class EventRecord(BaseModel):
    """One Event type published by its owning Module. Full identity is
    `<owner_id>.<name>`.
    """

    name: str
    description: str = ""


class PolicyRecordEntry(BaseModel):
    """One Policy rule, bound to a Command declared by the same owning
    Module. `command` refers to that Contract's `name`, not its full id --
    a Policy only ever governs a Command its own Module declared.
    """

    id: str
    command: str
    description: str = ""


class ModuleRecord(BaseModel):
    """A Module owns Entities (not modeled in Registry -- code, not
    declaration), Contracts, Events, Policies, and its own Concept Model
    entries. `consumed_contracts` / `subscribed_events` reference *other*
    Modules' or Capabilities' full ids -- a Module never references another
    Module's internals, only its published surface.
    """

    kind: Literal["module"] = "module"
    id: str
    owner: str
    status: ModuleStatusLiteral = "proposed"
    required_capabilities: list[str] = Field(default_factory=list)
    contracts: list[ContractRecord] = Field(default_factory=list)
    events: list[EventRecord] = Field(default_factory=list)
    policies: list[PolicyRecordEntry] = Field(default_factory=list)
    consumed_contracts: list[str] = Field(default_factory=list)
    subscribed_events: list[str] = Field(default_factory=list)

    def contract_full_id(self, contract: ContractRecord) -> str:
        return f"{self.id}.{contract.name}.v{contract.major_version}"

    def event_full_id(self, event: EventRecord) -> str:
        return f"{self.id}.{event.name}"


class CapabilityRecord(BaseModel):
    """A Capability is reusable, swappable, domain-agnostic, and optional.
    It publishes Contracts like a Module does, but must never declare
    `consumed_contracts` pointing at a Module, and never owns Concept Model
    entries -- both are enforced by the Validator, not just documented here.
    """

    kind: Literal["capability"] = "capability"
    id: str
    owner: str
    status: CapabilityStatusLiteral = "registered"
    contracts: list[ContractRecord] = Field(default_factory=list)

    def contract_full_id(self, contract: ContractRecord) -> str:
        return f"{self.id}.{contract.name}.v{contract.major_version}"


class ApplicationRecord(BaseModel):
    """A named composition of Modules and Capabilities. Contains no business
    logic and declares no Contracts/Events/Concepts of its own.
    """

    kind: Literal["application"] = "application"
    id: str
    owner: str
    status: ApplicationStatusLiteral = "initialized"
    modules: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)


class ConceptRecord(BaseModel):
    """One canonical business term. Identity (`id`) is permanent and
    namespace-qualified by scope; `label` is the human-readable display
    name and may be relabeled freely without breaking any reference to
    `id`. Exactly three relationship types are allowed -- this is
    deliberately not an open-ended ontology (see docs/ARCHITECTURE.md).
    """

    id: str
    label: str
    definition: str
    meta_model_type: MetaModelType
    owner_module: str
    scope: str
    aliases: list[str] = Field(default_factory=list)
    specializes: str | None = None
    references: list[str] = Field(default_factory=list)
    supersedes: str | None = None
    status: ConceptStatusLiteral = "active"
    sunset_date: str | None = None
