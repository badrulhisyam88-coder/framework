"""RegistryStore: discovers and aggregates distributed registry.yaml /
manifest.yaml / concepts.yaml files into a single, queryable view.

Registry data is distributed, not centralized: each Module, Capability, and
Application owns its own declaration file, colocated with its code. This is
what keeps "AI only reads the relevant folder" true in practice -- a single
giant registry file would itself violate the platform's own goal. This
module's job is to discover those distributed files via a known glob (never
an unbounded repository scan) and answer queries over the aggregate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import yaml

from framework_final.registry.models import (
    ApplicationRecord,
    CapabilityRecord,
    ConceptRecord,
    ContractRecord,
    ModuleRecord,
)


@dataclass
class RegistryStore:
    modules: dict[str, ModuleRecord] = field(default_factory=dict)
    capabilities: dict[str, CapabilityRecord] = field(default_factory=dict)
    applications: dict[str, ApplicationRecord] = field(default_factory=dict)
    concepts: dict[str, ConceptRecord] = field(default_factory=dict)
    sources: dict[str, Path] = field(default_factory=dict)
    """record id -> the file that declared it, for precise error messages."""

    @classmethod
    def discover(cls, roots: Iterable[Path | str]) -> "RegistryStore":
        store = cls()
        for root in roots:
            root = Path(root)
            if not root.exists():
                continue
            for registry_file in sorted(root.rglob("registry.yaml")):
                store._load_registry_file(registry_file)
            for manifest_file in sorted(root.rglob("manifest.yaml")):
                store._load_manifest_file(manifest_file)
            for concepts_file in sorted(root.rglob("concepts.yaml")):
                store._load_concepts_file(concepts_file)
        return store

    def _load_registry_file(self, path: Path) -> None:
        data = yaml.safe_load(path.read_text()) or {}
        kind = data.get("kind")
        if kind == "module":
            record = ModuleRecord.model_validate(data)
            self.modules[record.id] = record
        elif kind == "capability":
            record = CapabilityRecord.model_validate(data)
            self.capabilities[record.id] = record
        else:
            raise ValueError(
                f"{path}: registry.yaml must declare kind: module or "
                f"kind: capability, got {kind!r}"
            )
        self.sources[record.id] = path

    def _load_manifest_file(self, path: Path) -> None:
        data = yaml.safe_load(path.read_text()) or {}
        record = ApplicationRecord.model_validate(data)
        self.applications[record.id] = record
        self.sources[record.id] = path

    def _load_concepts_file(self, path: Path) -> None:
        data = yaml.safe_load(path.read_text()) or []
        for entry in data:
            record = ConceptRecord.model_validate(entry)
            self.concepts[record.id] = record
            self.sources[record.id] = path

    # -- query methods -- the mechanism that lets AI/tooling answer scope
    # and impact questions without reading code (see docs/AGENTS.md). ------

    def source_of(self, record_id: str) -> Path | None:
        return self.sources.get(record_id)

    def owner_of(self, record_id: str) -> str | None:
        for collection in (self.modules, self.capabilities, self.applications):
            rec = collection.get(record_id)
            if rec is not None:
                return rec.owner
        return None

    def all_contracts(self) -> dict[str, tuple[ModuleRecord | CapabilityRecord, ContractRecord]]:
        """full_contract_id -> (owner record, ContractRecord), across every
        Module and Capability.
        """
        out: dict[str, tuple[ModuleRecord | CapabilityRecord, ContractRecord]] = {}
        for m in self.modules.values():
            for c in m.contracts:
                out[m.contract_full_id(c)] = (m, c)
        for cap in self.capabilities.values():
            for c in cap.contracts:
                out[cap.contract_full_id(c)] = (cap, c)
        return out

    def all_event_ids(self) -> set[str]:
        return {m.event_full_id(e) for m in self.modules.values() for e in m.events}

    def find_contract(self, contract_id: str) -> tuple[ModuleRecord | CapabilityRecord, ContractRecord] | None:
        return self.all_contracts().get(contract_id)

    def consumers_of_contract(self, contract_id: str) -> list[str]:
        """Every Module that declares `contract_id` in consumed_contracts --
        the mechanical, always-current answer to "what breaks if I remove
        this Contract", replacing hand-maintained impact analysis.
        """
        return sorted(m.id for m in self.modules.values() if contract_id in m.consumed_contracts)

    def consumers_of_event(self, event_id: str) -> list[str]:
        return sorted(m.id for m in self.modules.values() if event_id in m.subscribed_events)

    def module_footprint(self, module_id: str) -> ModuleRecord | None:
        return self.modules.get(module_id)
