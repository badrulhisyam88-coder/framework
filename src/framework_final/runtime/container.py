"""DI container: binds a Contract id to the concrete Capability/Module
instance that fulfills it.

A Module never constructs its own Capability instance -- it only declares
which Contract it needs (registry.yaml's `required_capabilities`); Runtime
resolves it here at boot time (see runtime/boot.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from framework_final.platform.capability import CapabilityBase
from framework_final.platform.module import ModuleBase


class UnresolvedContractError(LookupError):
    pass


@dataclass
class Container:
    _capabilities: dict[str, CapabilityBase] = field(default_factory=dict)
    _modules: dict[str, ModuleBase] = field(default_factory=dict)

    def register_capability(self, instance: CapabilityBase) -> None:
        self._capabilities[instance.capability_id] = instance

    def register_module(self, instance: ModuleBase) -> None:
        self._modules[instance.module_id] = instance

    def has_capability(self, capability_id: str) -> bool:
        return capability_id in self._capabilities

    def has_module(self, module_id: str) -> bool:
        return module_id in self._modules

    def capability(self, capability_id: str) -> CapabilityBase:
        try:
            return self._capabilities[capability_id]
        except KeyError:
            raise UnresolvedContractError(
                f"no active Capability registered for id '{capability_id}'"
            ) from None

    def module(self, module_id: str) -> ModuleBase:
        try:
            return self._modules[module_id]
        except KeyError:
            raise UnresolvedContractError(f"no active Module registered for id '{module_id}'") from None

    def owner_of_contract(self, contract_id: str) -> ModuleBase | CapabilityBase:
        """`contract_id` is `<owner_id>.<name>.v<major>`; resolve to
        whichever registered Module or Capability owns it. Assumes owner
        ids themselves contain no dots, which holds for every id in this
        Registry's naming convention.
        """
        owner_id = contract_id.split(".")[0]
        if owner_id in self._modules:
            return self._modules[owner_id]
        if owner_id in self._capabilities:
            return self._capabilities[owner_id]
        raise UnresolvedContractError(f"no active Module or Capability owns contract '{contract_id}'")
