"""ai_context: the generated AI context bundle for one Module.

This is the primary artifact AI should read to scope a task -- one lookup
instead of five separate Registry queries (see docs/AGENTS.md). A real
deployment would additionally stamp this with a commit hash for a
freshness check; this skeleton stamps it with the declaring file's path,
which is enough to prove the mechanism.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from framework_final.discovery.index import scan
from framework_final.registry.store import RegistryStore


def generate(store: RegistryStore, module_id: str, discovery_roots: Iterable[Path] = ()) -> str:
    module = store.modules.get(module_id)
    if module is None:
        raise KeyError(f"unknown Module '{module_id}'")

    source = store.source_of(module_id)
    file_scope: list[str] = []
    if source is not None:
        index = scan(source.parent)
        file_scope = [str(p) for p in index.all_files()]

    consumers: set[str] = set()
    for c in module.contracts:
        consumers.update(store.consumers_of_contract(module.contract_full_id(c)))

    bundle = {
        "module_id": module.id,
        "owner": module.owner,
        "status": module.status,
        "published_contracts": sorted(module.contract_full_id(c) for c in module.contracts),
        "consumed_contracts": sorted(module.consumed_contracts),
        "published_events": sorted(module.event_full_id(e) for e in module.events),
        "subscribed_events": sorted(module.subscribed_events),
        "required_capabilities": sorted(module.required_capabilities),
        "consumers_of_this_module": sorted(consumers),
        "file_scope": sorted(file_scope),
        "source_declaration": str(source) if source else None,
    }
    return json.dumps(bundle, indent=2, sort_keys=True) + "\n"
