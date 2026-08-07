"""dependency_graph: who-depends-on-what, generated from Registry.

Deterministic and disposable -- regenerate any time, never hand-edit.
Output carries zero authority: if it ever disagrees with Registry, Registry
wins and the disagreement is drift to fix (see registry/validator.py check
#8).
"""

from __future__ import annotations

import json

from framework_final.registry.store import RegistryStore


def generate(store: RegistryStore) -> str:
    nodes: list[dict[str, str]] = []
    edges: list[dict[str, str | None]] = []

    for m in sorted(store.modules.values(), key=lambda r: r.id):
        nodes.append({"id": m.id, "type": "module", "owner": m.owner, "status": m.status})
    for c in sorted(store.capabilities.values(), key=lambda r: r.id):
        nodes.append({"id": c.id, "type": "capability", "owner": c.owner, "status": c.status})
    for a in sorted(store.applications.values(), key=lambda r: r.id):
        nodes.append({"id": a.id, "type": "application", "owner": a.owner, "status": a.status})

    all_contracts = store.all_contracts()
    for m in sorted(store.modules.values(), key=lambda r: r.id):
        for cid in sorted(m.consumed_contracts):
            info = all_contracts.get(cid)
            if info is not None:
                edges.append({"from": m.id, "to": info[0].id, "via": cid, "kind": "consumes_contract"})
        for cap_id in sorted(m.required_capabilities):
            edges.append({"from": m.id, "to": cap_id, "via": None, "kind": "requires_capability"})
        for eid in sorted(m.subscribed_events):
            owner_id = eid.rsplit(".", 1)[0]
            edges.append({"from": m.id, "to": owner_id, "via": eid, "kind": "subscribes_event"})
    for a in sorted(store.applications.values(), key=lambda r: r.id):
        for mod_id in sorted(a.modules):
            edges.append({"from": a.id, "to": mod_id, "via": None, "kind": "composes_module"})
        for cap_id in sorted(a.capabilities):
            edges.append({"from": a.id, "to": cap_id, "via": None, "kind": "composes_capability"})

    return json.dumps({"nodes": nodes, "edges": edges}, indent=2, sort_keys=True) + "\n"
