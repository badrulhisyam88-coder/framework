"""documentation: auto-rendered Markdown reference for one Module,
generated from Registry.

Supplements docs/ARCHITECTURE.md; never replaces it. Narrative "why"
documentation stays hand-written -- no generator can produce the reasoning
behind a decision (see docs/ARCHITECTURE.md).
"""

from __future__ import annotations

from framework_final.registry.store import RegistryStore


def generate_module_doc(store: RegistryStore, module_id: str) -> str:
    m = store.modules.get(module_id)
    if m is None:
        raise KeyError(f"unknown Module '{module_id}'")

    lines = [f"# {m.id}", "", f"**Owner:** {m.owner}  ", f"**Status:** {m.status}", ""]

    if m.contracts:
        lines += ["## Contracts", ""]
        for c in sorted(m.contracts, key=lambda c: c.name):
            lines.append(f"- `{m.contract_full_id(c)}` ({c.kind}, {c.status}) -- {c.description}")
        lines.append("")

    if m.events:
        lines += ["## Events", ""]
        for e in sorted(m.events, key=lambda e: e.name):
            lines.append(f"- `{m.event_full_id(e)}` -- {e.description}")
        lines.append("")

    if m.policies:
        lines += ["## Policies", ""]
        for p in sorted(m.policies, key=lambda p: p.id):
            lines.append(f"- `{p.id}` (governs `{p.command}`) -- {p.description}")
        lines.append("")

    if m.required_capabilities:
        lines += ["## Required Capabilities", ""]
        for cap_id in sorted(m.required_capabilities):
            lines.append(f"- `{cap_id}`")
        lines.append("")

    if m.consumed_contracts:
        lines += ["## Consumed Contracts", ""]
        for cid in sorted(m.consumed_contracts):
            lines.append(f"- `{cid}`")
        lines.append("")

    return "\n".join(lines) + "\n"
