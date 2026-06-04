"""Seam tests: every reference points to something that exists.

Pattern: DANGLING REFERENCE (PR G bug: cve_lookup placeholder)
  Bug example: nmap emitted cve_lookup next_actions on every service_detected
    finding. The CVE matcher chain was explicitly dropped — no engine with
    engine_id='cve_lookup' existed. Dead next_actions wasted Chain Orchestrator
    cycles and polluted finding records. The fix removed the emission.

  Test assertion: every next_action.engine_id references a registered engine.
  Every gate_id referenced by engines exists in the gate registry.
"""
from __future__ import annotations


def _get_all_engines():
    """Return all registered engine instances."""
    import apps.conductor.engines  # noqa: F401 — triggers registration
    from apps.conductor.engines.base import engine_registry
    return list(engine_registry._engines.values())


def _get_all_gate_ids():
    from apps.conductor.gates import list_gates
    return {g["gate_id"] for g in list_gates()}


def test_every_engine_gate_id_in_registry():
    """Every gate_id / gate_ids declared by an engine must exist in the gate registry.

    An engine with an unknown gate_id is fail-closed (never dispatched), but it
    should fail at startup validation — not silently disappear from investigations.
    This test is the early warning before startup validation catches it.
    """
    all_gate_ids = _get_all_gate_ids()
    engines = _get_all_engines()
    violations = []
    for eng in engines:
        # Multi-gate engines
        gate_ids = getattr(eng, "gate_ids", None)
        if gate_ids:
            for gid in gate_ids:
                if gid not in all_gate_ids:
                    violations.append(f"{eng.engine_id}: gate_ids contains unknown '{gid}'")
        # Single-gate engines
        gate_id = getattr(eng, "gate_id", None)
        if gate_id and gate_id not in all_gate_ids:
            violations.append(f"{eng.engine_id}: gate_id '{gate_id}' not in registry")

    assert not violations, (
        "Engines reference unknown gate IDs:\n" + "\n".join(violations)
    )


def test_every_next_action_engine_references_registered_engine():
    """Static next_actions emitted by engines must reference registered engine_ids.

    Dead references (like cve_lookup after that chain was dropped) waste Chain
    Orchestrator cycles and produce confusing investigation logs.
    This test checks next_actions embedded in engine source code (static checks).
    """
    import re

    import apps.conductor.engines  # noqa: F401
    from apps.conductor.engines.base import engine_registry

    registered_ids = set(engine_registry._engines.keys())
    # Also allow well-known probe IDs used in legacy next_actions
    registered_ids.update({"sqli_recon", "auth_recon", "api_recon", "cmdi_recon"})

    import os

    engine_files = [
        f for f in os.listdir("apps/conductor/engines")
        if f.endswith("_engine.py") and not f.startswith("mock")
    ]
    violations = []
    for fname in engine_files:
        with open(f"apps/conductor/engines/{fname}") as fh:
            src = fh.read()
        # Find all "engine_id": "xxx" patterns in next_actions dicts
        for match in re.finditer(r'"engine_id"\s*:\s*"([^"]+)"', src):
            eid = match.group(1)
            if eid not in registered_ids:
                violations.append(f"{fname}: next_action references unregistered engine_id='{eid}'")

    assert not violations, (
        "Engines emit next_actions referencing unregistered engine_ids:\n"
        + "\n".join(violations)
    )
