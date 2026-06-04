"""Seam tests: default configuration values must permit the feature to function.

Pattern: SILENTLY-DISABLING DEFAULT (PR D-fix-2 bug)
  Bug example: max_chain_depth=0 was set as the "safe" default in Conductor.
    A depth of 0 means "do not dispatch any chain actions." The Chain Orchestrator
    evaluated next_actions but immediately returned without dispatching because
    depth 0 means "at or above max depth." Plugins ran against wrong ports.
    The fix bumped max_chain_depth=3 in runtime.py.

  Test assertion: default configuration values for features must permit the
  feature to actually execute a non-trivial code path.
"""
from __future__ import annotations


def test_default_max_chain_depth_permits_chain_dispatch():
    """The max_chain_depth passed to Conductor in runtime.py must be > 0.

    A value of 0 silently disables the entire chain dispatch path — no
    next_actions are ever fired. This guard ensures the configured value
    actually permits chain operations.
    """
    import ast

    with open("apps/investigation_workspace/bootstrap/runtime.py") as f:
        src = f.read()

    assert "max_chain_depth" in src, (
        "max_chain_depth not configured in runtime.py — expected explicit setting"
    )
    # Find the value passed
    tree = ast.parse(src)
    values_found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "max_chain_depth":
            if isinstance(node.value, ast.Constant):
                values_found.append(node.value.value)

    # max_chain_depth is passed as a dict key: {"max_chain_depth": N}
    # Fall back to regex search when AST keyword search finds nothing
    if not values_found:
        import re
        for m in re.finditer(r'"max_chain_depth"\s*:\s*(\d+)', src):
            values_found.append(int(m.group(1)))

    assert values_found, (
        "max_chain_depth not found in runtime.py (checked keyword args and dict literals)"
    )
    for v in values_found:
        assert isinstance(v, int) and v > 0, (
            f"max_chain_depth={v} — a value of 0 silently disables chain dispatch entirely. "
            "Must be > 0 for chain next_actions to fire."
        )


def test_filter_orchestrator_runs_after_enumeration_not_recon():
    """FilterOrchestrator must be wired to run after enumeration, not recon.

    Running after recon misses all chain-dispatched enumeration engine findings
    (sqli_recon, auth_recon, api_recon). This is the timing bug fixed in PR K.
    """
    with open("apps/conductor/conductor.py") as f:
        src = f.read()

    assert 'if phase == "enumeration"' in src, (
        "FilterOrchestrator phase guard should check 'enumeration', not 'recon'. "
        "After recon, chain-dispatched findings haven't arrived yet."
    )
    assert 'if phase == "recon"' not in src, (
        "FilterOrchestrator is still guarded on the 'recon' phase — "
        "this is the timing bug from before PR K."
    )
