"""Seam tests: resource-class-aware policies apply the right limits.

Pattern: RESOURCE-CLASS-BLIND POLICY (PR G bug: watchdog kills nuclei)
  Bug example: ExecutionOrchestrator had a flat 30s watchdog threshold for all
    engines. nuclei runs a blocking subprocess that easily takes 60-300s.
    The watchdog killed nuclei at 30s while it was still scanning, silently
    returning 0 findings. The fix differentiated thresholds by resource_cost:
    heavy → 600s, light/medium → 30s.

  Test assertion: policies that use resource_cost for differentiated limits
  actually apply different limits; heavy engines get heavy-cost thresholds.
"""
from __future__ import annotations


def test_heavy_engines_get_extended_watchdog_threshold():
    """ExecutionOrchestrator must use _HUNG_THRESHOLD_HEAVY for heavy engines.

    Any engine declaring resource_cost='heavy' runs long blocking subprocess calls.
    A 30s threshold would kill it mid-scan. This test verifies the differentiation
    logic exists and would apply the correct threshold.
    """
    import inspect

    from apps.conductor.orchestrators.execution import ExecutionOrchestrator

    src = inspect.getsource(ExecutionOrchestrator)
    assert "_HUNG_THRESHOLD_HEAVY" in src, (
        "ExecutionOrchestrator does not reference _HUNG_THRESHOLD_HEAVY. "
        "Heavy engines (nmap, nuclei, zap) would be killed by the light threshold."
    )
    assert "resource_cost" in src, (
        "ExecutionOrchestrator does not branch on resource_cost. "
        "All engines would use the same threshold regardless of cost class."
    )


def test_threshold_values_are_differentiated():
    """Heavy threshold must be substantially larger than light threshold.

    If both thresholds are the same value, the differentiation has no effect.
    """
    from apps.conductor.orchestrators.execution import (
        _HUNG_THRESHOLD_HEAVY,
        _HUNG_THRESHOLD_LIGHT,
    )

    assert _HUNG_THRESHOLD_HEAVY > _HUNG_THRESHOLD_LIGHT, (
        f"_HUNG_THRESHOLD_HEAVY ({_HUNG_THRESHOLD_HEAVY}) must be > "
        f"_HUNG_THRESHOLD_LIGHT ({_HUNG_THRESHOLD_LIGHT})"
    )
    assert _HUNG_THRESHOLD_HEAVY >= 300, (
        f"_HUNG_THRESHOLD_HEAVY={_HUNG_THRESHOLD_HEAVY}s is too low. "
        "nuclei/nmap/zap can take 300+ seconds on real targets."
    )


def test_heavy_engines_declare_correct_resource_cost():
    """nmap, nuclei, zap must declare resource_cost='heavy'.

    Without 'heavy' declaration, they'd use the 30s threshold and be killed
    before finishing. This test enumerates the known heavy subprocess engines.
    """
    import apps.conductor.engines  # noqa: F401
    from apps.conductor.engines.base import engine_registry

    heavy_engine_ids = {"nmap", "nuclei", "zap"}
    for eid in heavy_engine_ids:
        engine = engine_registry.get(eid)
        if engine is None:
            continue  # engine may be gate-disabled; skip
        cost = getattr(engine.capabilities, "resource_cost", None)
        assert cost == "heavy", (
            f"Engine '{eid}' has resource_cost={cost!r}, expected 'heavy'. "
            f"With a light/medium cost class, the {_get_threshold_light()}s watchdog "
            "would kill it mid-scan."
        )


def _get_threshold_light():
    from apps.conductor.orchestrators.execution import _HUNG_THRESHOLD_LIGHT
    return _HUNG_THRESHOLD_LIGHT
