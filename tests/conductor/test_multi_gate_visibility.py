"""Multi-gate engine visibility tests — PR E verification.

Tests:
  1. multi_gate_engine_visible_when_any_gate_on — engine_is_visible returns
     True when at least one gate_ids entry is ON.
  2. multi_gate_engine_invisible_when_all_gates_off — engine_is_visible
     returns False when every gate_ids entry is OFF.
  3. both_gate_id_and_gate_ids_is_fail_closed — engine declaring both
     gate_id and gate_ids is treated as misconfigured → False.
  4. nuclei_excluded_from_dispatch_when_all_severity_gates_off — dispatch_phase
     does not include nuclei when all nuclei_severity_* gates are OFF.
"""
from __future__ import annotations

import pytest

from apps.conductor.gates import engine_is_visible, reset_all_gates_to_defaults, set_gate


@pytest.fixture(autouse=True)
def reset_gates():
    reset_all_gates_to_defaults()
    yield
    reset_all_gates_to_defaults()


# ── Stub engines ──────────────────────────────────────────────────────────────

class _MultiGateEngine:
    engine_id = "multi_gate_stub"
    gate_ids = ("nuclei_severity_info", "nuclei_severity_high")
    gate_id = None  # explicitly absent


class _BothGateEngine:
    """Misconfigured: declares both gate_id and gate_ids."""
    engine_id = "both_gate_stub"
    gate_id = "nmap_external_scan"
    gate_ids = ("nuclei_severity_info",)


# ── Test 1 ────────────────────────────────────────────────────────────────────

def test_multi_gate_engine_visible_when_any_gate_on():
    """engine_is_visible returns True when at least one gate in gate_ids is ON."""
    # Default: nuclei_severity_info=ON, nuclei_severity_high=OFF
    engine = _MultiGateEngine()
    assert engine_is_visible(engine) is True, (
        "engine_is_visible should return True when nuclei_severity_info gate is ON"
    )


# ── Test 2 ────────────────────────────────────────────────────────────────────

def test_multi_gate_engine_invisible_when_all_gates_off():
    """engine_is_visible returns False when all gate_ids entries are OFF."""
    set_gate("nuclei_severity_info", False)
    set_gate("nuclei_severity_high", False)

    engine = _MultiGateEngine()
    assert engine_is_visible(engine) is False, (
        "engine_is_visible should return False when all gate_ids entries are OFF"
    )


# ── Test 3 ────────────────────────────────────────────────────────────────────

def test_both_gate_id_and_gate_ids_is_fail_closed():
    """Engine declaring both gate_id and gate_ids is fail-closed (returns False)."""
    engine = _BothGateEngine()
    # nmap_external_scan=OFF by default; nuclei_severity_info=ON by default
    # But both present → fail-closed regardless of gate values
    result = engine_is_visible(engine)
    assert result is False, (
        "engine_is_visible must return False when both gate_id and gate_ids are set"
    )


# ── Test 4 ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_nuclei_excluded_from_dispatch_when_all_severity_gates_off():
    """dispatch_phase skips nuclei when all nuclei_severity_* gates are OFF."""
    from unittest.mock import MagicMock

    import apps.conductor.engines  # noqa: F401 — registers all engines incl. nuclei
    from apps.conductor.events.bus import EventBus
    from apps.conductor.orchestrators.execution import ExecutionOrchestrator

    # Turn all nuclei severity gates OFF
    for gate_id in (
        "nuclei_severity_info",
        "nuclei_severity_low",
        "nuclei_severity_medium",
        "nuclei_severity_high",
        "nuclei_severity_critical",
    ):
        set_gate(gate_id, False)

    bus = EventBus()
    orch = ExecutionOrchestrator(
        investigation_id="test-multi-gate-inv",
        target="http://10.0.0.1",
        config={},
        bus=bus,
    )
    orch._findings_orch = MagicMock()
    orch._session_orch = MagicMock()
    orch._session_orch.can_dispatch.return_value = (True, 0)

    launched: list[str] = []

    async def fake_launch(engine, correlation_id, extra_config=None):
        launched.append(engine.engine_id)

    orch._launch = fake_launch

    await orch.dispatch_phase("enumeration")

    assert "nuclei" not in launched, (
        f"nuclei engine dispatched despite all severity gates being OFF; launched: {launched}"
    )
