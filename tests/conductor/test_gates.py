"""Unit tests — apps.conductor.gates registry.

Tests 1-7: get_gate, set_gate, unknown gate, list_gates, reset.
All tests call reset_all_gates_to_defaults() in a fixture so state
doesn't bleed between tests.
"""
from __future__ import annotations

import pytest

from apps.conductor.gates import (
    get_gate,
    list_gates,
    reset_all_gates_to_defaults,
    set_gate,
)


@pytest.fixture(autouse=True)
def reset_gates():
    reset_all_gates_to_defaults()
    yield
    reset_all_gates_to_defaults()


# ── Test 1: default value ─────────────────────────────────────────────────────


def test_nmap_external_scan_default_is_false():
    assert get_gate("nmap_external_scan") is False


# ── Test 2: set_gate toggles the value ───────────────────────────────────────


def test_set_gate_enables_gate():
    set_gate("nmap_external_scan", True)
    assert get_gate("nmap_external_scan") is True


# ── Test 3: set_gate can disable again ───────────────────────────────────────


def test_set_gate_disables_gate():
    set_gate("nmap_external_scan", True)
    set_gate("nmap_external_scan", False)
    assert get_gate("nmap_external_scan") is False


# ── Test 4: unknown gate raises KeyError ─────────────────────────────────────


def test_get_gate_unknown_raises():
    with pytest.raises(KeyError, match="no_such_gate"):
        get_gate("no_such_gate")


def test_set_gate_unknown_raises():
    with pytest.raises(KeyError, match="no_such_gate"):
        set_gate("no_such_gate", True)


# ── Test 5: list_gates returns all registered gates ──────────────────────────


def test_list_gates_returns_registered():
    gates = list_gates()
    assert isinstance(gates, list)
    assert len(gates) >= 1
    ids = [g["gate_id"] for g in gates]
    assert "nmap_external_scan" in ids


# ── Test 6: list_gates reflects current value ────────────────────────────────


def test_list_gates_reflects_current_value():
    set_gate("nmap_external_scan", True)
    gates = list_gates()
    gate = next(g for g in gates if g["gate_id"] == "nmap_external_scan")
    assert gate["value"] is True
    assert gate["default"] is False


# ── Test 7: reset_all_gates_to_defaults restores defaults ────────────────────


def test_reset_restores_defaults():
    set_gate("nmap_external_scan", True)
    assert get_gate("nmap_external_scan") is True
    reset_all_gates_to_defaults()
    assert get_gate("nmap_external_scan") is False
