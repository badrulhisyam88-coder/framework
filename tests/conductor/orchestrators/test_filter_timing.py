"""Tests for FilterOrchestrator timing fix (PR K).

Verifies that FilterOrchestrator is wired to run after the enumeration
phase (not after recon), so chain-dispatched enumeration engines
(auth_recon, api_recon, sqli_recon) finish emitting before filtering.
"""
from __future__ import annotations

import ast
import re


def _read_conductor_source() -> str:
    path = "apps/conductor/conductor.py"
    with open(path) as f:
        return f.read()


def test_filter_runs_after_enumeration_not_recon():
    """The phase guard must check 'enumeration', not 'recon'."""
    src = _read_conductor_source()
    # Must NOT have: if phase == "recon": ... run_filter
    assert 'if phase == "recon"' not in src, (
        "FilterOrchestrator must NOT run after recon phase. "
        "Move invocation to after enumeration phase."
    )
    # Must have: if phase == "enumeration": ... run_filter
    assert 'if phase == "enumeration"' in src, (
        "FilterOrchestrator must run after enumeration phase."
    )


def test_filter_invocation_follows_enumeration_guard():
    """run_filter() call must appear after the enumeration guard, not elsewhere."""
    src = _read_conductor_source()
    lines = src.splitlines()
    guard_line = None
    filter_line = None
    for i, line in enumerate(lines):
        if 'if phase == "enumeration"' in line:
            guard_line = i
        if "run_filter()" in line and guard_line is not None:
            filter_line = i
            break
    assert guard_line is not None, "enumeration phase guard not found"
    assert filter_line is not None, "run_filter() call after enumeration guard not found"
    assert filter_line > guard_line, "run_filter() must appear after the enumeration guard"


def test_no_recon_filter_invocation_anywhere():
    """Verify there is no run_filter() call inside a 'recon' guard block."""
    src = _read_conductor_source()
    # Simple heuristic: find any run_filter() call and ensure the preceding
    # phase guard on the same or nearby lines is 'enumeration', not 'recon'.
    lines = src.splitlines()
    for i, line in enumerate(lines):
        if "run_filter()" in line:
            # Look back up to 5 lines for the guard
            context = lines[max(0, i - 5):i + 1]
            context_str = "\n".join(context)
            assert 'phase == "recon"' not in context_str, (
                f"run_filter() on line {i + 1} appears inside a recon guard"
            )
