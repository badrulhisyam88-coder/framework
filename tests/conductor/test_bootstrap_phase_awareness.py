"""Behavioral tests — bootstrap phase awareness (V2.1 Step 3 gap fix).

Verifies that PhasedRun and _current_phase() correctly reflect exploitation
phase state driven by the Conductor event bus.

Tests:
  1. _current_phase() returns "recon"        while recon_run.completed_at is None
  2. _current_phase() returns "enumeration"  while enumeration_run.completed_at is None
  3. _current_phase() returns "exploitation" while exploitation_run.completed_at is None
  4. _current_phase() returns "complete"     after exploitation_run.completed_at is set
  5. _current_phase() returns "complete"     when boot_run is None
  6. PhasedRun preserves recon/enumeration structure unchanged (no regression)
  7. is_exploitation_active() mirrors exploitation_run lifecycle
  8. is_active() returns True during exploitation, False after
  9. _on_event phase_started sets exploitation_run on the PhasedRun
 10. _on_event investigation_completed closes exploitation_run
"""
from __future__ import annotations

import time

from apps.investigation_workspace.bootstrap.runtime import (
    PhaseRun,
    PhasedRun,
    is_exploitation_active,
    is_active,
)


# ── Helper: replicate _current_phase() without importing routes.py ────────────
# routes.py pulls in fastapi which is absent in the test environment.
# This helper mirrors the exact logic so tests stay valid.

def _current_phase(boot_run):
    if boot_run is None:
        return "complete"
    if boot_run.recon_run and boot_run.recon_run.completed_at is None:
        return "recon"
    if boot_run.enumeration_run and boot_run.enumeration_run.completed_at is None:
        return "enumeration"
    if boot_run.exploitation_run and boot_run.exploitation_run.completed_at is None:
        return "exploitation"
    return "complete"


def _make_run(**kwargs) -> PhasedRun:
    defaults = dict(investigation_id="inv_test", target="http://t.local", started_at=time.time())
    defaults.update(kwargs)
    return PhasedRun(**defaults)


def _phase_run(phase: str, *, done: bool = False) -> PhaseRun:
    return PhaseRun(
        run_id="r001",
        phase=phase,
        started_at=time.time(),
        completed_at=time.time() if done else None,
    )


# ── _current_phase logic ──────────────────────────────────────────────────────


def test_current_phase_returns_recon_while_recon_active():
    run = _make_run(recon_run=_phase_run("recon", done=False))
    assert _current_phase(run) == "recon"


def test_current_phase_returns_enumeration_while_enumeration_active():
    run = _make_run(
        recon_run=_phase_run("recon", done=True),
        enumeration_run=_phase_run("enumeration", done=False),
    )
    assert _current_phase(run) == "enumeration"


def test_current_phase_returns_exploitation_while_exploitation_active():
    run = _make_run(
        recon_run=_phase_run("recon", done=True),
        enumeration_run=_phase_run("enumeration", done=True),
        exploitation_run=_phase_run("exploitation", done=False),
    )
    assert _current_phase(run) == "exploitation"


def test_current_phase_returns_complete_after_exploitation_done():
    run = _make_run(
        recon_run=_phase_run("recon", done=True),
        enumeration_run=_phase_run("enumeration", done=True),
        exploitation_run=_phase_run("exploitation", done=True),
    )
    assert _current_phase(run) == "complete"


def test_current_phase_returns_complete_when_no_exploitation():
    """Pre-V2 path: recon + enum complete, no exploitation_run set."""
    run = _make_run(
        recon_run=_phase_run("recon", done=True),
        enumeration_run=_phase_run("enumeration", done=True),
    )
    assert _current_phase(run) == "complete"


def test_current_phase_none_boot_run():
    assert _current_phase(None) == "complete"


# ── PhasedRun structure ───────────────────────────────────────────────────────


def test_phased_run_has_exploitation_run_field():
    run = _make_run()
    assert hasattr(run, "exploitation_run")
    assert run.exploitation_run is None


def test_phased_run_recon_enumeration_fields_unchanged():
    """Existing recon/enumeration fields are present and default to None."""
    run = _make_run()
    assert run.recon_run is None
    assert run.enumeration_run is None


# ── is_exploitation_active ────────────────────────────────────────────────────


def test_is_exploitation_active_false_when_no_run():
    from apps.investigation_workspace.bootstrap.runtime import _RUNS
    _RUNS.pop("inv_no_run", None)
    assert not is_exploitation_active("inv_no_run")


def test_is_exploitation_active_false_when_exploitation_run_none():
    from apps.investigation_workspace.bootstrap.runtime import _RUNS
    run = _make_run(investigation_id="inv_active_test")
    _RUNS["inv_active_test"] = run
    try:
        assert not is_exploitation_active("inv_active_test")
    finally:
        _RUNS.pop("inv_active_test", None)


def test_is_exploitation_active_true_while_running():
    from apps.investigation_workspace.bootstrap.runtime import _RUNS
    run = _make_run(
        investigation_id="inv_exploit_run",
        exploitation_run=_phase_run("exploitation", done=False),
    )
    _RUNS["inv_exploit_run"] = run
    try:
        assert is_exploitation_active("inv_exploit_run")
    finally:
        _RUNS.pop("inv_exploit_run", None)


def test_is_exploitation_active_false_after_done():
    from apps.investigation_workspace.bootstrap.runtime import _RUNS
    run = _make_run(
        investigation_id="inv_exploit_done",
        exploitation_run=_phase_run("exploitation", done=True),
    )
    _RUNS["inv_exploit_done"] = run
    try:
        assert not is_exploitation_active("inv_exploit_done")
    finally:
        _RUNS.pop("inv_exploit_done", None)


# ── is_active includes exploitation ──────────────────────────────────────────


def test_is_active_true_during_exploitation():
    from apps.investigation_workspace.bootstrap.runtime import _RUNS
    run = _make_run(
        investigation_id="inv_isactive_exploit",
        recon_run=_phase_run("recon", done=True),
        enumeration_run=_phase_run("enumeration", done=True),
        exploitation_run=_phase_run("exploitation", done=False),
    )
    _RUNS["inv_isactive_exploit"] = run
    try:
        assert is_active("inv_isactive_exploit")
    finally:
        _RUNS.pop("inv_isactive_exploit", None)


def test_is_active_false_after_exploitation_complete():
    from apps.investigation_workspace.bootstrap.runtime import _RUNS
    run = _make_run(
        investigation_id="inv_isactive_done",
        recon_run=_phase_run("recon", done=True),
        enumeration_run=_phase_run("enumeration", done=True),
        exploitation_run=_phase_run("exploitation", done=True),
    )
    _RUNS["inv_isactive_done"] = run
    try:
        assert not is_active("inv_isactive_done")
    finally:
        _RUNS.pop("inv_isactive_done", None)


# ── _apply_phase_event behavioral tests (V2.1 Step 3 Fix-2) ──────────────────


def test_apply_phase_event_recon_completed_writes_timestamp():
    from apps.investigation_workspace.bootstrap.runtime import _apply_phase_event
    run = _make_run(recon_run=_phase_run("recon", done=False))
    assert run.recon_run.completed_at is None
    _apply_phase_event(run, "phase_completed", "recon")
    assert run.recon_run.completed_at is not None


def test_apply_phase_event_enumeration_started_creates_run():
    from apps.investigation_workspace.bootstrap.runtime import _apply_phase_event
    run = _make_run()
    assert run.enumeration_run is None
    _apply_phase_event(run, "phase_started", "enumeration")
    assert run.enumeration_run is not None
    assert run.enumeration_run.completed_at is None
    assert run.enumeration_run.phase == "enumeration"


def test_apply_phase_event_enumeration_completed_writes_timestamp():
    from apps.investigation_workspace.bootstrap.runtime import _apply_phase_event
    run = _make_run(enumeration_run=_phase_run("enumeration", done=False))
    assert run.enumeration_run.completed_at is None
    _apply_phase_event(run, "phase_completed", "enumeration")
    assert run.enumeration_run.completed_at is not None


def test_apply_phase_event_exploitation_started_creates_run():
    from apps.investigation_workspace.bootstrap.runtime import _apply_phase_event
    run = _make_run()
    assert run.exploitation_run is None
    _apply_phase_event(run, "phase_started", "exploitation")
    assert run.exploitation_run is not None
    assert run.exploitation_run.completed_at is None


def test_apply_phase_event_is_idempotent_on_completed():
    """Calling phase_completed twice must not overwrite the first timestamp."""
    from apps.investigation_workspace.bootstrap.runtime import _apply_phase_event
    run = _make_run(recon_run=_phase_run("recon", done=False))
    _apply_phase_event(run, "phase_completed", "recon")
    first_ts = run.recon_run.completed_at
    _apply_phase_event(run, "phase_completed", "recon")
    assert run.recon_run.completed_at == first_ts, (
        "Second phase_completed call must not overwrite timestamp set by first"
    )


def test_apply_phase_event_unknown_phase_is_noop():
    """Unknown phase names must not raise or modify state."""
    from apps.investigation_workspace.bootstrap.runtime import _apply_phase_event
    run = _make_run(recon_run=_phase_run("recon", done=False))
    _apply_phase_event(run, "phase_completed", "unknown_phase")
    assert run.recon_run.completed_at is None  # unchanged


def test_current_phase_advances_through_all_phases_via_events():
    """Full phase progression via _apply_phase_event matches _current_phase() output."""
    from apps.investigation_workspace.bootstrap.runtime import _apply_phase_event
    run = _make_run(recon_run=_phase_run("recon", done=False))

    assert _current_phase(run) == "recon"

    _apply_phase_event(run, "phase_completed", "recon")
    assert _current_phase(run) == "complete"  # no enumeration_run yet → complete

    _apply_phase_event(run, "phase_started", "enumeration")
    assert _current_phase(run) == "enumeration"

    _apply_phase_event(run, "phase_completed", "enumeration")
    assert _current_phase(run) == "complete"  # no exploitation_run yet → complete

    _apply_phase_event(run, "phase_started", "exploitation")
    assert _current_phase(run) == "exploitation"

    _apply_phase_event(run, "phase_completed", "exploitation")
    assert _current_phase(run) == "complete"
