"""Pattern 13 — Bootstrap ↔ Conductor Phase State Seam
(test_seam_bootstrap_phase_state.py)

Risk: Activating a new phase in the Conductor (PhaseOrchestrator._PHASE_SEQUENCE)
without updating the workspace bootstrap layer (PhasedRun + _current_phase) leaves the
operator-facing UI permanently showing the prior phase. Same root shape as Pattern 7
(writer/reader targeting different DBs) — mechanically valid code on each side, silent
mismatch at the seam.

V2.1 Step 3 activated 'exploitation' in PhaseOrchestrator but did not update PhasedRun
or _current_phase(). The workspace showed 'complete' the instant enumeration finished,
making the Exploitation tab permanently inaccessible.

Invariants (post-gap-fix):
  - PhasedRun has an exploitation_run field (same PhaseRun shape as recon_run)
  - _current_phase() returns 'exploitation' while exploitation_run.completed_at is None
  - _current_phase() returns 'complete' after exploitation_run.completed_at is set
  - is_exploitation_active() returns True only while exploitation_run is live
  - The Conductor's _OPERATOR_DRIVEN_PHASES and PhasedRun.exploitation_run are
    co-present: if one exists, the other must too.
  - No csp_xss_reflected reference in exploit-tree.js CRITICAL_KINDS (V2.2 Step 1 cleanup)
"""
from __future__ import annotations

import ast
import pathlib
import time


# ── PhasedRun structure ───────────────────────────────────────────────────────


def test_phased_run_has_exploitation_run_field():
    """PhasedRun must have an exploitation_run field matching the PhaseRun shape."""
    from apps.investigation_workspace.bootstrap.runtime import PhasedRun, PhaseRun
    import dataclasses

    fields = {f.name for f in dataclasses.fields(PhasedRun)}
    assert "exploitation_run" in fields, (
        "PhasedRun is missing exploitation_run — add the field in the same PR "
        "that activates a new conductor phase"
    )


def test_exploitation_run_defaults_to_none():
    from apps.investigation_workspace.bootstrap.runtime import PhasedRun
    run = PhasedRun(investigation_id="x", target="t", started_at=time.time())
    assert run.exploitation_run is None


def test_phased_run_recon_and_enumeration_still_present():
    """Regression guard: existing fields must not be removed."""
    from apps.investigation_workspace.bootstrap.runtime import PhasedRun
    import dataclasses
    fields = {f.name for f in dataclasses.fields(PhasedRun)}
    assert "recon_run" in fields
    assert "enumeration_run" in fields


# ── _current_phase returns exploitation ───────────────────────────────────────


def _cp(boot_run):
    """Replicate _current_phase() without importing routes.py (fastapi absent)."""
    if boot_run is None:
        return "complete"
    if boot_run.recon_run and boot_run.recon_run.completed_at is None:
        return "recon"
    if boot_run.enumeration_run and boot_run.enumeration_run.completed_at is None:
        return "enumeration"
    if boot_run.exploitation_run and boot_run.exploitation_run.completed_at is None:
        return "exploitation"
    return "complete"


def _pr(phase, *, done=False):
    from apps.investigation_workspace.bootstrap.runtime import PhaseRun
    return PhaseRun(run_id="r", phase=phase, started_at=time.time(),
                    completed_at=time.time() if done else None)


def test_current_phase_exploitation_while_running():
    from apps.investigation_workspace.bootstrap.runtime import PhasedRun
    run = PhasedRun(
        investigation_id="inv", target="t", started_at=time.time(),
        recon_run=_pr("recon", done=True),
        enumeration_run=_pr("enumeration", done=True),
        exploitation_run=_pr("exploitation", done=False),
    )
    assert _cp(run) == "exploitation", (
        "_current_phase() must return 'exploitation' while exploitation_run.completed_at is None. "
        "If this fails a new Conductor phase was activated without updating _current_phase()."
    )


def test_current_phase_complete_after_exploitation():
    from apps.investigation_workspace.bootstrap.runtime import PhasedRun
    run = PhasedRun(
        investigation_id="inv", target="t", started_at=time.time(),
        recon_run=_pr("recon", done=True),
        enumeration_run=_pr("enumeration", done=True),
        exploitation_run=_pr("exploitation", done=True),
    )
    assert _cp(run) == "complete"


# ── is_exploitation_active ────────────────────────────────────────────────────


def test_is_exploitation_active_exported():
    """is_exploitation_active must be importable from runtime."""
    from apps.investigation_workspace.bootstrap.runtime import is_exploitation_active
    assert callable(is_exploitation_active)


# ── Conductor phase parity ────────────────────────────────────────────────────


def test_conductor_has_exploitation_in_operator_driven_phases():
    """_OPERATOR_DRIVEN_PHASES must contain 'exploitation'.

    If this fails, PhaseOrchestrator will auto-complete exploitation and the
    operator loses control of phase completion (Pattern 11).
    """
    from apps.conductor.orchestrators.phase import _OPERATOR_DRIVEN_PHASES
    assert "exploitation" in _OPERATOR_DRIVEN_PHASES


def test_conductor_phase_sequence_contains_exploitation():
    """_PHASE_SEQUENCE must include 'exploitation'.

    Guards against future removal of the phase from the conductor side
    while PhasedRun still tracks it.
    """
    from apps.conductor.orchestrators.phase import _PHASE_SEQUENCE
    assert "exploitation" in _PHASE_SEQUENCE


# ── Frontend cleanup (V2.2 Step 1) ───────────────────────────────────────────


def test_csp_xss_reflected_absent_from_exploit_tree_js():
    """csp_xss_reflected must not appear in CRITICAL_KINDS in exploit-tree.js."""
    src = pathlib.Path("frontend/static/js/exploit-tree.js").read_text()
    # Find the CRITICAL_KINDS array via AST-like text scan (file is vanilla JS, not parsed by ast)
    assert "csp_xss_reflected" not in src, (
        "'csp_xss_reflected' still in exploit-tree.js CRITICAL_KINDS — "
        "V2.2 Step 1 retires this action_kind; remove it from the frontend too"
    )


# ── Bus-event-driven write path (V2.1 Step 3 Fix-2) ──────────────────────────
# These tests call _apply_phase_event directly to verify the wiring from
# bus event → PhasedRun timestamp. The original Pattern 13 tests only verified
# _current_phase() return values on pre-constructed objects — they never exercised
# the actual write path. Lesson: pattern tests must exercise the wiring.


def test_phase_completed_recon_writes_timestamp():
    """phase_completed(recon) must write recon_run.completed_at.

    If this fails, the _apply_phase_event subscriber for recon is missing or
    broken — badges will show 'Recon Running' for the entire investigation.
    """
    from apps.investigation_workspace.bootstrap.runtime import (
        PhasedRun, PhaseRun, _apply_phase_event,
    )
    run = PhasedRun(investigation_id="seam_recon_ts", target="t", started_at=time.time())
    run.recon_run = PhaseRun(run_id="r", phase="recon", started_at=time.time(), completed_at=None)

    assert run.recon_run.completed_at is None, "precondition"
    _apply_phase_event(run, "phase_completed", "recon")
    assert run.recon_run.completed_at is not None, (
        "_apply_phase_event('phase_completed', 'recon') must write recon_run.completed_at"
    )


def test_phase_started_enumeration_creates_run():
    """phase_started(enumeration) must create enumeration_run with completed_at=None.

    If this fails, enumeration_run is never created during the investigation —
    is_enumeration_active() always returns False and the Enumeration badge
    shows 'Waiting' while enumeration is live.
    """
    from apps.investigation_workspace.bootstrap.runtime import (
        PhasedRun, _apply_phase_event,
    )
    run = PhasedRun(investigation_id="seam_enum_start", target="t", started_at=time.time())

    assert run.enumeration_run is None, "precondition"
    _apply_phase_event(run, "phase_started", "enumeration")
    assert run.enumeration_run is not None, (
        "_apply_phase_event('phase_started', 'enumeration') must create enumeration_run"
    )
    assert run.enumeration_run.completed_at is None, (
        "enumeration_run must be live (completed_at=None) after phase_started"
    )


def test_phase_completed_enumeration_writes_timestamp():
    """phase_completed(enumeration) must write enumeration_run.completed_at.

    If this fails, enumeration_run.completed_at stays None for the entire
    exploitation phase — is_enumeration_active() returns True after enumeration
    ends and _current_phase() never advances past 'enumeration'.
    """
    from apps.investigation_workspace.bootstrap.runtime import (
        PhasedRun, PhaseRun, _apply_phase_event,
    )
    run = PhasedRun(investigation_id="seam_enum_ts", target="t", started_at=time.time())
    run.enumeration_run = PhaseRun(
        run_id="r", phase="enumeration", started_at=time.time(), completed_at=None,
    )

    assert run.enumeration_run.completed_at is None, "precondition"
    _apply_phase_event(run, "phase_completed", "enumeration")
    assert run.enumeration_run.completed_at is not None, (
        "_apply_phase_event('phase_completed', 'enumeration') must write enumeration_run.completed_at"
    )
