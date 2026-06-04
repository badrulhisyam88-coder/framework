"""Module-level Conductor singleton — shared by admin UI and runtime parallel-track path.

Both apps/admin_ui/state_provider.py and _run_all_probes_via_conductor in runtime.py
import from here so that parallel-track investigations appear in the admin UI
without any additional wiring.

Tests override _conductor directly before each test run and reset it afterwards.
"""
from __future__ import annotations

from pathlib import Path

_conductor = None


def get_shared_conductor():
    """Return the process-level Conductor singleton, lazy-initialising on first call."""
    global _conductor
    if _conductor is None:
        from apps.conductor.conductor import Conductor
        from apps.conductor.events.bus import bus as _default_bus

        _conductor = Conductor(bus=_default_bus, db_path=Path("data/orchestration.db"))
    return _conductor
