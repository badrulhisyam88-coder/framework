"""Regression tests — ScanExecution lifecycle via kick_off lifecycle_fn callback.

Tests the lifecycle_fn callback mechanism added to _run_all_probes_via_conductor
and kick_off (runtime.py) as part of PR D-fix Bug B.

All tests work without pydantic/aiosqlite/fastapi — they use mock conductors and
inspect whether lifecycle_fn is called with the correct success boolean.

Tests:
  1. lifecycle_fn(True) called when investigation_completed fires
  2. lifecycle_fn(False) called when phase_failed fires
  3. lifecycle_fn exception is swallowed — does not propagate to the runner
  4. lifecycle_fn not called when conductor path is disabled (non-parallel track)
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

import apps.conductor.engines.mock  # noqa: F401 — register mock engines


# ── Shared helpers ────────────────────────────────────────────────────────────


def _make_mock_conductor(event_type: str = "investigation_completed"):
    """Return a mock conductor that fires *event_type* after start_investigation."""
    from apps.conductor.events.bus import EventBus

    bus = EventBus()

    async def mock_start(target, config, **kwargs):
        inv_id = "mock-conductor-inv"

        async def _fire():
            await asyncio.sleep(0)  # yield so inv_id is assigned before event fires
            if event_type == "phase_failed":
                await bus.emit("phase", "phase_failed", inv_id, {})
            else:
                await bus.emit("conductor", event_type, inv_id, {})

        asyncio.create_task(_fire())
        return inv_id

    mock_cond = MagicMock()
    mock_cond._bus = bus
    mock_cond.start_investigation = mock_start
    return mock_cond


def _make_run():
    from apps.investigation_workspace.bootstrap.runtime import PhasedRun

    return PhasedRun(
        investigation_id="old-path-inv",
        target="http://test-target",
        started_at=0.0,
    )


# ── Test 1: investigation_completed → lifecycle_fn(True) ─────────────────────


@pytest.mark.asyncio
async def test_lifecycle_fn_called_with_true_on_completed(monkeypatch):
    """lifecycle_fn(True) called when investigation_completed event fires."""
    from apps.investigation_workspace.bootstrap.runtime import _run_all_probes_via_conductor

    mock_conductor = _make_mock_conductor("investigation_completed")
    monkeypatch.setattr(
        "apps.conductor.shared.get_shared_conductor",
        lambda: mock_conductor,
    )

    run = _make_run()
    lifecycle_calls: list[bool] = []

    async def lifecycle_fn(success: bool) -> None:
        lifecycle_calls.append(success)

    await _run_all_probes_via_conductor(run, "http://test", None, lifecycle_fn)

    assert len(lifecycle_calls) == 1
    assert lifecycle_calls[0] is True


# ── Test 2: phase_failed → lifecycle_fn(False) ────────────────────────────────


@pytest.mark.asyncio
async def test_lifecycle_fn_called_with_false_on_phase_failed(monkeypatch):
    """lifecycle_fn(False) called when phase_failed event fires."""
    from apps.investigation_workspace.bootstrap.runtime import _run_all_probes_via_conductor

    mock_conductor = _make_mock_conductor("phase_failed")
    monkeypatch.setattr(
        "apps.conductor.shared.get_shared_conductor",
        lambda: mock_conductor,
    )

    run = _make_run()
    lifecycle_calls: list[bool] = []

    async def lifecycle_fn(success: bool) -> None:
        lifecycle_calls.append(success)

    await _run_all_probes_via_conductor(run, "http://test", None, lifecycle_fn)

    assert len(lifecycle_calls) == 1
    assert lifecycle_calls[0] is False


# ── Test 3: lifecycle_fn exception is swallowed ───────────────────────────────


@pytest.mark.asyncio
async def test_lifecycle_fn_exception_is_swallowed(monkeypatch):
    """Exception raised by lifecycle_fn must not propagate out of the runner."""
    from apps.investigation_workspace.bootstrap.runtime import _run_all_probes_via_conductor

    mock_conductor = _make_mock_conductor("investigation_completed")
    monkeypatch.setattr(
        "apps.conductor.shared.get_shared_conductor",
        lambda: mock_conductor,
    )

    run = _make_run()

    async def lifecycle_fn_that_raises(success: bool) -> None:
        raise RuntimeError("lifecycle exploded")

    # Must complete without raising
    await _run_all_probes_via_conductor(run, "http://test", None, lifecycle_fn_that_raises)

    # run should still be marked complete (lifecycle error doesn't abort the run)
    assert run.completed_at is not None


# ── Test 4: lifecycle_fn not called when it is None ──────────────────────────


@pytest.mark.asyncio
async def test_lifecycle_fn_none_is_safe(monkeypatch):
    """lifecycle_fn=None is the default; runner must complete without error."""
    from apps.investigation_workspace.bootstrap.runtime import _run_all_probes_via_conductor

    mock_conductor = _make_mock_conductor("investigation_completed")
    monkeypatch.setattr(
        "apps.conductor.shared.get_shared_conductor",
        lambda: mock_conductor,
    )

    run = _make_run()
    # No lifecycle_fn — should behave exactly as before PR D-fix
    await _run_all_probes_via_conductor(run, "http://test", None, None)

    assert run.completed_at is not None
