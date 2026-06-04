"""Verification helper — NOT production code.

Phase 56 dedup verification — runs all 4 backend scenarios in-process
against execution/runtime.py:

  1. Sequential dedup — two clicks while first running → same run_id.
  2. Race — two simultaneous kick_offs → same run_id, only one runner.
  3. Completed re-execution — after run finishes, new click → new run_id.
  4. Parallel exploit paths — same action_kind under two paths → 2 runs.

Run from repo root:
  docker compose exec -T backend python /app/scripts/verify_phase56_dedup.py
"""
from __future__ import annotations

import asyncio
import sys

sys.path.insert(0, "/app")


async def _stub_probe_runner(target: str):
    """Phase 59b — minimal stub probe runner for dedup tests. Yields
    one StageEvent + one ResultEvent and returns. Replaces the canned
    Script the dedup tests previously used; the canned-script mechanism
    was removed in Phase 59b. Tests the dedup invariant, not probe
    behaviour."""
    from apps.investigation_workspace.probe.events import (
        ResultEvent,
        StageEvent,
    )
    yield StageEvent(label="Test stage", actions=(), tools=(),
                     detected=(), confidence="—")
    yield ResultEvent(label="Test result", kind="detected", payload=None)


async def scenario_sequential() -> bool:
    """Two sequential clicks while the first run is still running."""
    from apps.investigation_workspace.execution import runtime
    runtime._RUNS.clear()
    runtime._BY_INV.clear()
    runtime._DEDUP_LOCKS.clear()
    common = dict(
        investigation_id = "test-inv",
        action_id        = "suggestion:test_action",
        parent_node_id   = "disc-test-finding",
        probe_runner     = _stub_probe_runner,
        exploit_path_id  = "test.path",
        dedup_key        = ("test-finding", "test_action", "test.path"),
    )
    run1 = await runtime.kick_off(**common)
    # Immediately re-click before run1 completes.
    run2 = await runtime.kick_off(**common)

    same_id   = run1.run_id == run2.run_id
    run_count = len([r for r in runtime._RUNS.values()
                     if r.investigation_id == "test-inv"])
    ok = same_id and run_count == 1
    print(f"  sequential: same_id={same_id} run_count={run_count}  "
          f"→ {'PASS' if ok else 'FAIL'}")
    return ok


async def scenario_race() -> bool:
    """Two near-simultaneous kick_offs (asyncio.gather)."""
    from apps.investigation_workspace.execution import runtime
    runtime._RUNS.clear()
    runtime._BY_INV.clear()
    runtime._DEDUP_LOCKS.clear()

    kwargs = dict(
        investigation_id = "test-inv",
        action_id        = "suggestion:test_action",
        parent_node_id   = "disc-test-finding",
        probe_runner     = _stub_probe_runner,
        exploit_path_id  = "test.path",
        dedup_key        = ("test-finding", "test_action", "test.path"),
    )
    # asyncio.gather schedules both coroutines; they will race on the
    # per-key lock — whichever wins the lock first registers the run,
    # the second sees it via find_active_run.
    run1, run2 = await asyncio.gather(
        runtime.kick_off(**kwargs),
        runtime.kick_off(**kwargs),
    )
    same_id   = run1.run_id == run2.run_id
    run_count = len([r for r in runtime._RUNS.values()
                     if r.investigation_id == "test-inv"])
    ok = same_id and run_count == 1
    print(f"  race:       same_id={same_id} run_count={run_count}  "
          f"→ {'PASS' if ok else 'FAIL'}")
    return ok


async def scenario_completed_rerun() -> bool:
    """After a run completes, the next kick_off creates a fresh run."""
    from apps.investigation_workspace.execution import runtime
    runtime._RUNS.clear()
    runtime._BY_INV.clear()
    runtime._DEDUP_LOCKS.clear()
    common = dict(
        investigation_id = "test-inv",
        action_id        = "suggestion:test_action",
        parent_node_id   = "disc-test-finding",
        probe_runner     = _stub_probe_runner,
        exploit_path_id  = "test.path",
        dedup_key        = ("test-finding", "test_action", "test.path"),
    )
    run1 = await runtime.kick_off(**common)

    # Wait for run1 to complete naturally (the canned Script takes
    # ~STAGE_DELAY_S + RESULT_PAUSE_S + small staggers).
    for _ in range(50):
        await asyncio.sleep(0.1)
        if run1.completed_at is not None:
            break
    completed = run1.completed_at is not None
    if not completed:
        print("  completed-rerun: FAIL — run1 never completed within 5s")
        return False

    # Now re-click. dedup should NOT match because run1 is no longer active.
    run2 = await runtime.kick_off(**common)
    fresh = run1.run_id != run2.run_id
    print(f"  completed-rerun: fresh_run={fresh}  "
          f"→ {'PASS' if fresh else 'FAIL'}")
    return fresh


async def scenario_parallel_paths() -> bool:
    """Same action_kind under two paths → two runs (different ids)."""
    from apps.investigation_workspace.execution import runtime
    runtime._RUNS.clear()
    runtime._BY_INV.clear()
    runtime._DEDUP_LOCKS.clear()

    run_a = await runtime.kick_off(
        investigation_id = "test-inv",
        action_id        = "suggestion:test_action",
        parent_node_id   = "disc-test-finding",
        probe_runner     = _stub_probe_runner,
        exploit_path_id  = "path.A",
        dedup_key        = ("test-finding", "test_action", "path.A"),
    )
    # Same finding + action_kind, DIFFERENT path. Must spawn its own run.
    run_b = await runtime.kick_off(
        investigation_id = "test-inv",
        action_id        = "suggestion:test_action",
        parent_node_id   = "disc-test-finding",
        probe_runner     = _stub_probe_runner,
        exploit_path_id  = "path.B",
        dedup_key        = ("test-finding", "test_action", "path.B"),
    )
    diff = run_a.run_id != run_b.run_id
    run_count = len([r for r in runtime._RUNS.values()
                     if r.investigation_id == "test-inv"])
    ok = diff and run_count == 2
    print(f"  parallel-paths: diff_ids={diff} run_count={run_count}  "
          f"→ {'PASS' if ok else 'FAIL'}")
    return ok


async def main() -> int:
    print("─── Phase 56 dedup verification ───")
    results = []
    results.append(await scenario_sequential())
    results.append(await scenario_race())
    results.append(await scenario_completed_rerun())
    results.append(await scenario_parallel_paths())
    print()
    print("="*40)
    print(f"OVERALL: {'PASS' if all(results) else 'FAIL'}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
