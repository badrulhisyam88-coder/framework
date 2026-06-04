"""Verification helper — NOT production code.

Phase 54b verification:
  Fix 1: Inject a temporary action_kind collision into
         NEXT_ACTIONS_BY_PATH (same action_kind under two paths).
         Confirm _emit_ghost_actions attributes ghosts to the path
         matching the run's explicit exploit_path_id, NOT the first
         path the reverse-lookup happens to find.

         Then run the same flow WITHOUT exploit_path_id set on the
         run (simulating a legacy in-flight run) — confirm the
         reverse-lookup fallback still produces output (back-compat).

Run from repo root:
  docker compose exec -T backend python /app/scripts/verify_phase54b.py
"""
from __future__ import annotations

import sys
import time
import types

sys.path.insert(0, "/app")


def main() -> int:
    from apps.investigation_workspace.branch import topology_v2
    from apps.investigation_workspace.exploitation_paths import next_actions
    from apps.investigation_workspace.execution.runtime import (
        ExecutionRun,
        ResultState,
    )

    # ── Inject a deliberate collision ──────────────────────────────────
    # "shared_replay" exists under BOTH transport.downgrade AND
    # injection.xss_reflected. The legacy reverse-lookup would pick
    # whichever insertion happened first.
    NA = next_actions.NextActionSpec
    original = dict(next_actions.NEXT_ACTIONS_BY_PATH)
    next_actions.NEXT_ACTIONS_BY_PATH["transport.downgrade"] = original.get(
        "transport.downgrade", ()
    ) + (NA(action_kind="shared_replay", label="Replay request",
            reason="Shared between transport and xss paths"),)
    next_actions.NEXT_ACTIONS_BY_PATH["injection.xss_reflected"] = original.get(
        "injection.xss_reflected", ()
    ) + (NA(action_kind="shared_replay", label="Replay request",
            reason="Shared between transport and xss paths"),)

    # Build minimal in-memory view with two paths under one finding so
    # _emit_ghost_actions has both path nodes to choose from.
    finding_nid  = "disc-test-finding"
    nodes: list[dict] = [
        {"id": finding_nid, "type": "finding",
         "data": {"node_id": finding_nid, "kind": "finding"}, "position": {"x":0,"y":0}},
        {"id": f"path-{finding_nid}-transport.downgrade",
         "type": "exploitation_path",
         "data": {"node_id": f"path-{finding_nid}-transport.downgrade",
                  "kind": "exploitation_path"}, "position": {"x":0,"y":0}},
        {"id": f"path-{finding_nid}-injection.xss_reflected",
         "type": "exploitation_path",
         "data": {"node_id": f"path-{finding_nid}-injection.xss_reflected",
                  "kind": "exploitation_path"}, "position": {"x":0,"y":0}},
    ]
    edges: list[dict] = []

    # Build a fake run with EXPLICIT exploit_path_id pointing at
    # transport.downgrade (the operator-chosen path). The legacy
    # reverse-lookup would pick injection.xss_reflected (it's first in
    # NEXT_ACTIONS_BY_PATH iteration order), so this is the case that
    # actually exercises the divergence — explicit fix must win over
    # the legacy guess.
    run_explicit = ExecutionRun(
        run_id           = "test-explicit",
        investigation_id = "test-inv",
        action_id        = "suggestion:shared_replay",
        parent_node_id   = finding_nid,
        started_at       = time.time(),
        exploit_path_id  = "transport.downgrade",
    )
    run_explicit.results.append(ResultState(
        label="dummy outcome", kind="detected", emitted_at=time.time(),
    ))

    # Run the emission. Use a dummy `view` namespace with what
    # _emit_ghost_actions reads: nothing relevant beyond runs.
    view = types.SimpleNamespace(investigation_id="test-inv")
    nodes_before = len(nodes)
    topology_v2._emit_ghost_actions(view, [run_explicit], nodes, edges)

    new = nodes[nodes_before:]
    ghosts = [n for n in new if n["id"].startswith("ghost-")]
    attributed_paths = {n["id"].rsplit("-shared_replay", 1)[0]
                          .removeprefix("ghost-")
                        for n in ghosts}

    print("─── Fix 1 — explicit exploit_path_id ───")
    print(f"  ghosts emitted: {len(ghosts)}")
    for g in ghosts:
        print(f"    {g['id']}")
    print(f"  attributed to paths: {attributed_paths}")

    expected_path_node = f"path-{finding_nid}-transport.downgrade"
    wrong_path_node    = f"path-{finding_nid}-injection.xss_reflected"
    has_correct = any(g["id"].startswith(f"ghost-{expected_path_node}-")
                      for g in ghosts)
    has_wrong   = any(g["id"].startswith(f"ghost-{wrong_path_node}-")
                      for g in ghosts)
    fix1_explicit_ok = has_correct and not has_wrong
    print(f"  expected attribution: {expected_path_node}")
    print(f"  legacy reverse-lookup would have chosen: {wrong_path_node}")
    print(f"  → ghosts under operator-chosen path only (no leak to "
          f"legacy-guessed path): {'PASS' if fix1_explicit_ok else 'FAIL'}")
    print()

    # ── Same setup but WITHOUT exploit_path_id (legacy) ────────────────
    run_legacy = ExecutionRun(
        run_id           = "test-legacy",
        investigation_id = "test-inv",
        action_id        = "suggestion:shared_replay",
        parent_node_id   = finding_nid,
        started_at       = time.time(),
        # exploit_path_id intentionally absent
    )
    run_legacy.results.append(ResultState(
        label="dummy outcome", kind="detected", emitted_at=time.time(),
    ))

    # Reset nodes (drop the previous run's ghosts so comparison is clean)
    nodes = nodes[:nodes_before]
    edges = []
    topology_v2._emit_ghost_actions(view, [run_legacy], nodes, edges)

    legacy_ghosts = [n for n in nodes if n["id"].startswith("ghost-")]
    print("─── Fix 1 back-compat — legacy run without exploit_path_id ───")
    print(f"  ghosts emitted: {len(legacy_ghosts)} (back-compat path)")
    for g in legacy_ghosts:
        print(f"    {g['id']}")
    fix1_legacy_ok = len(legacy_ghosts) > 0
    print(f"  → legacy fallback still produces ghosts: "
          f"{'PASS' if fix1_legacy_ok else 'FAIL'}")
    print()

    # ── Restore catalog ────────────────────────────────────────────────
    next_actions.NEXT_ACTIONS_BY_PATH.clear()
    next_actions.NEXT_ACTIONS_BY_PATH.update(original)

    overall = fix1_explicit_ok and fix1_legacy_ok
    print("="*40)
    print(f"OVERALL: {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
