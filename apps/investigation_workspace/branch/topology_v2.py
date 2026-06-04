"""Phase 37 — React Flow topology serializer.

Emits {nodes, edges, meta} for the operator-facing React Flow canvas.
Node TYPES are semantic (Phase 50) — surface / category / finding /
action / execution_stage / outcome / evidence — and the frontend
chooses a rendered component per type.

Phase 51 — LAYOUT IS NOT COMPUTED HERE. Positions emitted by this
module are placeholder {x: 0, y: 0}. The frontend graph-layout.js
module runs Dagre and overwrites every position before React Flow
mounts the canvas. Don't reintroduce position math in this file —
that's the change Phase 51 made and it has no external callers.

Status vocabulary (mapped from BranchState):
    ready                — available
    running              — active / verification_running
    completed            — completed / evidence_attached / verified
    failed               — regression
    discovered           — milestone, brand-new branches
"""
from __future__ import annotations

from typing import Any

from apps.investigation_workspace.branch.model import (
    BranchNode,
    BranchState,
    NodeKind,
    WorkspaceView,
)

# Phase 51 — position placeholders. All real layout happens in the
# frontend graph-layout.js Dagre module. Backend emits {x:0,y:0}; the
# frontend overwrites before React Flow mounts.
_PLACEHOLDER_POS = {"x": 0.0, "y": 0.0}

# State → operator-facing status
_STATE_TO_STATUS: dict[BranchState, str] = {
    BranchState.LOCKED:               "ready",
    BranchState.AVAILABLE:            "ready",
    BranchState.ACTIVE:               "running",
    BranchState.COMPLETED:            "completed",
    BranchState.EVIDENCE_ATTACHED:    "completed",
    BranchState.REMEDIATION_PENDING:  "ready",
    BranchState.VERIFICATION_RUNNING: "running",
    BranchState.VERIFIED:             "completed",
    BranchState.REGRESSION:           "failed",
}

# BranchNode → semantic node-type (Phase 50). The vocabulary now matches
# the investigation hierarchy: surface > category > finding > action >
# execution_stage > outcome > evidence. Pre-Phase-50 type names are kept
# as values where they still describe accurate semantics (action states,
# regression markers, etc.); pseudo-node emitters in this module set
# their types directly without going through this function.
def _node_type(node: BranchNode) -> str:
    if node.kind == NodeKind.DISCOVERY:
        return "finding"
    # Phase 59a — NodeKind.MILESTONE branch removed alongside the
    # milestone subsystem; no emitter creates MILESTONE-kind nodes.
    if node.kind == NodeKind.REMEDIATION:
        return "verification"
    if node.kind == NodeKind.EVIDENCE:
        return "evidence"
    if node.kind == NodeKind.ACTION:
        if node.state in (BranchState.COMPLETED, BranchState.EVIDENCE_ATTACHED):
            return "completed_action"
        if node.state in (BranchState.ACTIVE,):
            return "running_action"
        return "action"
    if node.state == BranchState.REGRESSION:
        return "blocked_path"
    return "system_analysis"


def serialize_topology(view: WorkspaceView) -> dict[str, Any]:
    """Return {nodes, edges, meta} ready for React Flow.

    Phase 50 — semantic node hierarchy: Surface → Category → Finding →
    Action/Evidence + (overlay) Execution → Outcome. Surface and Category
    nodes are synthesized here (no schema change on BranchNode).

    Phase 51 — positions are placeholders. The frontend graph-layout.js
    Dagre module computes real positions just before React Flow mounts.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    # ── Surface banner ─────────────────────────────────────────────────
    surface_node_id = _emit_surface_node(view, nodes)

    # ── Group findings by category ─────────────────────────────────────
    grouped = _group_findings_by_category(view)

    for cat, discoveries in grouped:
        cat_node_id = _emit_category_node(cat, len(discoveries), nodes)
        if surface_node_id:
            edges.append(_synth_edge(surface_node_id, cat_node_id))

        for disc in discoveries:
            _emit_node(disc, nodes=nodes)
            edges.append(_synth_edge(cat_node_id, disc.node_id))
            _emit_exploitation_paths(disc, nodes, edges)
            _emit_subtree(disc, nodes=nodes)

    # Within-tree edges (finding → action, action → evidence, etc.) from
    # the assembler's CausalEdge records. Surface→discovery edges are
    # superseded by the synthesized surface→category→finding chain above.
    seen: set[tuple[str, str]] = set()
    for branch in view.branches:
        for e in branch.edges:
            if e.parent_id == branch.branch_id:
                continue
            k = (e.parent_id, e.child_id)
            if k in seen:
                continue
            seen.add(k)
            edges.append({
                "id":     f"e-{e.parent_id}-{e.child_id}",
                "source": e.parent_id,
                "target": e.child_id,
                "type":   "smoothstep",
            })

    # Pick the suggested-next action (Phase 30 heuristic — surfaces here
    # as the node-level CTA on whichever node is the next operator move).
    next_node_id = _pick_suggested_next(view)

    # Phase 39 — overlay live execution runs. Each active run sprouts stage
    # and result nodes from its parent action node so the operator sees the
    # investigation evolve in real time. The runtime is in-memory; restart
    # wipes it (consistent with "live runtime" semantics).
    from apps.investigation_workspace.execution.runtime import (
        active_runs,
        has_active_execution,
    )

    runs = active_runs(view.investigation_id)
    _overlay_execution_runs(runs, nodes, edges)

    # Phase 54 — ghost-action suggestions hanging off each exploitation
    # path whose finding has produced evidence. Resolved from the
    # next_actions catalog (catalog default) or the evidence payload
    # (probe-emitted override). Each ghost is an action-type node with
    # data.ghost_state="ghost" so the frontend renders the dashed
    # outline + activation flow.
    _emit_ghost_actions(view, runs, nodes, edges)

    # If a result node was just emitted, use it as the suggested-next so the
    # frontend auto-pans to the freshest emergence instead of the now-stale
    # original action.
    fresh_focus = _freshest_result_id(runs)
    if fresh_focus:
        next_node_id = fresh_focus

    # V1.5 — Phased run overlay. Shows Recon then Enumeration stage chains.
    from apps.investigation_workspace.bootstrap.runtime import (
        get_run as get_phased_run,
    )
    from apps.investigation_workspace.bootstrap.runtime import (
        is_enumeration_active,
        is_recon_active,
    )
    from apps.investigation_workspace.bootstrap.runtime import (
        is_visible as phased_run_is_visible,
    )

    phased_run = get_phased_run(view.investigation_id)
    if phased_run is not None:
        _overlay_phased_run(phased_run, nodes, edges)
        running_stage_id = _phased_run_running_stage_id(phased_run)
        if running_stage_id:
            next_node_id = running_stage_id

    # Phase 48 — annotate finding nodes with suggestion_count so the
    # frontend can render an indicator badge ("action available here")
    # without the operator having to expand first.
    _annotate_suggestion_counts(nodes, view)

    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "investigation_id":       view.investigation_id,
            "target":                  view.target,
            "branch_count":           view.branch_count_total,
            "regression_count":       view.regression_count,
            "suggested_next_node_id": next_node_id,
            "has_active_execution":   has_active_execution(view.investigation_id),
            "has_active_recon":       is_recon_active(view.investigation_id),
            "has_active_enumeration": is_enumeration_active(view.investigation_id),
            "phased_run_visible":     phased_run_is_visible(view.investigation_id),
            # Phase 51 — layout is computed in the frontend (graph-layout.js).
            # No layout constants ship from the backend any more.
        },
    }


# ─── Phase 39 — live execution overlay ─────────────────────────────────


def _overlay_execution_runs(runs, nodes, edges) -> None:
    """Splice stage + result pseudo-nodes into the topology in place.

    Phase 51 — positions are placeholder; the frontend Dagre module lays
    out the chain LR from its parent finding. We just emit nodes and
    edges; the parent_node_id → first-stage edge anchors the chain to
    the finding the user clicked.

    by_id is kept updated as each node is appended so that nested runs
    (whose parent is an exec-{...}-r0 outcome node added by an earlier
    run in the same loop) can find their parent. Runs arrive in insertion
    order (chronological), so the parent run is always processed before
    its children.
    """
    by_id = {n["id"]: n for n in nodes}

    for run in runs:
        parent = by_id.get(run.parent_node_id)
        if parent is None:
            continue

        prev_id = parent["id"]
        for i, stage in enumerate(run.stages):
            sid = f"exec-{run.run_id}-s{i}"
            status = "completed" if stage.completed_at else "running"
            node = {
                "id":   sid,
                "type": "execution_stage",
                "position": dict(_PLACEHOLDER_POS),
                "data": {
                    "node_id":   sid,
                    "kind":      "execution_stage",
                    "status":    status,
                    "title":     stage.label,
                    "subtitle":  "",
                    "approvable": False,
                    "transient": True,
                },
                "draggable":  False,
                "selectable": True,
            }
            nodes.append(node)
            by_id[sid] = node
            edges.append({
                "id":     f"e-{prev_id}->{sid}",
                "source": prev_id,
                "target": sid,
                "type":   "smoothstep",
            })
            prev_id = sid

        status_map = {
            "blocked":  "completed",
            "persists": "failed",
            "detected": "discovered",
            "note":     "completed",
        }
        for j, result in enumerate(run.results):
            rid = f"exec-{run.run_id}-r{j}"
            r_status = status_map.get(result.kind, "completed")
            node = {
                "id":   rid,
                "type": "outcome",
                "position": dict(_PLACEHOLDER_POS),
                "data": {
                    "node_id":   rid,
                    "kind":      "outcome",
                    "status":    r_status,
                    "title":     result.label,
                    "subtitle":  "",
                    "approvable": False,
                    "transient": True,
                },
                "draggable":  False,
                "selectable": True,
            }
            nodes.append(node)
            by_id[rid] = node
            edges.append({
                "id":     f"e-{prev_id}->{rid}",
                "source": prev_id,
                "target": rid,
                "type":   "smoothstep",
            })

            # Phase 58 — Capture node hanging off the Outcome.
            # When the probe completed a post-exploit capture, it set
            # payload.captured_bundle_id; emit a "capture" node + edge.
            bundle_id = (result.payload or {}).get("captured_bundle_id") \
                if result.payload else None
            if bundle_id:
                cap_id = f"bundle-{bundle_id}"
                cap_node = {
                    "id":   cap_id,
                    "type": "capture",
                    "position": dict(_PLACEHOLDER_POS),
                    "data": {
                        "node_id":    cap_id,
                        "kind":       "capture",
                        "status":     "completed",
                        "title":      "Captured artifacts",
                        "subtitle":   "post-exploit bundle",
                        "bundle_id":  bundle_id,
                        "approvable": False,
                    },
                    "draggable":  False,
                    "selectable": True,
                }
                nodes.append(cap_node)
                by_id[cap_id] = cap_node
                edges.append({
                    "id":     f"e-{rid}->{cap_id}",
                    "source": rid,
                    "target": cap_id,
                    "type":   "smoothstep",
                })


def _freshest_result_id(runs) -> str | None:
    """Most recently emitted result node id across all active runs.

    Used to drive the React Flow camera toward the latest emergence.
    """
    newest = None
    newest_t = 0.0
    for run in runs:
        for j, r in enumerate(run.results):
            if r.emitted_at > newest_t:
                newest_t = r.emitted_at
                newest = f"exec-{run.run_id}-r{j}"
    return newest


# ─── V1.5 — Phased run overlay ──────────────────────────────────────────


def _overlay_phased_run(run, nodes: list, edges: list) -> None:
    """Add stage nodes for both Recon and Enumeration phases to the topology."""
    for phase_run in (run.recon_run, run.enumeration_run):
        if phase_run is None:
            continue
        prev_id = None
        for i, stage in enumerate(phase_run.stages):
            sid    = f"boot-{phase_run.run_id}-s{i}"
            status = "completed" if stage.completed_at else "running"
            nodes.append({
                "id":   sid,
                "type": "execution_stage",
                "position": dict(_PLACEHOLDER_POS),
                "data": {
                    "node_id":   sid,
                    "kind":      "bootstrap_stage",
                    "status":    status,
                    "title":     stage.label,
                    "subtitle":  f"{phase_run.phase} phase",
                    "approvable": False,
                    "transient": True,
                },
                "draggable":  False,
                "selectable": True,
            })
            if prev_id is not None:
                edges.append({
                    "id":     f"e-{prev_id}->{sid}",
                    "source": prev_id,
                    "target": sid,
                    "type":   "smoothstep",
                })
            prev_id = sid


def _phased_run_running_stage_id(run) -> str | None:
    """Node id of the currently-running stage across both phases."""
    for phase_run in (run.recon_run, run.enumeration_run):
        if phase_run is None:
            continue
        for i, stage in enumerate(phase_run.stages):
            if stage.completed_at is None:
                return f"boot-{phase_run.run_id}-s{i}"
    return None


# ─── Phase 50 — surface + category synthesis ───────────────────────────


def _emit_surface_node(view: WorkspaceView, nodes: list[dict]) -> str | None:
    """Emit a single Surface banner node. Position is a placeholder; the
    frontend Dagre module overwrites it.
    """
    target = view.target or ""
    if not target and not view.branches:
        return None
    sid = "surface-root"
    nodes.append({
        "id":   sid,
        "type": "surface",
        "position": dict(_PLACEHOLDER_POS),
        "data": {
            "node_id":   sid,
            "kind":      "surface",
            "status":    "ready",
            "title":     target or "Investigation",
            "subtitle":  "scope",
            "approvable": False,
        },
        "draggable":  False,
        "selectable": True,
    })
    return sid


def _emit_category_node(cat, finding_count: int, nodes: list[dict]) -> str:
    """Emit one Category container node (placeholder position)."""
    cid = f"cat-{cat.category_id}"
    nodes.append({
        "id":   cid,
        "type": "category",
        "position": dict(_PLACEHOLDER_POS),
        "data": {
            "node_id":         cid,
            "kind":            "category",
            "status":          "ready",
            "title":           cat.label,
            "subtitle":        cat.description,
            "category_id":     cat.category_id,
            "severity_hint":   cat.severity_hint,
            "finding_count":   finding_count,
            "approvable":      False,
        },
        "draggable":  False,
        "selectable": True,
    })
    return cid


def _group_findings_by_category(view: WorkspaceView) -> list[tuple]:
    """Group DISCOVERY nodes across all branches by their category.

    Returns a deterministically-ordered list of (Category, list[BranchNode]).
    Ordering: by first appearance of the category across branches.
    """
    from apps.investigation_workspace.categories.catalog import for_finding_type

    order: list[str] = []
    by_cat: dict[str, list] = {}
    cat_objs: dict[str, object] = {}

    for branch in view.branches:
        for discovery in branch.root.children:
            if discovery.kind != NodeKind.DISCOVERY:
                continue
            cat = for_finding_type(discovery.finding_type or "")
            if cat.category_id not in by_cat:
                order.append(cat.category_id)
                by_cat[cat.category_id] = []
                cat_objs[cat.category_id] = cat
            by_cat[cat.category_id].append(discovery)

    return [(cat_objs[cid], by_cat[cid]) for cid in order]


def _synth_edge(source_id: str, target_id: str) -> dict:
    """Synthesized parent→child edge for surface/category/finding layer."""
    return {
        "id":     f"e-{source_id}-{target_id}",
        "source": source_id,
        "target": target_id,
        "type":   "smoothstep",
    }


# ─── Phase 54 — ghost-action suggestions ───────────────────────────────


def _has_v2_engine(finding_type: str) -> bool:
    """Return True if SUGGESTIONS has at least one engine_id-backed spec for finding_type.

    V2.4 non-exploitable filter: findings whose finding_type has no V2 engine spec
    (only V1 probe_runner specs or guidance-only specs) are excluded from the
    exploitation mindmap Phase 2 ghost emission. V1 probes write to in-memory _RUNS
    only; they never produce exploitation_branches records.

    SUGGESTIONS is keyed by finding_type → tuple[SuggestionSpec, ...].
    A finding_type has a V2 engine if its spec tuple contains at least one spec
    with engine_id set (not None).

    V2.5: ai_probe findings are always treated as having a V2 engine — they are
    synthetic findings created when Qwen triggers an engine dispatch directly.
    """
    if finding_type == "ai_probe":
        return True  # AI-triggered findings always have an engine running
    from apps.investigation_workspace.suggestions.catalog import SUGGESTIONS
    specs = SUGGESTIONS.get(finding_type, ())
    return any(spec.engine_id is not None for spec in specs)


def _emit_ghost_actions(view, runs, nodes, edges) -> None:
    """Emit ghost-action nodes under each exploitation path.

    Two phases:

    Phase 1 — For each execution run that produced at least one outcome,
    reverse-lookup which exploitation path the run's action_kind belongs to.
    Resolve the next_actions for the path and emit one ghost node per
    next_action.

    Phase 2 — For exploitation paths that have NO runs at all (fresh
    investigation or first-time action), emit ghost nodes from the
    suggestion catalog so operators always see an Execute affordance.
    V2.4: only findings with at least one V2 engine SuggestionSpec reach
    Phase 2 (_has_v2_engine guard); V1 probe specs were retired from SUGGESTIONS.

    Filter for both phases: skip ghosts for action_kinds that already
    have an active run on this finding (they're "now", not "next").
    """

    from apps.investigation_workspace.exploitation_paths.next_actions import (
        NEXT_ACTIONS_BY_PATH,
        resolve_next_actions,
    )

    # Phase 54b — fallback reverse map: action_kind → path_id.
    # ──────────────────────────────────────────────────────────────────
    # LEGACY back-compat ONLY. The primary source of truth is now
    # run.exploit_path_id, set when the operator clicks Execute. The
    # reverse-lookup below is consulted ONLY when the run has no
    # exploit_path_id (in-flight runs that started before Phase 54b,
    # or panel callers that haven't been updated to pass the param).
    #
    # `setdefault` silently picks the first path that declares a given
    # action_kind. This is the latent bug the Phase 54 audit surfaced —
    # safe today (catalog has no collisions) but quietly wrong if any
    # future catalog entry shares an action_kind across paths. The fix
    # is to send exploit_path_id with the Execute click; this map is
    # only here to keep stale ExecutionRuns from breaking ghost
    # emission during the upgrade window.
    #
    # TODO(phase-54c): remove this map and the `else` branch below once
    # all active runs were started post-54b (i.e., after one deployment
    # cycle / process restart of all backends).
    kind_to_path: dict[str, str] = {}
    for path_id, specs in NEXT_ACTIONS_BY_PATH.items():
        for s in specs:
            kind_to_path.setdefault(s.action_kind, path_id)

    # R2 restore — augment kind_to_path with initial catalog suggestions
    # (action_kinds that are first-time actions, not "next" actions).
    # brute_force_login is the canonical example: it's in the suggestion
    # catalog for login_form_detected but absent from NEXT_ACTIONS_BY_PATH.
    from apps.investigation_workspace.exploitation_paths.bindings import (
        FINDING_TYPE_TO_PATH_IDS,
    )
    from apps.investigation_workspace.suggestions.catalog import (
        for_finding_type as _catalog_suggestions,
    )
    for _ftype, _path_ids in FINDING_TYPE_TO_PATH_IDS.items():
        for _spec in _catalog_suggestions(_ftype):
            if not _spec.guidance_only and (_spec.probe_runner or _spec.engine_id) and _path_ids:
                kind_to_path.setdefault(_spec.action_kind, _path_ids[0])

    # Index of existing path nodes (so we only attach to paths that
    # actually exist for this finding).
    path_node_ids = {n["id"] for n in nodes if n["type"] == "exploitation_path"}

    # Group runs by (finding_node_id, path_id). Track the latest outcome
    # per group so probe-emitted next_actions override catalog when present.
    by_path: dict[tuple[str, str], object] = {}
    active_kinds_by_finding: dict[str, set[str]] = {}
    for run in runs:
        if not run.action_id:
            continue
        ak = run.action_id
        if ak.startswith("suggestion:"):
            ak = ak[len("suggestion:"):]
        # Phase 54b — primary: run.exploit_path_id, set by the operator's
        # click. Fallback: legacy reverse-lookup for runs predating 54b.
        path_id = getattr(run, "exploit_path_id", None) or kind_to_path.get(ak)
        active_kinds_by_finding.setdefault(run.parent_node_id, set()).add(ak)
        if not path_id or not run.results:
            continue
        by_path[(run.parent_node_id, path_id)] = run.results[-1]

    for (finding_nid, path_id), outcome in by_path.items():
        path_node_id = f"path-{finding_nid}-{path_id}"
        if path_node_id not in path_node_ids:
            continue

        finding_id = finding_nid
        if finding_id.startswith("disc-"):
            finding_id = finding_id[len("disc-"):]

        payload = getattr(outcome, "payload", None)
        next_acts = resolve_next_actions(payload, path_id)
        if not next_acts:
            continue

        active_kinds = active_kinds_by_finding.get(finding_nid, set())
        for na in next_acts:
            if na.action_kind in active_kinds:
                # Already running / ran — not a "next" action.
                continue
            if na.inputs:
                # Actions requiring operator-supplied inputs can only be
                # executed from the structured-evidence panel, where the
                # input form renders. A ghost node in the topology has no
                # place to accept those inputs — skip it.
                continue
            ghost_id = f"ghost-{path_node_id}-{na.action_kind}"
            nodes.append({
                "id":   ghost_id,
                "type": "action",
                "position": dict(_PLACEHOLDER_POS),
                "data": {
                    "node_id":     ghost_id,
                    "kind":        "action",
                    "ghost_state": "ghost",
                    "status":      "ready",
                    "title":       na.label,
                    "subtitle":    na.reason,
                    "action_kind": na.action_kind,
                    "finding_id":  finding_id,
                    "exploit_path_id": path_id,
                    "approvable":  False,
                    "transient":   True,
                },
                "draggable":  False,
                "selectable": True,
            })
            edges.append({
                "id":      f"e-{path_node_id}->{ghost_id}",
                "source":  path_node_id,
                "target":  ghost_id,
                "type":    "smoothstep",
                "animated": False,
                "style":   {"strokeDasharray": "5 3", "stroke": "#58a6ff", "strokeWidth": 1.2},
            })

    # ── Phase 2: initial ghosts for findings with no prior runs ────────────
    # For each discovery node in the view, if the exploitation path under it
    # has NO runs (hence no entry in by_path), emit ghost nodes from the
    # suggestion catalog so operators always see an Execute affordance on a
    # fresh investigation. Deduplicates against Phase 1 ghosts already emitted.
    # V2.4: findings with no V2 engine path are skipped (_has_v2_engine guard).
    existing_ghost_ids = {n["id"] for n in nodes if n.get("data", {}).get("ghost_state") == "ghost"}
    ftype_by_nid: dict[str, str] = {}
    for branch in view.branches:
        for n in _walk(branch.root):
            if n.kind == NodeKind.DISCOVERY and n.finding_type:
                ftype_by_nid[n.node_id] = n.finding_type

    for finding_nid, ftype in ftype_by_nid.items():
        # V2.4 non-exploitable filter: skip findings whose finding_type has no
        # V2 engine spec in SUGGESTIONS. V1 probe-backed specs write only to
        # in-memory _RUNS; they never produce exploitation_branches entries, so
        # their findings cannot appear as actionable nodes in the mindmap.
        if not _has_v2_engine(ftype):
            continue
        active_kinds = active_kinds_by_finding.get(finding_nid, set())
        for spec in _catalog_suggestions(ftype):
            if spec.guidance_only or (not spec.probe_runner and not spec.engine_id):
                continue
            if spec.action_kind in active_kinds:
                continue
            path_id = kind_to_path.get(spec.action_kind)
            if not path_id:
                continue
            path_node_id = f"path-{finding_nid}-{path_id}"
            if path_node_id not in path_node_ids:
                continue
            ghost_id = f"ghost-{path_node_id}-{spec.action_kind}"
            if ghost_id in existing_ghost_ids:
                continue  # Phase 1 already emitted this ghost
            finding_id = (
                finding_nid[len("disc-"):] if finding_nid.startswith("disc-") else finding_nid
            )
            nodes.append({
                "id":   ghost_id,
                "type": "action",
                "position": dict(_PLACEHOLDER_POS),
                "data": {
                    "node_id":       ghost_id,
                    "kind":          "action",
                    "ghost_state":   "ghost",
                    "status":        "ready",
                    "title":         spec.label,
                    "subtitle":      spec.reasoning,
                    "action_kind":   spec.action_kind,
                    "finding_id":    finding_id,
                    "exploit_path_id": path_id,
                    "approvable":    False,
                    "transient":     True,
                    "engine_id":     spec.engine_id,
                },
                "draggable":  False,
                "selectable": True,
            })
            edges.append({
                "id":      f"e-{path_node_id}->{ghost_id}",
                "source":  path_node_id,
                "target":  ghost_id,
                "type":    "smoothstep",
                "animated": False,
                "style":   {"strokeDasharray": "5 3", "stroke": "#58a6ff", "strokeWidth": 1.2},
            })
            existing_ghost_ids.add(ghost_id)


# ─── Phase 52 — exploitation paths under each finding ──────────────────


def _emit_exploitation_paths(
    discovery: BranchNode, nodes: list[dict], edges: list[dict],
) -> None:
    """Emit one exploitation_path node per binding for this finding.

    The path-emission layer sits between Finding and any chain children.
    Findings with no binding fall back to a single 'exploit.uncategorized'
    placeholder so the operator always sees the layer.
    """
    from apps.investigation_workspace.exploitation_paths import (
        for_finding_type as _paths_for,
    )
    from apps.investigation_workspace.exploitation_paths import (
        presentation_for as _present_for,
    )

    paths = _paths_for(discovery.finding_type or "")
    for p in paths:
        # Path-node id is finding-scoped so multiple findings can each
        # carry the same path without collision (e.g., two missing
        # headers both spawning injection.xss_reflected).
        pnid = f"path-{discovery.node_id}-{p.path_id}"
        pres = _present_for(p.path_id)
        nodes.append({
            "id":   pnid,
            "type": "exploitation_path",
            "position": dict(_PLACEHOLDER_POS),
            "data": {
                "node_id":    pnid,
                "kind":       "exploitation_path",
                "status":     "ready",
                "title":      p.label,
                "subtitle":   pres.family,
                "path_id":    p.path_id,
                "description": p.description,
                "parent_id":  p.parent_id,
                "color":      pres.color,
                "glyph":      pres.glyph,
                "finding_id": discovery.finding_id,
                "approvable": False,
            },
            "draggable":  False,
            "selectable": True,
        })
        edges.append(_synth_edge(discovery.node_id, pnid))


# ─── Phase 48 — suggestion-count annotation ────────────────────────────


def _annotate_suggestion_counts(nodes: list[dict], view: WorkspaceView) -> None:
    """Add suggestion_count + has_suggestions to finding-kind node data.

    Walks the assembled view to build {node_id → finding_type}, then looks
    up the suggestion catalog for each. The frontend renders a small
    indicator badge when has_suggestions is true so operators see "action
    available here" without having to expand the node first.
    """
    from apps.investigation_workspace.suggestions.catalog import for_finding_type

    ftype_by_id: dict[str, str] = {}
    for branch in view.branches:
        for n in _walk(branch.root):
            if n.kind == NodeKind.DISCOVERY and n.finding_type:
                ftype_by_id[n.node_id] = n.finding_type

    for n in nodes:
        nid = n.get("id", "")
        ftype = ftype_by_id.get(nid)
        if not ftype:
            continue
        count = len(for_finding_type(ftype))
        if count > 0:
            n["data"]["suggestion_count"] = count
            n["data"]["has_suggestions"]  = True


# ─── Node emission (positions are placeholders — frontend lays out) ────


def _emit_node(node: BranchNode, *, nodes: list[dict[str, Any]]) -> None:
    """Emit one BranchNode with a placeholder position. The frontend
    graph-layout.js Dagre module overwrites position before mount.
    """
    status = _STATE_TO_STATUS.get(node.state, "ready")
    nodes.append({
        "id":   node.node_id,
        "type": _node_type(node),
        "position": dict(_PLACEHOLDER_POS),
        "data": {
            "node_id":           node.node_id,
            "kind":              str(node.kind),
            "status":            status,
            "title":             node.label,
            "subtitle":          "",
            "context":           node.detail,
            "narrative":         node.narrative,
            # Phase 59b — `approvable` is always False. The canned
            # branch-action/approve route is gone; clicking a GuidedAction
            # node on the topology must no longer fire any execution. Real
            # actions execute via the suggestion list in the side panel.
            "approvable": False,
            "action_id":            node.action_id,
            "remediation_action_id": node.remediation_action_id,
            # Phase 59a — objective_key removed from node data alongside
            # the milestone subsystem; the BranchNode field is gone.
            "finding_id":           node.finding_id,
            "finding_type":         node.finding_type or "",
            "severity":             node.severity_class,
            "confidence_glyph":     node.confidence_glyph,
            "confidence_label":     node.confidence_label,
        },
        "draggable":  False,
        "selectable": True,
    })


def _emit_subtree(node: BranchNode, *, nodes: list[dict[str, Any]]) -> None:
    """Emit all descendants of `node` (children, grandchildren, ...).

    Children themselves are emitted; parent→child edges come from the
    CausalEdge records elsewhere in serialize_topology.
    """
    for child in node.children:
        _emit_node(child, nodes=nodes)
        if child.children:
            _emit_subtree(child, nodes=nodes)


def _pick_suggested_next(view: WorkspaceView) -> str | None:
    """First high-priority action node in the highest-priority corridor.

    Mirror of the Phase 30 priority heuristic — kept here so the client can
    visually highlight one node as the suggested next move.
    """
    priority = {
        BranchState.REGRESSION:           5,
        BranchState.REMEDIATION_PENDING:  4,
        BranchState.VERIFICATION_RUNNING: 3,
        BranchState.AVAILABLE:            2,
        BranchState.ACTIVE:               1,
    }
    best = None
    best_score = -1
    for branch in view.branches:
        for n in _walk(branch.root):
            if n.kind not in (NodeKind.ACTION, NodeKind.REMEDIATION):
                continue
            s = priority.get(n.state, -1)
            if s > best_score:
                best_score = s
                best = n
    return best.node_id if best else None


def _walk(node: BranchNode):
    yield node
    for c in node.children:
        yield from _walk(c)
