"""Corridor grouping helpers used by the investigation-flow partial.

Replaces the old topology.py module after the Phase 33 legacy-removal pass.
Pre-removal, these helpers lived alongside the React-Flow JSON serializer,
which had accreted layout constants, position emitters, JSON shape code,
and rendering primitives that no operator surface still uses. Only the
pure grouping + edge-label vocabulary is kept here.

Public API:
  group_branches_by_corridor(view) -> (corridor_order, corridor_branches, cluster_labels)
  compute_active_corridor(view, corridor_order=None, corridor_branches=None)
  semantic_edge_label(edge_kind) -> str

All deterministic; no React Flow, no JSON serializer, no layout maths.
"""
from __future__ import annotations

from apps.investigation_workspace.branch.model import (
    BranchState,
    NodeKind,
    WorkspaceView,
)


def group_branches_by_corridor(
    view: WorkspaceView,
) -> tuple[list[str], dict[str, list], dict[str, str]]:
    """Group view.branches by primary cluster.

    Returns:
      (corridor_order, corridor_branches, cluster_label_lookup)
    """
    cluster_label_lookup = _build_cluster_label_lookup()
    corridor_order: list[str] = []
    corridor_branches: dict[str, list] = {}
    for branch in view.branches:
        cid = _primary_cluster_for_branch(branch)
        if cid not in corridor_branches:
            corridor_order.append(cid)
            corridor_branches[cid] = []
        corridor_branches[cid].append(branch)
    return corridor_order, corridor_branches, cluster_label_lookup


def compute_active_corridor(
    view: WorkspaceView,
    corridor_order: list[str] | None = None,
    corridor_branches: dict[str, list] | None = None,
) -> str | None:
    """Pick the highest-priority corridor.

    Priority scoring: regression=5, verification_running/active=3,
    remediation_pending=2, available=1. Tie-break by insertion order.
    """
    if corridor_order is None or corridor_branches is None:
        corridor_order, corridor_branches, _ = group_branches_by_corridor(view)
    if not corridor_order:
        return None

    pts_for_state = {
        BranchState.REGRESSION:           5,
        BranchState.VERIFICATION_RUNNING: 3,
        BranchState.ACTIVE:               3,
        BranchState.REMEDIATION_PENDING:  2,
        BranchState.AVAILABLE:            1,
    }
    best: str = corridor_order[0]
    best_score: int = -1
    for cid in corridor_order:
        score = 0
        for branch in corridor_branches[cid]:
            for n in _walk_branch_nodes(branch.root):
                if n.kind == NodeKind.SURFACE:
                    continue
                score += pts_for_state.get(n.state, 0)
        if score > best_score:
            best_score = score
            best = cid
    return best


def semantic_edge_label(edge_kind: str) -> str:
    """Operator-facing causality label for a CausalEdge.edge_kind."""
    return {
        "surface_groups":            "groups",
        "finding_implies_action":    "probe path",
        "finding_implies_milestone": "objective",
        "action_yields_evidence":    "evidence captured",
        "theme_implies_remediation": "mitigation",
        "finding_implies_theme":     "root cause",
    }.get(edge_kind, "")


# ────────────────────────────────────────────────────────────────────────


def _walk_branch_nodes(node):
    yield node
    for c in node.children:
        yield from _walk_branch_nodes(c)


def _build_cluster_label_lookup() -> dict[str, str]:
    from apps.investigation_core.intelligence.clusters import CLUSTERS
    out: dict[str, str] = {cid: cluster.label for cid, cluster in CLUSTERS.items()}
    out.setdefault("uncategorised", "Other surfaces")
    return out


def _primary_cluster_for_branch(branch) -> str:
    """Dominant cluster for a branch's discoveries.

    Walks each discovery's remediation children (whose remediation_action_id
    maps back via CLUSTER_TO_DEFENSIVE_ACTIONS); falls back to a label-text
    heuristic for findings that aren't yet in the cluster registry.
    """
    from collections import Counter

    counts: Counter = Counter()
    for disc in branch.root.children:
        for child in disc.children:
            if child.kind == NodeKind.REMEDIATION and child.remediation_action_id:
                cid = _cluster_for_remediation_action(child.remediation_action_id)
                if cid:
                    counts[cid] += 1
                    break
        if not counts and disc.label:
            label_lower = disc.label.lower()
            if "sql injection" in label_lower or "sqli" in label_lower:
                counts["unsafe_input_handling"] += 1
            elif "xss" in label_lower:
                counts["unsafe_input_handling"] += 1
            elif "csp" in label_lower or "hsts" in label_lower or "header" in label_lower:
                counts["weak_hardening_posture"] += 1
            elif "disclosure" in label_lower or "leak" in label_lower or "banner" in label_lower:
                counts["excessive_disclosure"] += 1
            elif "auth" in label_lower or "credential" in label_lower or "session" in label_lower:
                counts["weak_authentication"] += 1

    if not counts:
        return "uncategorised"
    return counts.most_common(1)[0][0]


def _cluster_for_remediation_action(action_id: str) -> str | None:
    from apps.investigation_core.intelligence.clusters import (
        CLUSTER_TO_DEFENSIVE_ACTIONS,
    )
    for cluster_id, action_ids in CLUSTER_TO_DEFENSIVE_ACTIONS.items():
        if action_id in action_ids:
            return cluster_id
    return None
