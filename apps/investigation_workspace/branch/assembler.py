"""BranchAssembler — derive the investigation branch graph from stored data.

Phase 19. Pure deterministic re-shaping of:
  - findings (apps/scanner_orchestration)
  - approvals + artifacts + milestones (apps/investigation_core)
  - themes / clusters (apps/investigation_core/intelligence)
  - defensive snapshots (apps/investigation_core/defensive)

No autonomous reasoning. No LLM. Every node carries `why`.
"""
from __future__ import annotations

from datetime import UTC, datetime

import aiosqlite

from apps.investigation_workspace.branch.model import (
    BranchNode,
    BranchState,
    CausalEdge,
    InvestigationBranch,
    NodeKind,
    StorylineEntry,
    ThemeOverlay,
    WorkspaceView,
)
from apps.investigation_workspace.branch.states import (
    aggregate_branch_state,
    defensive_confidence_glyph,
    defensive_confidence_label,
    derive_action_state,
    derive_discovery_state,
    derive_remediation_state,
    state_badge_text,
    state_icon,
)
from apps.investigation_workspace.feed.interpretations import interpret
from apps.investigation_workspace.feed.lifecycle import derive_lifecycle

# ── Datetime normalisation ────────────────────────────────────────────────
# Stored datetimes in the codebase are a mix:
#   - aware UTC: NormalizedFinding/EvidenceArtifact when written via the seeded
#                paths that use `datetime.now(timezone.utc)`
#   - naive UTC: anything created via `datetime.utcnow()` (e.g. PostureSnapshot,
#                some legacy paths)
# Comparing them raises TypeError. `_utc_aware` coerces None → epoch, naive →
# aware-UTC (assumes naive values are UTC, which is true throughout this app).
_EPOCH_UTC = datetime.min.replace(tzinfo=UTC)


def _utc_aware(dt: datetime | None) -> datetime:
    if dt is None:
        return _EPOCH_UTC
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


class BranchAssembler:
    """Builds a WorkspaceView from stored investigation data."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    # ------------------------------------------------------------------ #
    # Entry point                                                        #
    # ------------------------------------------------------------------ #

    async def assemble(self, investigation_id: str, target: str) -> WorkspaceView:
        # Lazy imports — bounded-context isolation (same pattern as FeedBuilder).
        from apps.investigation_core.defensive.models.posture import (
            PostureSnapshotKind,
        )
        from apps.investigation_core.defensive.services.posture_service import (
            PostureSnapshotService,
            compare_snapshots,
        )
        from apps.investigation_core.evidence.storage.artifact_repo import (
            ArtifactRepository,
        )
        from apps.investigation_core.guided_actions.approvals.approval_service import (
            ApprovalService,
        )
        from apps.investigation_core.guided_actions.registry.action_registry import (
            action_registry,
        )
        from apps.investigation_core.intelligence.clusters import (
            CLUSTER_TO_DEFENSIVE_ACTIONS,
            CLUSTERS,
        )
        from apps.investigation_core.intelligence.engine import themes_for_findings
        from apps.investigation_core.storage.timeline_repo import TimelineRepository
        from apps.scanner_orchestration.services.orchestration_service import (
            OrchestrationService,
        )

        # ── 1. Load primary data ─────────────────────────────────────────
        orch = OrchestrationService(self._db)
        findings = await orch.list_all_findings(investigation_id)

        approvals = await ApprovalService(self._db).list_approvals(investigation_id)
        approval_by_action: dict[str, list] = {}
        for a in approvals:
            approval_by_action.setdefault(a.action_id, []).append(a)
        for lst in approval_by_action.values():
            lst.sort(key=lambda x: _utc_aware(x.requested_at), reverse=True)

        all_artifacts = await ArtifactRepository(self._db).list_for_investigation(
            investigation_id,
        )
        artifacts_by_action: dict[str, list] = {}
        artifacts_by_finding: dict[str, list] = {}
        for art in all_artifacts:
            if art.guided_action_id:
                artifacts_by_action.setdefault(art.guided_action_id, []).append(art)
            if art.finding_id:
                artifacts_by_finding.setdefault(art.finding_id, []).append(art)

        # Phase 59a — milestone subsystem removed. Empty maps preserved
        # so the section-3.2 reader (also removed in this PR) and any
        # remaining consumers see dict-shaped values instead of crashing.
        milestones_by_key: dict[str, list] = {}
        milestones_by_finding: dict[str, list] = {}

        themes = themes_for_findings(findings, evidence=all_artifacts)

        # ── Phase 21: per-defensive-action signals ─────────────────────
        # 1. Approval state for every defensive action_id this investigation
        #    has touched. Reuses ApprovalService — defensive actions are
        #    just GuidedActions with is_defensive=True.
        defensive_approval_by_action: dict[str, str] = {}
        for a in approvals:
            # str() because ApprovalStatus is a StrEnum.
            defensive_approval_by_action[a.action_id] = str(a.status)

        # 2. Evidence-count map (already keyed by action_id above via
        #    artifacts_by_action — re-used for defensive actions).

        # 3. Regression set from PostureService comparison.
        #    Find the latest POST_REMEDIATION snapshot and compare it against
        #    a subsequent (regression_check / ad_hoc / baseline) snapshot.
        #    PostureService.compare_snapshots populates `themes_regressed`
        #    only when the BEFORE snapshot is POST_REMEDIATION.
        regression_cluster_ids: set[str] = set()
        regression_action_ids: set[str] = set()
        comparison_view = None
        baseline_snap = None
        post_remediation_snap = None
        try:
            posture_svc = PostureSnapshotService(self._db)
            snapshots = await posture_svc.list_for_investigation(investigation_id)
            # Sort ascending by captured_at so "before" is older.
            snapshots.sort(key=lambda s: _utc_aware(s.captured_at))

            # Latest post-remediation snapshot
            post_remediation_snap = next(
                (s for s in reversed(snapshots)
                 if str(s.snapshot_kind) == PostureSnapshotKind.POST_REMEDIATION),
                None,
            )
            # First-recorded baseline / pre_remediation for the before/after
            # panel — earliest snapshot before any post_remediation entry.
            for s in snapshots:
                if str(s.snapshot_kind) in (
                    PostureSnapshotKind.BASELINE,
                    PostureSnapshotKind.PRE_REMEDIATION,
                ):
                    baseline_snap = s
                    break

            # Regression detection — needs a POST_REMEDIATION followed by
            # ANY later snapshot (regression_check / ad_hoc / baseline).
            if post_remediation_snap is not None:
                later = [
                    s for s in snapshots
                    if _utc_aware(s.captured_at) > _utc_aware(post_remediation_snap.captured_at)
                ]
                if later:
                    cmp = compare_snapshots(post_remediation_snap, later[-1])
                    for td in cmp.themes_regressed:
                        regression_cluster_ids.add(td.cluster_id)

            # Build action-level regression set via CLUSTER_TO_DEFENSIVE_ACTIONS.
            from apps.investigation_core.intelligence.clusters import (
                CLUSTER_TO_DEFENSIVE_ACTIONS as _C2D,
            )
            for cid in regression_cluster_ids:
                for aid in _C2D.get(cid, ()):
                    regression_action_ids.add(aid)

            # Build the before/after PostureComparison for the workspace
            # view (Part D). Prefer baseline/pre_remediation → post_remediation
            # pair when both exist; otherwise compare the earliest two.
            if (baseline_snap and post_remediation_snap
                    and baseline_snap.snapshot_id != post_remediation_snap.snapshot_id):
                comparison_view = compare_snapshots(
                    baseline_snap, post_remediation_snap,
                )
            elif len(snapshots) >= 2:
                comparison_view = compare_snapshots(snapshots[0], snapshots[-1])
        except Exception:
            # Snapshot infrastructure missing or empty → branches still render.
            comparison_view = None

        # ── 2. Group findings into surfaces ─────────────────────────────
        surfaces = _group_into_surfaces(findings)

        # ── 3. Build a branch per surface ───────────────────────────────
        branches: list[InvestigationBranch] = []
        edges_all: list[CausalEdge] = []
        storyline: list[StorylineEntry] = []

        for surface_key, surface_findings in surfaces.items():
            branch = self._build_surface_branch(
                surface_key=surface_key,
                findings=surface_findings,
                approval_by_action=approval_by_action,
                defensive_approval_by_action=defensive_approval_by_action,
                artifacts_by_action=artifacts_by_action,
                artifacts_by_finding=artifacts_by_finding,
                milestones_by_finding=milestones_by_finding,
                milestones_by_key=milestones_by_key,
                action_registry=action_registry,
                cluster_to_defensive=CLUSTER_TO_DEFENSIVE_ACTIONS,
                clusters=CLUSTERS,
                regression_action_ids=regression_action_ids,
            )
            branches.append(branch)
            edges_all.extend(branch.edges)
            storyline.extend(_storyline_for_branch(branch))

        # ── 4. Cross-cutting theme overlays ─────────────────────────────
        finding_id_to_branch: dict[str, str] = {}
        finding_type_to_branch_ids: dict[str, list[str]] = {}
        for branch in branches:
            for n in _walk(branch.root):
                if n.kind == NodeKind.DISCOVERY and n.finding_id:
                    finding_id_to_branch[n.finding_id] = branch.branch_id

        # Map finding_type → branch_ids by scanning findings list once.
        for f in findings:
            bid = finding_id_to_branch.get(f.finding_id)
            if bid:
                finding_type_to_branch_ids.setdefault(f.finding_type, []).append(bid)

        # Pre-compute per-cluster remediation-state counts by walking the
        # REMEDIATION nodes built into each branch (Phase 21 Part G).
        cluster_remediation_counts: dict[str, dict[str, int]] = {}
        from apps.investigation_core.intelligence.clusters import (
            CLUSTER_TO_DEFENSIVE_ACTIONS as _C2D_for_counts,
        )
        action_to_clusters: dict[str, list[str]] = {}
        for cid, action_ids in _C2D_for_counts.items():
            for aid in action_ids:
                action_to_clusters.setdefault(aid, []).append(cid)
        for branch in branches:
            for n in _walk(branch.root):
                if n.kind != NodeKind.REMEDIATION or not n.remediation_action_id:
                    continue
                for cid in action_to_clusters.get(n.remediation_action_id, []):
                    bucket = cluster_remediation_counts.setdefault(
                        cid, {"verified": 0, "running": 0, "unverified": 0, "regressed": 0},
                    )
                    if n.state == BranchState.VERIFIED:
                        bucket["verified"] += 1
                    elif n.state == BranchState.VERIFICATION_RUNNING:
                        bucket["running"] += 1
                    elif n.state == BranchState.REGRESSION:
                        bucket["regressed"] += 1
                    else:
                        bucket["unverified"] += 1

        theme_overlays: list[ThemeOverlay] = []
        for theme in themes:
            cluster = CLUSTERS.get(theme.theme_id)
            matching_branch_ids: list[str] = []
            for ft in theme.matching_finding_types:
                for bid in finding_type_to_branch_ids.get(ft, []):
                    if bid not in matching_branch_ids:
                        matching_branch_ids.append(bid)
            counts = cluster_remediation_counts.get(theme.theme_id, {})
            theme_overlays.append(ThemeOverlay(
                theme_id=theme.theme_id,
                label=cluster.label if cluster else theme.label,
                description=theme.description,
                confidence=theme.confidence,
                matching_branch_ids=matching_branch_ids,
                remediation_concepts=list(theme.remediation_concepts),
                remediation_documented=theme.remediation_documented,
                why=theme.why,
                verified_remediation_count=counts.get("verified", 0),
                running_remediation_count=counts.get("running", 0),
                unverified_remediation_count=counts.get("unverified", 0),
                regressed_remediation_count=counts.get("regressed", 0),
            ))

        # ── 5. Storyline — chronological branch-tagged narrative ────────
        # Augment with timeline events so the storyline is anchored in real time.
        try:
            timeline_events = await TimelineRepository(self._db).list_for_investigation(
                investigation_id, limit=200,
            )
            for ev in timeline_events:
                d = ev.detail or {}
                fid = d.get("finding_id")
                bid = finding_id_to_branch.get(fid) if fid else None
                if not bid:
                    continue
                label, icon, state = _storyline_label_for_event(ev.event_type, d)
                if label:
                    storyline.append(StorylineEntry(
                        timestamp=ev.timestamp,
                        branch_id=bid,
                        label=label,
                        icon=icon,
                        state=state,
                        why=f"Timeline event `{ev.event_type}` on this branch.",
                    ))
        except Exception:
            pass

        storyline.sort(key=lambda s: _utc_aware(s.timestamp))

        # ── 6. Aggregate header counts (investigation-progression only) ─
        # Phase 21: VERIFIED / VERIFICATION_RUNNING also count toward
        # "in remediation" / "with evidence" / "progressed" buckets.
        _PROGRESSED = {
            BranchState.COMPLETED,
            BranchState.EVIDENCE_ATTACHED,
            BranchState.REMEDIATION_PENDING,
            BranchState.VERIFICATION_RUNNING,
            BranchState.VERIFIED,
            BranchState.REGRESSION,
        }
        _WITH_EVIDENCE = {
            BranchState.EVIDENCE_ATTACHED,
            BranchState.VERIFICATION_RUNNING,
            BranchState.VERIFIED,
            BranchState.REGRESSION,
        }
        _IN_REMEDIATION = {
            BranchState.REMEDIATION_PENDING,
            BranchState.VERIFICATION_RUNNING,
            BranchState.VERIFIED,
            BranchState.REGRESSION,
        }
        branch_count_completed = 0
        branch_count_evidence = 0
        branch_count_remediation = 0
        regression_count = 0
        for b in branches:
            if b.state in _PROGRESSED:
                branch_count_completed += 1
            if b.state in _WITH_EVIDENCE:
                branch_count_evidence += 1
            if b.state in _IN_REMEDIATION:
                branch_count_remediation += 1
            if b.state == BranchState.REGRESSION:
                regression_count += 1

        # ── 7. Progressive reveal — clamp deeply nested branches ────────
        for b in branches:
            _apply_progressive_reveal(b)

        # ── 8. Before/after comparison panel (Part D) ───────────────────
        comparison_kwargs: dict = {}
        if comparison_view is not None:
            cv = comparison_view
            comparison_kwargs = {
                "comparison_available":     True,
                "comparison_before_label":  cv.before.label,
                "comparison_after_label":   cv.after.label,
                "comparison_resolved":      [_theme_delta_to_view(t) for t in cv.themes_resolved],
                "comparison_unchanged":     [_theme_delta_to_view(t) for t in cv.themes_unchanged],
                "comparison_emerging":      [_theme_delta_to_view(t) for t in cv.themes_emerging],
                "comparison_regressed":     [_theme_delta_to_view(t) for t in cv.themes_regressed],
                "comparison_strengthened":
                    [_theme_delta_to_view(t) for t in cv.themes_strengthened],
                "comparison_why":           cv.why,
            }

        return WorkspaceView(
            investigation_id=investigation_id,
            target=target,
            branches=branches,
            theme_overlays=theme_overlays,
            storyline=storyline,
            branch_count_total=len(branches),
            branch_count_completed=branch_count_completed,
            branch_count_with_evidence=branch_count_evidence,
            branch_count_in_remediation=branch_count_remediation,
            regression_count=regression_count,
            **comparison_kwargs,
        )

    # ------------------------------------------------------------------ #
    # Per-surface branch builder                                         #
    # ------------------------------------------------------------------ #

    def _build_surface_branch(
        self,
        *,
        surface_key: str,
        findings: list,
        approval_by_action: dict[str, list],
        defensive_approval_by_action: dict[str, str],
        artifacts_by_action: dict[str, list],
        artifacts_by_finding: dict[str, list],
        milestones_by_finding: dict[str, list],
        milestones_by_key: dict[str, list],
        action_registry,
        cluster_to_defensive: dict[str, tuple[str, ...]],
        clusters: dict,
        regression_action_ids: set[str],
    ) -> InvestigationBranch:
        from apps.investigation_core.intelligence.clusters import clusters_for_finding_type

        edges: list[CausalEdge] = []
        branch_id = _safe_id("surface", surface_key)

        # Surface root node — language is investigation-centric, not
        # scanner-centric ("Surface" not "Scanner output").
        surface_label, surface_detail = _surface_label(surface_key, findings)
        surface_node = BranchNode(
            node_id=branch_id,
            kind=NodeKind.SURFACE,
            label=surface_label,
            state=BranchState.AVAILABLE,
            why=(
                f"{len(findings)} discovery(ies) share this surface — "
                "grouped to surface causal lineage."
            ),
            icon="◐",
            detail=surface_detail,
        )

        discovery_states: list[BranchState] = []

        for f in findings:
            interp = interpret(f.finding_type)
            disc_node_id = _safe_id("disc", f.finding_id)

            # ── 3.1 Build ACTION children ───────────────────────────────
            action_nodes: list[BranchNode] = []
            action_states: list[BranchState] = []
            seen_action_ids: set[str] = set()

            for aid in (interp.get("actions") or []):
                if aid in seen_action_ids:
                    continue
                seen_action_ids.add(aid)
                act = action_registry.get(aid)
                if not act:
                    continue

                apr = (approval_by_action.get(aid) or [None])[0]
                evidence_for_action = artifacts_by_action.get(aid, [])
                lc = derive_lifecycle(apr, evidence_for_action)
                deriv = derive_action_state(
                    lifecycle_state=lc.state,
                    evidence_count=lc.evidence_count,
                    parent_unlocked=True,
                )
                action_states.append(deriv.state)

                # Evidence children — leaves under the action node
                evidence_children: list[BranchNode] = []
                for art in evidence_for_action:
                    ev_node = BranchNode(
                        node_id=_safe_id("ev", art.artifact_id),
                        kind=NodeKind.EVIDENCE,
                        label=_short_evidence_label(art),
                        state=BranchState.EVIDENCE_ATTACHED,
                        why="Operator captured this artifact while progressing the step.",
                        icon=state_icon(BranchState.EVIDENCE_ATTACHED),
                        badge=state_badge_text(BranchState.EVIDENCE_ATTACHED),
                        evidence_id=art.artifact_id,
                        latest_at=getattr(art, "captured_at", None),
                    )
                    evidence_children.append(ev_node)
                    edges.append(CausalEdge(
                        parent_id=_safe_id("act", aid),
                        child_id=ev_node.node_id,
                        edge_kind="action_yields_evidence",
                        why="Evidence artifact is linked to this guided action.",
                    ))

                action_node = BranchNode(
                    node_id=_safe_id("act", aid),
                    kind=NodeKind.ACTION,
                    label=act.title,
                    state=deriv.state,
                    why=deriv.why,
                    icon=state_icon(deriv.state),
                    severity_class=("ok" if deriv.state in (
                        BranchState.COMPLETED, BranchState.EVIDENCE_ATTACHED,
                    ) else "info"),
                    detail=_action_detail(act),
                    badge=state_badge_text(deriv.state),
                    action_id=aid,
                    evidence_goals=list(interp.get("evidence_goals") or []),
                    learning_concepts=list(interp.get("learning_concepts") or []),
                    # Phase 25 — contextual narrative: action.why_this_matters
                    # already reads as an observation-grounded explanation.
                    narrative=(
                        getattr(act, "why_this_matters", "")
                        or getattr(act, "explanation", "")
                    ),
                    children=evidence_children,
                )
                action_nodes.append(action_node)
                edges.append(CausalEdge(
                    parent_id=disc_node_id,
                    child_id=action_node.node_id,
                    edge_kind="finding_implies_action",
                    why=(
                        "Action recommended by deterministic interpretation for "
                        f"finding_type `{f.finding_type}`."
                    ),
                ))

            # Phase 59a — section 3.2 (MILESTONE children) removed. The
            # milestone subsystem was vestige per the Phase 58 audit:
            # "Mark achieved" buttons against canned CTF objective text
            # never executed real work. Empty list preserved so the
            # children-collection step below still works uniformly.
            milestone_nodes: list[BranchNode] = []
            milestone_states: list[BranchState] = []

            # ── 3.3 Build REMEDIATION children (defensive overlay) ──────
            remediation_nodes: list[BranchNode] = []
            remediation_states: list[BranchState] = []
            cluster_objs = clusters_for_finding_type(f.finding_type)
            seen_remediation_ids: set[str] = set()
            for cluster in cluster_objs:
                for raid in cluster_to_defensive.get(cluster.cluster_id, ()):
                    if raid in seen_remediation_ids:
                        continue
                    seen_remediation_ids.add(raid)
                    # Phase 21: derive state from approval + evidence + regression set.
                    raid_approval_status = defensive_approval_by_action.get(raid)
                    raid_evidence_count = len(artifacts_by_action.get(raid, []))
                    has_regression = raid in regression_action_ids
                    deriv = derive_remediation_state(
                        is_documented=True,
                        approval_status=raid_approval_status,
                        evidence_count=raid_evidence_count,
                        has_regression=has_regression,
                    )
                    remediation_states.append(deriv.state)
                    r_node = BranchNode(
                        node_id=_safe_id("rem", f"{f.finding_id}:{raid}"),
                        kind=NodeKind.REMEDIATION,
                        label=_humanise_action_id(raid),
                        state=deriv.state,
                        why=deriv.why,
                        icon=state_icon(deriv.state),
                        severity_class=(
                            "critical" if deriv.state == BranchState.REGRESSION
                            else "ok" if deriv.state == BranchState.VERIFIED
                            else "info"
                        ),
                        badge=state_badge_text(deriv.state),
                        remediation_action_id=raid,
                        confidence_glyph=defensive_confidence_glyph(deriv.state),
                        confidence_label=defensive_confidence_label(deriv.state),
                        # Phase 25 — contextual narrative pulled from the
                        # defensive GuidedAction's why_this_matters /
                        # remediation_context (observation-grounded).
                        narrative=_remediation_narrative(action_registry, raid),
                    )
                    remediation_nodes.append(r_node)
                    edges.append(CausalEdge(
                        parent_id=disc_node_id,
                        child_id=r_node.node_id,
                        edge_kind="theme_implies_remediation",
                        why=(
                            f"Cluster `{cluster.cluster_id}` declares "
                            f"`{raid}` as a defensive verification."
                        ),
                    ))

            # ── 3.4 Discovery node (aggregate of its children) ──────────
            child_states = action_states + milestone_states + remediation_states
            disc_deriv = derive_discovery_state(child_states=child_states)
            discovery_states.append(disc_deriv.state)

            disc_node = BranchNode(
                node_id=disc_node_id,
                kind=NodeKind.DISCOVERY,
                label=_discovery_label(f, interp),
                state=disc_deriv.state,
                why=disc_deriv.why,
                icon=state_icon(disc_deriv.state),
                severity_class=f.severity or "info",
                detail=_discovery_detail(f),
                badge=state_badge_text(disc_deriv.state),
                finding_id=f.finding_id,
                finding_type=f.finding_type,        # Phase 48 — used by suggestion lookup
                evidence_goals=list(interp.get("evidence_goals") or []),
                learning_concepts=list(interp.get("learning_concepts") or []),
                # Phase 59a — ctf_objectives still surfaces the narrative
                # text list (read by feed/builder.py for the finding
                # detail panel); the corresponding ctf_objective_keys
                # list and the Milestone-kind nodes that consumed it
                # were the parts removed.
                ctf_objectives=list(interp.get("ctf_objectives") or []),
                # Phase 25 — contextual narrative: interp.meaning is the
                # operator-readable observation that grounds the finding.
                narrative=str(interp.get("meaning") or ""),
                children=action_nodes + milestone_nodes + remediation_nodes,
                earliest_at=getattr(f, "created_at", None),
            )
            surface_node.children.append(disc_node)
            edges.append(CausalEdge(
                parent_id=branch_id,
                child_id=disc_node_id,
                edge_kind="surface_groups",
                why="Discovery shares the surface key (endpoint or service/port).",
            ))

        # Surface state — aggregate from discoveries
        surface_state = aggregate_branch_state(discovery_states)
        surface_node.state = surface_state
        surface_node.icon = state_icon(surface_state)
        surface_node.badge = state_badge_text(surface_state)
        surface_node.why = (
            f"Aggregate of {len(findings)} discovery state(s) on this surface."
        )

        return InvestigationBranch(
            branch_id=branch_id,
            root=surface_node,
            edges=edges,
            state=surface_state,
        )


# ====================================================================== #
# Helpers — deterministic, pure                                          #
# ====================================================================== #

def _group_into_surfaces(findings: list) -> dict[str, list]:
    """Group findings by surface key.

    Surface key is the most-specific stable grouping available:
      1. endpoint (HTTP path) if set
      2. otherwise `port/{port}` if port set
      3. otherwise `target/{target}` as a catchall

    Result is ordered by insertion (Python 3.7+ dicts preserve order) which
    keeps surface rendering stable across page loads.
    """
    out: dict[str, list] = {}
    for f in findings:
        if getattr(f, "endpoint", None):
            key = f"endpoint/{f.endpoint}"
        elif getattr(f, "port", None):
            key = f"port/{f.port}"
        else:
            key = f"target/{getattr(f, 'target', '?')}"
        out.setdefault(key, []).append(f)
    return out


def _surface_label(surface_key: str, findings: list) -> tuple[str, str]:
    """Human label + one-line detail for a surface."""
    if surface_key.startswith("endpoint/"):
        path = surface_key.split("/", 1)[1]
        return f"Surface: {path}", f"{len(findings)} discovery(ies) at this endpoint"
    if surface_key.startswith("port/"):
        port = surface_key.split("/", 1)[1]
        return (
            f"Surface: port {port}",
            f"{len(findings)} discovery(ies) on this service",
        )
    if surface_key.startswith("target/"):
        return (
            "Surface: target",
            f"{len(findings)} discovery(ies) without endpoint/port context",
        )
    return surface_key, f"{len(findings)} discovery(ies)"


def _discovery_label(finding, interp: dict) -> str:
    """Choose the most informative label for a finding node.

    Phase 43 — prefer the finding's own title over the interpretation
    headline. interp.headline is "Finding identified" for any finding_type
    not registered in FINDING_INTERPRETATIONS, which used to display as
    generic placeholder text on the topology. The scanner / bootstrap
    writes a real title; surface that instead and fall back to the
    interpretation headline only when title is empty.
    """
    title = (finding.title or "").strip()
    if title:
        return title
    return str(interp.get("headline") or "Discovery")


def _discovery_detail(finding) -> str:
    bits: list[str] = []
    if finding.port:
        bits.append(f"port {finding.port}")
    if finding.endpoint:
        bits.append(finding.endpoint[:60])
    if finding.source_scanner:
        bits.append(f"via {finding.source_scanner}")
    return " · ".join(bits)


def _action_detail(action) -> str:
    summary = getattr(action, "summary", "") or getattr(action, "description", "")
    return str(summary or "")[:160]


def _short_evidence_label(art) -> str:
    kind = getattr(art, "artifact_type", "") or "artifact"
    title = getattr(art, "title", "") or getattr(art, "name", "")
    return f"{kind}: {title}" if title else f"{kind}"


def _humanise_action_id(action_id: str) -> str:
    return action_id.replace("verify_", "Verify ").replace("_", " ")


def _remediation_narrative(action_registry, action_id: str) -> str:
    """Best-effort narrative for a defensive verification action."""
    act = action_registry.get(action_id)
    if not act:
        return ""
    bits: list[str] = []
    for attr in ("why_this_matters", "remediation_context", "explanation"):
        val = getattr(act, attr, "")
        if val:
            bits.append(str(val))
            break
    return " ".join(bits)


def _safe_id(prefix: str, key) -> str:
    """DOM-safe node id."""
    safe = "".join(c if c.isalnum() else "-" for c in str(key))[:80]
    return f"{prefix}-{safe}"


def _walk(node: BranchNode):
    yield node
    for c in node.children:
        yield from _walk(c)


def _storyline_for_branch(branch: InvestigationBranch) -> list[StorylineEntry]:
    """Build a synthetic storyline entry per non-locked node — used as a
    fallback when timeline_events don't link to the finding (e.g. milestones
    achieved via the milestone API without a finding_id).
    """
    entries: list[StorylineEntry] = []
    for n in _walk(branch.root):
        if n.kind == NodeKind.SURFACE:
            continue
        if n.state == BranchState.LOCKED:
            continue
        ts = n.latest_at or n.earliest_at
        if ts is None:
            continue
        entries.append(StorylineEntry(
            timestamp=ts,
            branch_id=branch.branch_id,
            label=f"{n.label}",
            icon=n.icon,
            state=n.state,
            why=n.why,
        ))
    return entries


def _storyline_label_for_event(event_type: str, detail: dict) -> tuple[str, str, BranchState]:
    """Map a timeline event into a storyline beat. Returns ("", "·", AVAILABLE)
    if the event isn't a branch-narrative beat (the caller filters those out).
    """
    et = str(event_type)
    if et == "guided_action_completed":
        return (
            f"Step completed: {detail.get('action_id', '')}",
            state_icon(BranchState.COMPLETED),
            BranchState.COMPLETED,
        )
    if et == "evidence_captured":
        return (
            "Evidence captured on this branch",
            state_icon(BranchState.EVIDENCE_ATTACHED),
            BranchState.EVIDENCE_ATTACHED,
        )
    # Phase 59a — milestone_achieved event branch removed (no emitter
    # exists after milestone subsystem removal). The EventType enum
    # value lives on as taxonomy/stages.py::EventType.MILESTONE_ACHIEVED
    # pending Phase 59d cleanup.
    if et == "action_started":
        return (
            f"Step started: {detail.get('action_id', '')}",
            state_icon(BranchState.ACTIVE),
            BranchState.ACTIVE,
        )
    # Phase 21 — defensive lifecycle beats
    if et == "posture_snapshot_captured":
        kind = detail.get("kind") or detail.get("snapshot_kind") or ""
        return (
            f"Posture snapshot captured ({kind})",
            state_icon(BranchState.VERIFIED),
            BranchState.VERIFIED,
        )
    if et == "verification_evidence_captured":
        aid = detail.get("action_id", "")
        return (
            f"Verification evidence captured: {aid}",
            state_icon(BranchState.VERIFICATION_RUNNING),
            BranchState.VERIFICATION_RUNNING,
        )
    if et == "remediation_verified":
        aid = detail.get("action_id", "")
        return (
            f"Remediation verified: {aid}",
            state_icon(BranchState.VERIFIED),
            BranchState.VERIFIED,
        )
    if et == "regression_detected":
        aid = detail.get("action_id", "") or detail.get("cluster_id", "")
        return (
            f"Regression detected: {aid}",
            state_icon(BranchState.REGRESSION),
            BranchState.REGRESSION,
        )
    return ("", "·", BranchState.AVAILABLE)


def _theme_delta_to_view(td) -> dict:
    """Flatten a PostureService.ThemeDelta into a template-friendly dict."""
    return {
        "cluster_id":     td.cluster_id,
        "label":          td.label,
        "state":          td.state,
        "before_count":   td.before_finding_count,
        "after_count":    td.after_finding_count,
        "before_confidence": td.before_confidence or "",
        "after_confidence":  td.after_confidence or "",
    }


# ====================================================================== #
# Progressive reveal                                                     #
# ====================================================================== #

def _apply_progressive_reveal(branch: InvestigationBranch) -> None:
    """Deterministic depth clamp (Part G).

    Rules:
      - Depth 0 (surface) and 1 (discovery) are ALWAYS shown.
      - Depth 2 (actions/milestones/remediation) — show unconditionally;
        operators need to see the recommended next steps even before
        starting them.
      - Depth 3+ (evidence beneath actions, etc.) — show only if the
        parent at depth 2 is past `available` state. Otherwise hidden
        and counted in `hidden_descendant_count`.

    Branches keep the data; the template chooses what to render based on
    `max_revealed_depth`. This implementation prunes the in-memory tree
    so the template stays simple.
    """
    hidden = 0
    for disc in branch.root.children:               # depth 1
        for child in disc.children:                 # depth 2 (action/milestone/remediation)
            if child.state == BranchState.AVAILABLE:
                hidden += len(child.children)
                child.children = []
    branch.hidden_descendant_count = hidden
    branch.max_revealed_depth = 3
