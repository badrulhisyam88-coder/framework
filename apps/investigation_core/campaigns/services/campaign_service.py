"""CampaignService — CRUD + cross-investigation snapshot aggregator.

The snapshot is purely derived: it reads from existing tables (timeline_events,
evidence_artifacts, normalized_findings) and reuses the Phase 15 intelligence
engine to aggregate themes / remediation gaps across all member investigations
of one campaign.

Phase 59a — `investigation_milestones` was a fourth source; removed
alongside the milestone subsystem. Campaign objective completion now
resolves purely from finding-type signals.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

import aiosqlite

from apps.investigation_core.campaigns.models.campaign import (
    STAGE_LABELS,
    STAGE_ORDER,
    CampaignStage,
    CampaignStatus,
    InvestigationCampaign,
)
from apps.investigation_core.campaigns.models.membership import CampaignMembership
from apps.investigation_core.campaigns.models.objective import ObjectiveStatus
from apps.investigation_core.campaigns.models.snapshot import (
    CampaignProgressSnapshot,
    CampaignStageProgress,
    CampaignTimelineEvent,
)
from apps.investigation_core.campaigns.storage.campaign_repo import CampaignRepository
from apps.investigation_core.campaigns.storage.membership_repo import (
    MembershipRepository,
)
from sdk import Logger


class CampaignService:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db
        self._campaign_repo = CampaignRepository(db)
        self._member_repo = MembershipRepository(db)

    # ── CRUD ────────────────────────────────────────────────────────────

    async def create_campaign(
        self,
        title: str,
        *,
        description: str = "",
        status: CampaignStatus = CampaignStatus.PLANNING,
        created_by: str = "user",
    ) -> InvestigationCampaign:
        campaign = InvestigationCampaign(
            title=title,
            description=description,
            status=status,
            created_by=created_by,
        )
        await self._campaign_repo.insert(campaign)
        Logger.info(
            "campaign.created",
            extra={"campaign_id": campaign.campaign_id, "title": title},
        )
        return campaign

    async def update_campaign(self, campaign: InvestigationCampaign) -> None:
        await self._campaign_repo.update(campaign)

    async def add_investigation(
        self,
        campaign_id: str,
        investigation_id: str,
        *,
        stage: CampaignStage = CampaignStage.RECON,
        parent_investigation_id: str | None = None,
        notes: str | None = None,
    ) -> CampaignMembership:
        existing = await self._member_repo.get(campaign_id, investigation_id)
        if existing:
            return existing
        # Sequence: append at the end
        all_members = await self._member_repo.list_for_campaign(campaign_id)
        seq = (max((m.sequence_order for m in all_members), default=-1)) + 1
        membership = CampaignMembership(
            campaign_id=campaign_id,
            investigation_id=investigation_id,
            stage=stage,
            sequence_order=seq,
            parent_investigation_id=parent_investigation_id,
            notes=notes,
        )
        await self._member_repo.insert(membership)
        Logger.info(
            "campaign.investigation_added",
            extra={
                "campaign_id": campaign_id,
                "investigation_id": investigation_id,
                "stage": str(stage),
                "parent": parent_investigation_id,
            },
        )
        return membership

    async def update_membership_stage(
        self, campaign_id: str, investigation_id: str, stage: CampaignStage
    ) -> None:
        await self._member_repo.update_stage(campaign_id, investigation_id, stage)

    async def detach_investigation(
        self, campaign_id: str, investigation_id: str
    ) -> None:
        await self._member_repo.delete(campaign_id, investigation_id)

    async def list_campaigns(self, limit: int = 200) -> list[InvestigationCampaign]:
        return await self._campaign_repo.list_all(limit)

    async def get_campaign(self, campaign_id: str) -> InvestigationCampaign | None:
        return await self._campaign_repo.get_by_id(campaign_id)

    async def list_memberships_for_investigation(
        self, investigation_id: str
    ) -> list[CampaignMembership]:
        return await self._member_repo.list_for_investigation(investigation_id)

    async def list_members(self, campaign_id: str) -> list[CampaignMembership]:
        return await self._member_repo.list_for_campaign(campaign_id)

    # ── Snapshot aggregator ─────────────────────────────────────────────

    async def progress_snapshot(self, campaign_id: str) -> CampaignProgressSnapshot:
        from apps.investigation_core.evidence.storage.artifact_repo import (
            ArtifactRepository,
        )
        from apps.investigation_core.guided_actions.approvals.approval_service import (
            ApprovalService,
        )
        from apps.investigation_core.guided_actions.models.approval import (
            ApprovalStatus,
        )
        from apps.investigation_core.intelligence.engine import (
            _build_documented_concept_index,
            _concept_match,
            themes_for_findings,
        )
        from apps.investigation_core.intelligence.models import (
            RemediationGap,
            ThemeRepetition,
        )
        from apps.investigation_core.storage.investigation_repo import (
            InvestigationRepository,
        )
        from apps.investigation_core.storage.timeline_repo import TimelineRepository
        from apps.scanner_orchestration.storage.finding_repo import (
            NormalizedFindingRepository,
        )

        members = await self._member_repo.list_for_campaign(campaign_id)
        snap = CampaignProgressSnapshot(
            campaign_id=campaign_id,
            computed_at=datetime.utcnow(),
            total_investigations=len(members),
        )
        if not members:
            return snap

        inv_repo = InvestigationRepository(self._db)
        finding_repo = NormalizedFindingRepository(self._db)
        art_repo = ArtifactRepository(self._db)
        # Phase 59a — MilestoneRepository removed; ms_repo references
        # below stubbed to empty results.
        tl_repo = TimelineRepository(self._db)
        approval_svc = ApprovalService(self._db)

        # Per-stage counts
        stage_counts: Counter = Counter()
        for m in members:
            stage_counts[str(m.stage)] += 1
        snap.investigations_by_stage = [
            CampaignStageProgress(
                stage=str(stg),
                label=STAGE_LABELS[str(stg)],
                investigation_count=stage_counts.get(str(stg), 0),
            )
            for stg in STAGE_ORDER
        ]

        # Aggregate across member investigations
        rep_count: Counter = Counter()
        rep_findings: Counter = Counter()
        rep_invs: dict[str, list[str]] = defaultdict(list)
        rep_labels: dict[str, str] = {}

        surfaced: Counter = Counter()
        documented: Counter = Counter()
        concept_clusters: dict[str, set[str]] = defaultdict(set)

        timeline_events: list[CampaignTimelineEvent] = []
        inv_titles: dict[str, str] = {}

        for m in members:
            inv = await inv_repo.get_by_id(m.investigation_id)
            inv_title = inv.title if inv else m.investigation_id[:8]
            inv_titles[m.investigation_id] = inv_title

            findings = await finding_repo.list_for_investigation(m.investigation_id)
            evidence = await art_repo.list_for_investigation(m.investigation_id)
            # Phase 59a — milestones removed; counter stays at 0.
            approvals = await approval_svc.list_approvals(m.investigation_id)

            snap.total_findings += len(findings)
            snap.total_evidence_artifacts += len(evidence)
            snap.total_actions_completed += sum(
                1 for a in approvals if a.status == ApprovalStatus.COMPLETED
            )

            # Theme aggregation
            themes = themes_for_findings(findings, evidence=evidence)
            ev_index = _build_documented_concept_index(evidence)
            for t in themes:
                rep_count[t.theme_id] += 1
                rep_findings[t.theme_id] += t.matching_finding_count
                rep_invs[t.theme_id].append(m.investigation_id)
                rep_labels[t.theme_id] = t.label
                for concept in t.remediation_concepts:
                    concept_clusters[concept].add(t.theme_id)
                    surfaced[concept] += 1
                    if _concept_match(concept, ev_index):
                        documented[concept] += 1

            # Timeline — investigation_joined synthetic event
            timeline_events.append(CampaignTimelineEvent(
                timestamp=m.joined_at,
                event_type="investigation_joined",
                summary=f"Investigation joined campaign at stage {STAGE_LABELS[str(m.stage)]}",
                investigation_id=m.investigation_id,
                investigation_title=inv_title,
                stage=str(m.stage),
                detail={"parent_investigation_id": m.parent_investigation_id},
            ))

            # Member milestones + exports → timeline
            ev_rows = await tl_repo.list_for_investigation(m.investigation_id, limit=300)
            for ev in ev_rows:
                et = str(ev.event_type)
                # Phase 59a — "milestone_achieved" removed from filter
                # (no emitters; EventType enum value lives on dormant).
                if et in (
                    "guided_action_completed",
                    "knowledge_exported", "scan_completed",
                ):
                    timeline_events.append(CampaignTimelineEvent(
                        timestamp=ev.timestamp,
                        event_type=et,
                        summary=ev.summary or et,
                        investigation_id=m.investigation_id,
                        investigation_title=inv_title,
                        stage=str(m.stage),
                        detail=ev.detail or {},
                    ))

        timeline_events.sort(key=lambda e: e.timestamp)
        # Cap to keep the narrative focused
        snap.timeline = timeline_events[-80:]

        # Themes repeated across ≥2 investigations
        for cid, count in rep_count.most_common():
            if count >= 2:
                snap.aggregated_themes.append(ThemeRepetition(
                    cluster_id=cid,
                    label=rep_labels[cid],
                    investigations_count=count,
                    total_findings=rep_findings[cid],
                    investigation_ids=rep_invs[cid][:8],
                ))

        # Remediation gaps — surfaced in ≥2 investigations, documented in <half
        for concept, s_count in surfaced.most_common():
            d_count = documented[concept]
            if s_count >= 2 and d_count * 2 < s_count:
                snap.common_remediation_gaps.append(RemediationGap(
                    concept=concept,
                    surfaced_in_investigations=s_count,
                    documented_in_investigations=d_count,
                    cluster_ids=sorted(concept_clusters[concept]),
                ))

        snap.common_remediation_gaps = snap.common_remediation_gaps[:10]

        # Update objective status on the campaign (deterministic check)
        await self._refresh_objectives(campaign_id, members)

        # Phase 17 — defensive aggregates across members
        await self._populate_defensive(snap, members)

        # Build strengths + unresolved
        snap.strengths = _build_strengths(snap)
        snap.unresolved_weaknesses = _build_unresolved(snap)

        return snap

    async def _populate_defensive(self, snap, members) -> None:
        """Aggregate per-investigation defensive maturity into campaign-level signal."""
        from apps.investigation_core.defensive.services.posture_service import (
            compare_snapshots,
        )
        from apps.investigation_core.defensive.storage.posture_repo import (
            PostureRepository,
        )
        from apps.investigation_core.guided_actions.approvals.approval_service import (
            ApprovalService,
        )
        from apps.investigation_core.guided_actions.models.approval import (
            ApprovalStatus,
        )
        from apps.investigation_core.guided_actions.registry.action_registry import (
            action_registry,
        )

        posture_repo = PostureRepository(self._db)
        approval_svc = ApprovalService(self._db)

        defensive_actions = 0
        post_snaps = 0
        improvements: list[str] = []
        regressions: list[str] = []

        for m in members:
            # Defensive actions completed (is_defensive=True)
            approvals = await approval_svc.list_approvals(m.investigation_id)
            for ap in approvals:
                if ap.status != ApprovalStatus.COMPLETED:
                    continue
                a = action_registry.get(ap.action_id)
                if a and a.is_defensive:
                    defensive_actions += 1

            # Snapshot pairs → improvements / regressions
            snaps = await posture_repo.list_for_investigation(m.investigation_id)
            post = [s for s in snaps if str(s.snapshot_kind) == "post_remediation"]
            post_snaps += len(post)
            if post:
                latest_post = max(post, key=lambda s: s.captured_at)
                # If there's a baseline earlier, summarise the improvement
                earlier = [s for s in snaps if s.captured_at < latest_post.captured_at]
                if earlier:
                    base = min(earlier, key=lambda s: s.captured_at)
                    cmp = compare_snapshots(base, latest_post)
                    if cmp.themes_resolved:
                        labels = ", ".join(t.label for t in cmp.themes_resolved[:3])
                        improvements.append(
                            f"{m.investigation_id[:8]}…: resolved {labels}"
                        )
                # Regression-check snapshots taken AFTER
                later = [s for s in snaps if s.captured_at > latest_post.captured_at]
                if later:
                    latest_later = max(later, key=lambda s: s.captured_at)
                    cmp = compare_snapshots(latest_post, latest_later)
                    for d in cmp.themes_regressed:
                        regressions.append(
                            f"{m.investigation_id[:8]}…: regression on '{d.label}'"
                        )

        snap.total_defensive_actions_completed = defensive_actions
        snap.total_post_remediation_snapshots = post_snaps
        snap.posture_improvement_summary = improvements[:8]
        snap.regression_alerts = regressions[:8]
        # Most-improved area: pick label that appears most across improvements
        if improvements:
            from collections import Counter
            labels = []
            for line in improvements:
                if ":" in line:
                    labels.extend(
                        x.strip() for x in line.split(":", 1)[1].split(",")
                    )
            if labels:
                snap.most_improved_area = Counter(labels).most_common(1)[0][0]

    async def _refresh_objectives(
        self, campaign_id: str, members: list[CampaignMembership]
    ) -> None:
        """Recompute objective + sub-objective statuses against current activity."""
        from apps.scanner_orchestration.storage.finding_repo import (
            NormalizedFindingRepository,
        )

        campaign = await self._campaign_repo.get_by_id(campaign_id)
        if not campaign or not campaign.objectives:
            return

        finding_repo = NormalizedFindingRepository(self._db)

        # Pull finding types across members ONCE. Phase 59a — milestones
        # removed; achieved_keys stays empty, which means objective
        # completion now resolves purely via finding-type signals (the
        # other completion path defined in campaigns/models/objective.py).
        achieved_keys: set[str] = set()
        finding_types_seen: set[str] = set()
        for m in members:
            for f in await finding_repo.list_for_investigation(m.investigation_id):
                finding_types_seen.add(f.finding_type)

        changed = False
        for obj in campaign.objectives:
            sub_statuses: list[ObjectiveStatus] = []
            for sub in obj.sub_objectives:
                hit = bool(set(sub.milestone_keys) & achieved_keys) or bool(
                    set(sub.finding_types) & finding_types_seen and not sub.milestone_keys
                )
                new_status = (
                    ObjectiveStatus.COMPLETED if hit
                    else (
                        ObjectiveStatus.IN_PROGRESS
                        if (set(sub.finding_types) & finding_types_seen)
                        else ObjectiveStatus.NOT_STARTED
                    )
                )
                if sub.status != new_status:
                    sub.status = new_status
                    changed = True
                sub_statuses.append(new_status)

            # Derive objective status: COMPLETED if all subs COMPLETED,
            # IN_PROGRESS if any sub is in_progress/completed, else NOT_STARTED.
            if sub_statuses and all(s == ObjectiveStatus.COMPLETED for s in sub_statuses):
                new_obj_status = ObjectiveStatus.COMPLETED
            elif any(s != ObjectiveStatus.NOT_STARTED for s in sub_statuses):
                new_obj_status = ObjectiveStatus.IN_PROGRESS
            else:
                new_obj_status = ObjectiveStatus.NOT_STARTED
            if obj.status != new_obj_status:
                obj.status = new_obj_status
                changed = True

        if changed:
            await self._campaign_repo.update(campaign)


def _build_strengths(snap: CampaignProgressSnapshot) -> list[str]:
    out: list[str] = []
    if snap.total_milestones >= 5:
        out.append(
            f"{snap.total_milestones} milestone(s) achieved across "
            f"{snap.total_investigations} investigation(s)"
        )
    if snap.aggregated_themes:
        labels = ", ".join(t.label for t in snap.aggregated_themes[:3])
        out.append(f"Recurring themes identified: {labels}")
    if snap.total_evidence_artifacts >= 10:
        out.append(
            f"Substantial evidence base — {snap.total_evidence_artifacts} artifact(s)"
        )
    return out


def _build_unresolved(snap: CampaignProgressSnapshot) -> list[str]:
    out: list[str] = []
    for gap in snap.common_remediation_gaps[:5]:
        out.append(
            f"Remediation gap: '{gap.concept}' surfaced in "
            f"{gap.surfaced_in_investigations} investigation(s), "
            f"documented in {gap.documented_in_investigations}"
        )
    if not snap.aggregated_themes and snap.total_findings >= 5:
        out.append(
            "No recurring themes yet — single-finding-oriented investigations; "
            "consider scoping a follow-up to pursue cross-investigation structure"
        )
    return out
