"""MemoryService — compute an InvestigationMemory snapshot from existing data.

Pure aggregation + deterministic heuristics. No new persistence. Every value
in the returned snapshot is traceable to a row in:
  - normalized_findings
  - guided_action_approvals
  - evidence_artifacts
  - skill_mastery

Phase 59a — `investigation_milestones` was a fifth source; removed.
Aggregates that derived from it (total_milestones_achieved,
repeated_milestone_keys, milestones_by_category) now always resolve
to 0 / empty.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime

import aiosqlite

from apps.investigation_core.evidence.storage.artifact_repo import ArtifactRepository
from apps.investigation_core.guided_actions.approvals.approval_service import (
    ApprovalService,
)
from apps.investigation_core.guided_actions.models.approval import ApprovalStatus
from apps.investigation_core.guided_actions.registry.action_registry import (
    action_registry,
)
from apps.investigation_core.memory.categories import (
    CATEGORY_LABELS,
    category_for_finding_type,
)
from apps.investigation_core.memory.models.memory import (
    ConceptReinforcement,
    InvestigationMemory,
)
from apps.investigation_core.memory.services.maturity_calculator import (
    compute_category_maturity,
)
from apps.investigation_core.memory.services.quality_scorer import (
    score_investigation_evidence,
)
from apps.investigation_core.progression.storage.mastery_repo import MasteryRepository
from apps.scanner_orchestration.storage.finding_repo import NormalizedFindingRepository

# A skill_id can carry hints about which category it belongs to.
_SKILL_PREFIX_TO_CATEGORY = {
    "sqli":      "sql_injection",
    "xss":       "xss",
    "auth":      "authentication",
    "hardening": "hardening",
    "tls":       "authentication",
    "recon":     "recon",
}


class MemoryService:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def snapshot(self, investigation_id: str) -> InvestigationMemory:
        finding_repo = NormalizedFindingRepository(self._db)
        approval_svc = ApprovalService(self._db)
        art_repo = ArtifactRepository(self._db)
        mastery_repo = MasteryRepository(self._db)

        # ── Raw data fetch ──────────────────────────────────────────────
        findings = await finding_repo.list_for_investigation(investigation_id)
        approvals = await approval_svc.list_approvals(investigation_id)
        # Phase 59a — milestone subsystem removed. Treat as empty so all
        # downstream aggregations resolve to 0 / empty cleanly.
        milestones: list = []
        artifacts = await art_repo.list_for_investigation(investigation_id)
        mastery = await mastery_repo.list_for_investigation(investigation_id)

        # ── Bucket by category ──────────────────────────────────────────
        # 1. Findings → category counts
        findings_by_category: dict[str, int] = {}
        finding_id_to_category: dict[str, str] = {}
        finding_id_to_type: dict[str, str] = {}
        for f in findings:
            cat = category_for_finding_type(f.finding_type)
            findings_by_category[cat] = findings_by_category.get(cat, 0) + 1
            finding_id_to_category[f.finding_id] = cat
            finding_id_to_type[f.finding_id] = f.finding_type

        # 2. Actions: completed/abandoned by category
        actions_completed_by_cat: dict[str, int] = {}
        actions_abandoned_by_cat: dict[str, int] = {}
        for a in approvals:
            action = action_registry.get(a.action_id)
            if not action:
                continue
            primary_ft = action.finding_type
            cat = category_for_finding_type(primary_ft)
            if a.status == ApprovalStatus.COMPLETED:
                actions_completed_by_cat[cat] = actions_completed_by_cat.get(cat, 0) + 1
            elif a.status == ApprovalStatus.REJECTED:
                actions_abandoned_by_cat[cat] = actions_abandoned_by_cat.get(cat, 0) + 1

        # 3. Milestones by category (use finding_type if set, else parse key)
        milestones_by_cat: dict[str, int] = {}
        repeated_milestone_keys: Counter = Counter()
        for m in milestones:
            if str(m.status) != "achieved":
                continue
            if m.finding_type:
                cat = category_for_finding_type(m.finding_type)
            else:
                # objective_key like "sqli:auth_bypass" — take the prefix
                prefix = m.objective_key.split(":", 1)[0] if ":" in m.objective_key else ""
                cat = category_for_finding_type(prefix) if prefix else "other"
            milestones_by_cat[cat] = milestones_by_cat.get(cat, 0) + 1
            repeated_milestone_keys[m.objective_key] += 1

        # 4. Evidence by category (via finding linkage where present)
        evidence_by_cat: dict[str, int] = {}
        for art in artifacts:
            cat = "other"
            if art.finding_id and art.finding_id in finding_id_to_category:
                cat = finding_id_to_category[art.finding_id]
            evidence_by_cat[cat] = evidence_by_cat.get(cat, 0) + 1

        # 5. Skills by category (via skill_id prefix)
        skills_completed_by_cat: dict[str, int] = {}
        skills_in_progress_by_cat: dict[str, int] = {}
        for sm in mastery:
            cat = _skill_category(sm.skill_id)
            if str(sm.status) in ("completed", "mastered"):
                skills_completed_by_cat[cat] = skills_completed_by_cat.get(cat, 0) + 1
            elif str(sm.status) == "in_progress":
                skills_in_progress_by_cat[cat] = skills_in_progress_by_cat.get(cat, 0) + 1

        # ── Maturity per category ───────────────────────────────────────
        all_categories = set(findings_by_category.keys())
        all_categories.update(milestones_by_cat.keys())
        all_categories.update(actions_completed_by_cat.keys())
        all_categories.update(skills_completed_by_cat.keys())
        all_categories.update(skills_in_progress_by_cat.keys())
        # Filter out 'other' if it has no signal
        if "other" in all_categories and not any(
            v.get("other", 0) for v in [
                findings_by_category, milestones_by_cat,
                actions_completed_by_cat, skills_completed_by_cat,
            ]
        ):
            all_categories.discard("other")

        maturity_by_category = {}
        for cat in sorted(all_categories):
            if cat not in CATEGORY_LABELS and cat != "other":
                continue
            maturity_by_category[cat] = compute_category_maturity(
                cat,
                findings_count=findings_by_category.get(cat, 0),
                milestones_achieved=milestones_by_cat.get(cat, 0),
                actions_completed=actions_completed_by_cat.get(cat, 0),
                actions_abandoned=actions_abandoned_by_cat.get(cat, 0),
                skills_in_progress=skills_in_progress_by_cat.get(cat, 0),
                skills_completed=skills_completed_by_cat.get(cat, 0),
                evidence_count=evidence_by_cat.get(cat, 0),
            )

        # ── Evidence quality snapshot ───────────────────────────────────
        evidence_quality = score_investigation_evidence(artifacts)

        # ── Concept reinforcement ───────────────────────────────────────
        concept_reinforcement = _compute_concept_reinforcement(
            findings_by_type=Counter(f.finding_type for f in findings),
            completed_actions={a.action_id for a in approvals
                               if a.status == ApprovalStatus.COMPLETED},
            achieved_milestone_keys={m.objective_key for m in milestones
                                     if str(m.status) == "achieved"},
        )

        # ── Incomplete-objective patterns ───────────────────────────────
        incomplete_objectives = _compute_incomplete_objectives(
            findings_by_type=Counter(f.finding_type for f in findings),
            achieved_milestone_keys={m.objective_key for m in milestones
                                     if str(m.status) == "achieved"},
        )

        # ── Aggregate counts + strengths/gaps ───────────────────────────
        total_milestones = sum(milestones_by_cat.values())
        total_completed = sum(actions_completed_by_cat.values())
        total_abandoned = sum(actions_abandoned_by_cat.values())

        strengths = _build_strengths(maturity_by_category, evidence_quality)
        needs_reinforcement = _build_reinforcement(
            maturity_by_category,
            evidence_quality,
            concept_reinforcement,
            actions_abandoned_by_cat,
        )

        # ── Theme identification (Phase 15) ─────────────────────────────
        from apps.investigation_core.intelligence.clusters import (
            CLUSTER_TO_DEFENSIVE_ACTIONS,
        )
        from apps.investigation_core.intelligence.engine import themes_for_findings
        active_themes = themes_for_findings(findings, evidence=artifacts)
        undocumented_themes = [
            t.label for t in active_themes
            if not t.remediation_documented and t.confidence != "emerging"
        ]
        # Surface the gap into the needs_reinforcement list so the maturity banner
        # carries it without additional template wiring.
        for label in undocumented_themes:
            needs_reinforcement.append(
                f"Theme '{label}' active — no remediation evidence documented yet"
            )

        # ── Defensive maturity (Phase 17) ───────────────────────────────
        defensive_maturity, posture_snapshots, regression_alerts = (
            await _compute_defensive_maturity(
                self._db,
                investigation_id=investigation_id,
                active_themes=active_themes,
                approvals=approvals,
                artifacts=artifacts,
                cluster_defensive_map=CLUSTER_TO_DEFENSIVE_ACTIONS,
                category_by_cluster={
                    "weak_hardening_posture":   "hardening",
                    "unsafe_input_handling":    "sql_injection",
                    "weak_authentication":      "authentication",
                    "excessive_disclosure":     "hardening",
                    "insecure_legacy_services": "authentication",
                },
            )
        )
        for alert in regression_alerts:
            needs_reinforcement.append(alert)

        return InvestigationMemory(
            investigation_id=investigation_id,
            computed_at=datetime.utcnow(),
            maturity_by_category=maturity_by_category,
            evidence_quality=evidence_quality,
            concept_reinforcement=concept_reinforcement,
            total_milestones_achieved=total_milestones,
            total_actions_completed=total_completed,
            total_actions_abandoned=total_abandoned,
            total_evidence_artifacts=len(artifacts),
            total_findings=len(findings),
            repeated_milestone_keys={
                k: v for k, v in repeated_milestone_keys.items() if v >= 2
            },
            incomplete_objectives=incomplete_objectives,
            strengths=strengths,
            needs_reinforcement=needs_reinforcement,
            active_themes=active_themes,
            undocumented_themes=undocumented_themes,
            defensive_maturity_by_category=defensive_maturity,
            posture_snapshots=posture_snapshots,
            regression_alerts=regression_alerts,
        )


def _skill_category(skill_id: str) -> str:
    """Map a skill_id (e.g. 'sqli_auth_bypass') to a category by prefix."""
    for prefix, cat in _SKILL_PREFIX_TO_CATEGORY.items():
        if skill_id.startswith(prefix):
            return cat
    return "other"


def _compute_concept_reinforcement(
    *,
    findings_by_type: Counter,
    completed_actions: set[str],
    achieved_milestone_keys: set[str],
) -> list[ConceptReinforcement]:
    """Lazy-import interpretations to identify concepts per finding type."""
    from apps.investigation_workspace.feed.interpretations import interpret

    # Build per-concept aggregation
    concept_seen: Counter = Counter()
    concept_finding_types: dict[str, set[str]] = {}
    concept_practiced: Counter = Counter()
    for ft, ft_count in findings_by_type.items():
        interp = interpret(ft)
        concepts = list(interp.get("learning_concepts") or [])  # type: ignore[arg-type]
        actions = list(interp.get("actions") or [])             # type: ignore[arg-type]
        obj_keys = list(interp.get("ctf_objective_keys") or [])  # type: ignore[arg-type]
        # Practised = any related action completed OR any objective achieved
        practiced = (
            any(a in completed_actions for a in actions)
            or any(k in achieved_milestone_keys for k in obj_keys)
        )
        for c in concepts:
            concept_seen[c] += ft_count
            concept_finding_types.setdefault(c, set()).add(ft)
            if practiced:
                concept_practiced[c] += 1

    out: list[ConceptReinforcement] = []
    for concept, seen_count in concept_seen.most_common():
        practiced_count = concept_practiced.get(concept, 0)
        # Needs reinforcement = seen >= 2 times across findings but never practised,
        # OR practised once but seen many more times (under-practised concept).
        needs = (practiced_count == 0 and seen_count >= 1) or (
            seen_count >= 3 and practiced_count < seen_count // 2
        )
        out.append(ConceptReinforcement(
            concept=concept,
            finding_types=sorted(concept_finding_types.get(concept, set())),
            seen_count=seen_count,
            practiced_count=practiced_count,
            needs_reinforcement=needs,
        ))
    return out


def _compute_incomplete_objectives(
    *,
    findings_by_type: Counter,
    achieved_milestone_keys: set[str],
) -> list[str]:
    """Return objective TEXTS that appear in multiple findings yet were never achieved."""
    from apps.investigation_workspace.feed.interpretations import interpret

    objective_count: Counter = Counter()
    objective_to_text: dict[str, str] = {}
    for ft, ft_count in findings_by_type.items():
        interp = interpret(ft)
        objs = list(interp.get("ctf_objectives") or [])          # type: ignore[arg-type]
        keys = list(interp.get("ctf_objective_keys") or [])      # type: ignore[arg-type]
        for text, key in zip(objs, keys, strict=False):
            objective_count[key] += ft_count
            objective_to_text[key] = text
    out: list[str] = []
    for key, count in objective_count.most_common():
        if count >= 2 and key not in achieved_milestone_keys:
            out.append(objective_to_text[key])
    return out[:8]   # Cap


def _build_strengths(
    maturity_by_category: dict,
    evidence_quality,
) -> list[str]:
    out: list[str] = []
    for mat in maturity_by_category.values():
        if str(mat.level) == "advanced":
            out.append(f"{mat.label} — advanced demonstrated activity")
        elif str(mat.level) == "intermediate":
            out.append(f"{mat.label} — intermediate progression")
    if evidence_quality.overall_score >= 75 and evidence_quality.total_artifacts > 0:
        out.append(
            f"Evidence quality strong ({evidence_quality.overall_score}/100, "
            f"{evidence_quality.type_diversity} type(s))"
        )
    return out


def _build_reinforcement(
    maturity_by_category: dict,
    evidence_quality,
    concept_reinforcement: list[ConceptReinforcement],
    actions_abandoned_by_cat: dict[str, int],
) -> list[str]:
    out: list[str] = []
    # Categories with findings but no activity
    for _cat, mat in maturity_by_category.items():
        if str(mat.level) == "exposure_only" and mat.findings_count > 0:
            out.append(
                f"{mat.label} — {mat.findings_count} finding(s) surfaced, "
                "no investigation activity yet"
            )
    # Evidence-quality gap
    if evidence_quality.total_artifacts > 0 and evidence_quality.overall_score < 50:
        out.append(
            f"Evidence quality thin ({evidence_quality.overall_score}/100) — "
            "improve linkage and detail"
        )
    # Repeated abandons
    for cat, count in actions_abandoned_by_cat.items():
        if count >= 2:
            label = CATEGORY_LABELS.get(cat, cat)
            out.append(f"{label} — {count} action(s) abandoned, revisit approach")
    # Concepts needing reinforcement (top 3)
    needing = [c for c in concept_reinforcement if c.needs_reinforcement][:3]
    for c in needing:
        out.append(
            f"Concept needs reinforcement: {c.concept} "
            f"(seen {c.seen_count}×, practised {c.practiced_count}×)"
        )
    return out


# ── Phase 17 — defensive maturity helper ─────────────────────────────────────


async def _compute_defensive_maturity(
    db,
    *,
    investigation_id: str,
    active_themes,
    approvals,
    artifacts,
    cluster_defensive_map: dict,
    category_by_cluster: dict,
):
    """Compute per-category defensive maturity + posture snapshot history.

    Returns (maturity_dict, posture_snapshots_dicts, regression_alerts).
    """
    from apps.investigation_core.defensive.services.maturity_calculator import (
        compute_defensive_maturity,
    )
    from apps.investigation_core.defensive.services.posture_service import (
        compare_snapshots,
    )
    from apps.investigation_core.defensive.storage.posture_repo import (
        PostureRepository,
    )
    from apps.investigation_core.guided_actions.models.approval import ApprovalStatus
    from apps.investigation_core.guided_actions.registry.action_registry import (
        action_registry,
    )

    # Defensive actions completed, grouped by category
    completed_defensive_by_cat: dict[str, int] = {}
    for ap in approvals:
        if ap.status != ApprovalStatus.COMPLETED:
            continue
        action = action_registry.get(ap.action_id)
        if not action or not action.is_defensive:
            continue
        # Map action → category via its declared finding_type → cluster
        for cluster_id, def_aids in cluster_defensive_map.items():
            if ap.action_id in def_aids:
                cat = category_by_cluster.get(cluster_id, "other")
                completed_defensive_by_cat[cat] = (
                    completed_defensive_by_cat.get(cat, 0) + 1
                )

    # Remediation-tagged evidence
    remediation_ev_by_cat: dict[str, int] = {}
    for art in artifacts:
        is_remediation = any(
            t in ("remediation", "verification", "post_remediation")
            for t in (art.tags or [])
        )
        if not is_remediation:
            continue
        # Categorise via metadata or finding linkage (simple heuristic: 'other')
        cat = (art.metadata or {}).get("category", "other") if art.metadata else "other"
        remediation_ev_by_cat[cat] = remediation_ev_by_cat.get(cat, 0) + 1

    # Posture snapshots (per category not tracked; we count post_remediation overall)
    posture_repo = PostureRepository(db)
    snaps = await posture_repo.list_for_investigation(investigation_id)
    post_remediation_count = sum(
        1 for s in snaps if str(s.snapshot_kind) in ("post_remediation", "regression_check")
    )

    # Documented remediation concepts per cluster → category
    documented_by_cat: dict[str, int] = {}
    for theme in active_themes:
        if not theme.remediation_documented:
            continue
        cat = category_by_cluster.get(theme.theme_id, "other")
        documented_by_cat[cat] = documented_by_cat.get(cat, 0) + 1

    # Build per-category defensive maturity for categories with any signal
    relevant_cats = (
        set(completed_defensive_by_cat)
        | set(remediation_ev_by_cat)
        | set(documented_by_cat)
    )
    defensive_maturity: dict = {}
    for cat in sorted(relevant_cats):
        defensive_maturity[cat] = compute_defensive_maturity(
            cat,
            documented_remediation_concepts=documented_by_cat.get(cat, 0),
            completed_defensive_actions=completed_defensive_by_cat.get(cat, 0),
            remediation_evidence_count=remediation_ev_by_cat.get(cat, 0),
            post_remediation_snapshots=post_remediation_count if cat in documented_by_cat else 0,
        )

    # Posture snapshot summary for rendering (lightweight dict view)
    posture_views = [
        {
            "snapshot_id":     s.snapshot_id,
            "label":           s.label,
            "snapshot_kind":   str(s.snapshot_kind),
            "captured_at":     s.captured_at,
            "findings_count":  s.findings_count,
            "themes":          s.active_themes,
            "evidence_quality_score": s.evidence_quality_score,
        }
        for s in snaps
    ]

    # Regression alerts — auto-compute by comparing the most recent
    # POST_REMEDIATION snapshot against the latest AD_HOC / BASELINE if newer
    regression_alerts: list[str] = []
    post_snaps = [s for s in snaps if str(s.snapshot_kind) == "post_remediation"]
    later_snaps = [
        s for s in snaps if str(s.snapshot_kind) in (
            "ad_hoc", "regression_check", "baseline"
        )
    ]
    if post_snaps and later_snaps:
        latest_post = max(post_snaps, key=lambda s: s.captured_at)
        candidates = [s for s in later_snaps if s.captured_at > latest_post.captured_at]
        if candidates:
            latest_later = max(candidates, key=lambda s: s.captured_at)
            cmp = compare_snapshots(latest_post, latest_later)
            for delta in cmp.themes_regressed:
                regression_alerts.append(
                    f"Regression: theme '{delta.label}' reappeared "
                    f"({delta.after_finding_count} finding(s)) after "
                    f"post-remediation snapshot '{latest_post.label}'"
                )

    return defensive_maturity, posture_views, regression_alerts
