"""FeedBuilder — assemble a chronological investigation feed.

Aggregates from:
  - apps/scanner_orchestration/  (runs, findings)
  - apps/investigation_core/     (timeline, evidence, mastery)
  - apps/investigation_core/guided_actions/registry  (action templates)
  - apps/investigation_core/learning/path_registry   (learning paths)

Produces a list[FeedEntry] sorted most-recent-first.

Phase 13 additions:
  - Action lifecycle badges on each finding entry's guided actions
  - Dedicated entries for GUIDED_ACTION_COMPLETED and EVIDENCE_CAPTURED
    so the timeline tells a progression story
  - UnlockHint attached to completion events (next steps)

Phase 59a — milestone-derived entries and per-objective achievement
state removed alongside the milestone subsystem.
"""

from __future__ import annotations

import aiosqlite

from apps.investigation_workspace.adaptive.guidance import (
    adapt_unlock_hint,
    reinforcement_chips_for_finding,
)
from apps.investigation_workspace.adaptive.insights import generate_insights
from apps.investigation_workspace.feed.interpretations import interpret
from apps.investigation_workspace.feed.lifecycle import derive_lifecycle
from apps.investigation_workspace.feed.models import (
    ActionLifecycleView,
    ActionLink,
    CrossInvestigationLinkView,
    FeedEntry,
    ObjectiveView,
    ReinforcementChipView,
    ThemeView,
    UnlockHint,
)
from apps.investigation_workspace.feed.unlock_rules import (
    unlocks_for_action_completed,
)

# Timeline event types we surface in the feed (and how).
_SCAN_LIFECYCLE_EVENTS = {
    "scan_queued":          ("●", "info",     "Scan queued"),
    "target_reachable":     ("✓", "ok",       "Target confirmed reachable"),
    "target_fingerprinted": ("◉", "info",     "Service identified"),
    "target_unreachable":   ("✗", "critical", "Target unreachable"),
    "scan_started":         ("▶", "info",     "Investigation running"),
    "scan_completed":       ("✓", "ok",       "Scan complete"),
    "scan_failed":          ("✗", "critical", "Scan failed"),
}


class FeedBuilder:
    """Builds the investigation feed by querying read-only data from each context."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def build(self, investigation_id: str, limit: int = 60) -> list[FeedEntry]:
        from apps.investigation_core.evidence.storage.artifact_repo import ArtifactRepository
        from apps.investigation_core.guided_actions.approvals.approval_service import (
            ApprovalService,
        )
        from apps.investigation_core.guided_actions.registry.action_registry import (
            action_registry,
        )
        from apps.investigation_core.learning.path_registry import registry as path_registry
        from apps.investigation_core.memory.services.memory_service import MemoryService
        from apps.investigation_core.progression.storage.mastery_repo import MasteryRepository
        from apps.investigation_core.storage.timeline_repo import TimelineRepository
        from apps.scanner_orchestration.services.orchestration_service import (
            OrchestrationService,
        )

        entries: list[FeedEntry] = []

        # ── Memory snapshot — drives adaptive behaviour throughout ─────
        memory_svc = MemoryService(self._db)
        memory = await memory_svc.snapshot(investigation_id)

        # ── Preload supporting data once ─────────────────────────────────
        approval_svc = ApprovalService(self._db)
        approvals = await approval_svc.list_approvals(investigation_id)
        approval_by_action: dict[str, list] = {}
        for a in approvals:
            approval_by_action.setdefault(a.action_id, []).append(a)
        # Most-recent first → take index 0 later
        for lst in approval_by_action.values():
            lst.sort(key=lambda x: x.requested_at, reverse=True)

        art_repo = ArtifactRepository(self._db)
        all_artifacts = await art_repo.list_for_investigation(investigation_id)
        artifacts_by_action: dict[str, list] = {}
        artifacts_by_finding: dict[str, list] = {}
        for a in all_artifacts:
            if a.guided_action_id:
                artifacts_by_action.setdefault(a.guided_action_id, []).append(a)
            if a.finding_id:
                artifacts_by_finding.setdefault(a.finding_id, []).append(a)

        # Phase 59a — milestone subsystem removed. Empty maps preserved
        # here for downstream code that still pattern-matches on these
        # names (they remain dict-shaped, just always empty).
        milestones_by_key: dict[str, list] = {}
        milestones_by_finding: dict[str, list] = {}

        # ── Timeline events ──────────────────────────────────────────────
        tl_repo = TimelineRepository(self._db)
        all_events = await tl_repo.list_for_investigation(investigation_id, limit=300)

        # Scan-lifecycle events (the existing quiet surface)
        for ev in all_events:
            et = str(ev.event_type)
            if et not in _SCAN_LIFECYCLE_EVENTS:
                continue
            icon, sev, default_headline = _SCAN_LIFECYCLE_EVENTS[et]
            d = ev.detail or {}

            summary = ""
            if et == "target_fingerprinted":
                fp = d.get("fingerprint", "")
                summary = f"Identified as {fp}" if fp else ""
            elif et == "target_reachable":
                fp = d.get("fingerprint")
                lat = d.get("latency_ms")
                bits = []
                if fp:
                    bits.append(fp)
                if lat:
                    bits.append(f"{int(lat)}ms latency")
                summary = " · ".join(bits)
            elif et == "scan_completed":
                count = d.get("findings_count", 0)
                dur = d.get("duration_seconds", 0) or 0
                summary = f"{count} finding(s) in {dur:.0f}s"
            elif et == "scan_failed":
                err = d.get("error", "")
                summary = str(err)[:100] if err else "Scan execution failed"
            elif et == "target_unreachable":
                summary = "Could not reach target — check network/firewall"

            entries.append(FeedEntry(
                kind="scan",
                timestamp=ev.timestamp,
                headline=default_headline,
                summary=summary,
                severity_class=sev,
                icon=icon,
                meta={"event_type": et, "scan_id": d.get("scan_id")},
            ))

        # Investigation-progression events — the story of what the user did
        for ev in all_events:
            et = str(ev.event_type)
            d = ev.detail or {}
            if et == "action_started":
                aid = d.get("action_id", "")
                action = action_registry.get(aid)
                title = action.title if action else aid
                entries.append(FeedEntry(
                    kind="action_started",
                    timestamp=ev.timestamp,
                    headline=f"Investigation step started: {title}",
                    summary="Approved; guidance unlocked. Capture evidence as you go.",
                    severity_class="info",
                    icon="▶",
                    meta={"action_id": aid, "finding_id": d.get("finding_id")},
                ))
            elif et == "guided_action_completed":
                aid = d.get("action_id", "")
                action = action_registry.get(aid)
                title = action.title if action else aid
                refs = d.get("evidence_refs", []) or []
                ev_summary = (
                    f"Linked {len(refs)} evidence artifact(s)"
                    if refs else "Marked complete"
                )
                hint = None
                rule = unlocks_for_action_completed(aid)
                if rule:
                    hint = UnlockHint(
                        narrative=str(rule.get("narrative", "")),
                        next_action_ids=list(rule.get("next_actions") or []),  # type: ignore[arg-type]
                        next_milestone_keys=[],   # Phase 59a — milestones removed
                    )
                # Adapt the hint using memory — primary finding_type of the action
                ft = action.finding_type if action else None
                hint = adapt_unlock_hint(hint, memory, finding_type=ft)
                entries.append(FeedEntry(
                    kind="action_completed",
                    timestamp=ev.timestamp,
                    headline=f"Investigation step completed: {title}",
                    summary=ev_summary,
                    severity_class="ok",
                    icon="✓",
                    unlock_hint=hint,
                    meta={"action_id": aid},
                ))
            elif et == "evidence_captured":
                ev_title = ev.summary or "Evidence captured"
                aid = d.get("guided_action_id")
                action_title = ""
                if aid:
                    action = action_registry.get(aid)
                    if action:
                        action_title = action.title
                summary = f"For step: {action_title}" if action_title else ""
                entries.append(FeedEntry(
                    kind="evidence",
                    timestamp=ev.timestamp,
                    headline=ev_title,
                    summary=summary,
                    severity_class="ok",
                    icon="⬡",
                    meta={
                        "evidence_id": d.get("evidence_id"),
                        "action_id": aid,
                        "finding_id": d.get("finding_id"),
                    },
                ))

        # ── Findings (the main investigation content) ─────────────────────
        orch_svc = OrchestrationService(self._db)
        all_findings = await orch_svc.list_all_findings(investigation_id)

        for f in all_findings:
            interp = interpret(f.finding_type)

            # Build inline action links from the interpretation + skill graph
            actions: list[ActionLink] = []
            action_lifecycle_views: list[ActionLifecycleView] = []

            # Suggested guided actions for this finding type
            seen_action_ids: set[str] = set()
            for aid in (interp.get("actions") or []):  # type: ignore[union-attr]
                if aid in seen_action_ids:
                    continue
                action = action_registry.get(aid)
                if action:
                    actions.append(ActionLink(
                        kind="action",
                        label=f"▶ {action.title}",
                        target=aid,
                        primary=True,
                    ))
                    seen_action_ids.add(aid)
                    # Lifecycle derivation
                    apr = (approval_by_action.get(aid) or [None])[0]
                    action_evidence = artifacts_by_action.get(aid, [])
                    lc = derive_lifecycle(apr, action_evidence)
                    action_lifecycle_views.append(ActionLifecycleView(
                        action_id=aid,
                        state=lc.state,
                        label=lc.label,
                        icon=lc.icon,
                        evidence_count=lc.evidence_count,
                    ))

            # Learning path link
            lp_id = interp.get("learning_path") or (
                f.related_learning_paths[0] if f.related_learning_paths else None
            )
            if lp_id:
                path = path_registry.get(lp_id)
                if path:
                    actions.append(ActionLink(
                        kind="learn",
                        label=f"◉ Learn — {path.title}",
                        target=lp_id,
                    ))

            # ── Concrete waypoints for EVERY finding ─────────────────────
            if f.endpoint or f.port:
                base = f.target or ""
                if "://" not in base and base:
                    base = "http://" + base
                inspect_url = base
                if f.endpoint and f.endpoint.startswith("/"):
                    from urllib.parse import urlparse
                    parsed = urlparse(base)
                    inspect_url = f"{parsed.scheme}://{parsed.netloc}{f.endpoint}"
                elif f.endpoint:
                    inspect_url = f.endpoint
                actions.append(ActionLink(
                    kind="external",
                    label="🔍 Inspect endpoint",
                    target=inspect_url,
                ))

            # Web-scan suggestion for recon/exposure findings
            if f.finding_type in ("open_port_detected", "http_service_detected",
                                   "service_banner_disclosed", "http_only_site",
                                   "security_misconfiguration", "information_disclosure"):
                if f.port in (80, 443, 3000, 5000, 8000, 8080, 8443, 10000) or f.endpoint:
                    actions.append(ActionLink(
                        kind="scan_profile",
                        label="▶ Run Web Vulnerability Scan",
                        target="web_learning_scan",
                    ))

            # Document evidence (HTMX inline form)
            actions.append(ActionLink(
                kind="capture_evidence_form",
                label="⬡ Capture evidence",
                target=f.finding_id,
                primary=False,
            ))

            # Compose detail paragraphs
            detail_paragraphs: list[str] = []
            meaning = interp.get("meaning")
            if meaning:
                detail_paragraphs.append(str(meaning))
            if f.description:
                detail_paragraphs.append(f.description[:280])

            base_headline = str(interp.get("headline", "Finding identified"))
            location_bits = []
            if f.port:
                location_bits.append(f"port {f.port}")
            if f.endpoint:
                location_bits.append(f.endpoint[:60])
            location = " · ".join(location_bits)
            headline = f"{base_headline} — {location}" if location else base_headline

            # CTF objective views — with achievement state from milestones
            objs_text = list(interp.get("ctf_objectives") or [])  # type: ignore[arg-type]
            obj_keys = list(interp.get("ctf_objective_keys") or [])  # type: ignore[arg-type]
            achieved_keys_for_finding: set[str] = {
                m.objective_key
                for m in milestones_by_finding.get(f.finding_id, [])
                if str(m.status) == "achieved"
            }
            # Also count global achievements for this objective key
            globally_achieved: set[str] = {
                key for key, mlist in milestones_by_key.items()
                if any(str(mm.status) == "achieved" for mm in mlist)
            }
            obj_views: list[ObjectiveView] = []
            for text, key in zip(objs_text, obj_keys, strict=False):
                obj_views.append(ObjectiveView(
                    key=key,
                    text=text,
                    achieved=(key in achieved_keys_for_finding) or (key in globally_achieved),
                ))

            evidence_goals = list(interp.get("evidence_goals") or [])  # type: ignore[arg-type]
            learning_concepts = list(interp.get("learning_concepts") or [])  # type: ignore[arg-type]

            # Memory-driven reinforcement chips
            chips = reinforcement_chips_for_finding(f.finding_type, memory)
            chip_views = [
                ReinforcementChipView(label=c.label, tone=c.tone, why=c.why)
                for c in chips
            ]

            entries.append(FeedEntry(
                kind="finding",
                timestamp=f.created_at,
                headline=headline,
                summary=f.title,
                detail_paragraphs=detail_paragraphs,
                ctf_opportunity=interp.get("ctf_opportunity"),  # type: ignore[arg-type]
                ctf_objectives=objs_text,
                ctf_objective_views=obj_views,
                evidence_goals=evidence_goals,
                learning_concepts=learning_concepts,
                action_lifecycles=action_lifecycle_views,
                reinforcement_chips=chip_views,
                severity_class=f.severity or "info",
                icon=_severity_icon(f.severity),
                actions=actions,
                meta={
                    "finding_id":   f.finding_id,
                    "finding_type": f.finding_type,
                    "source":       f.source_scanner,
                },
            ))

        # ── Skill progression milestones ─────────────────────────────────
        mastery_repo = MasteryRepository(self._db)
        mastery = await mastery_repo.list_for_investigation(investigation_id)
        for m in mastery:
            if str(m.status) not in ("in_progress", "completed", "mastered"):
                continue
            ts = m.validated_at or m.started_at or m.created_at
            label = m.skill_id.replace("_", " ").title()
            if str(m.status) == "mastered":
                icon, sev = "★", "ok"
                headline = f"Skill mastered: {label}"
            elif str(m.status) == "completed":
                icon, sev = "✓", "ok"
                headline = f"Skill completed: {label}"
            else:
                icon, sev = "●", "info"
                headline = f"Skill in progress: {label}"
            conf_pct = int(m.confidence_score * 100) if m.confidence_score else 0
            summary = f"Confidence: {conf_pct}%" if conf_pct else ""
            entries.append(FeedEntry(
                kind="skill",
                timestamp=ts,
                headline=headline,
                summary=summary,
                severity_class=sev,
                icon=icon,
                meta={"skill_id": m.skill_id, "status": str(m.status)},
            ))

        # ── Adaptive insight entries ─────────────────────────────────────
        # These are emitted with the memory's computed_at timestamp so they
        # naturally appear at the very top of the most-recent-first feed.
        insights = generate_insights(memory)
        for ins in insights:
            entries.append(FeedEntry(
                kind="insight",
                timestamp=memory.computed_at,
                headline=ins.headline,
                summary=ins.summary,
                severity_class=ins.severity,
                icon=_insight_icon(ins.kind),
                insight_why=ins.why,
                meta={"insight_kind": ins.kind},
            ))

        # ── Root-cause theme entries (Phase 15) ──────────────────────────
        from datetime import timedelta as _td

        from apps.investigation_core.intelligence.clusters import CLUSTERS
        from apps.investigation_core.intelligence.engine import (
            cross_investigation_links,
            themes_for_findings,
        )

        themes = themes_for_findings(all_findings, evidence=all_artifacts)
        # Slight offset so themes sort just below insights but above findings
        theme_ts = memory.computed_at - _td(microseconds=1)
        for theme in themes:
            cluster = CLUSTERS[theme.theme_id]
            try:
                links = await cross_investigation_links(
                    self._db, cluster, exclude_investigation_id=investigation_id,
                )
            except Exception:
                links = []
            link_views = [
                CrossInvestigationLinkView(
                    investigation_id=cl.investigation_id,
                    title=cl.title,
                    matching_finding_count=cl.matching_finding_count,
                    matching_finding_types=cl.matching_finding_types,
                )
                for cl in links
            ]
            theme_view = ThemeView(
                theme_id=theme.theme_id,
                label=theme.label,
                description=theme.description,
                confidence=theme.confidence,
                matching_finding_count=theme.matching_finding_count,
                matching_finding_types=theme.matching_finding_types,
                remediation_concepts=theme.remediation_concepts,
                remediation_documented=theme.remediation_documented,
                cross_links=link_views,
                why=theme.why,
            )
            headline = f"Theme: {theme.label}"
            summary = (
                f"{theme.matching_finding_count} finding(s) — "
                f"confidence {theme.confidence}"
            )
            if not theme.remediation_documented:
                summary += " · remediation not yet documented"
            entries.append(FeedEntry(
                kind="theme",
                timestamp=theme_ts,
                headline=headline,
                summary=summary,
                severity_class={
                    "strong":      "ok",
                    "established": "info",
                    "emerging":    "info",
                }.get(theme.confidence, "info"),
                icon="◈",
                theme=theme_view,
                meta={"theme_id": theme.theme_id},
            ))

        # Sort newest-first and cap
        entries.sort(key=lambda e: e.timestamp, reverse=True)
        return entries[:limit]


def _severity_icon(sev: str | None) -> str:
    return {
        "critical": "⚠",
        "high":     "⚠",
        "medium":   "◆",
        "low":      "◇",
        "info":     "·",
    }.get(sev or "info", "·")


def _insight_icon(kind: str) -> str:
    return {
        "maturity":         "✦",
        "evidence_quality": "⬡",
        "reinforcement":    "↺",
        "remediation":      "⛨",
    }.get(kind, "✦")
