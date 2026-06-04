"""Snapshot dataclasses returned by CampaignService.progress_snapshot().

All values are derived at query time from existing tables — no new persistence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CampaignTimelineEvent:
    """One event in the campaign's chronological narrative.

    Sources are existing tables (timeline_events, milestones, exports). The
    event_type categories distinguish the operational meaning:

      investigation_joined | milestone | action_completed | evidence_captured
      | finding_critical | theme_emerged | knowledge_exported
    """
    timestamp: datetime
    event_type: str
    summary: str
    investigation_id: str | None = None
    investigation_title: str | None = None
    stage: str | None = None
    detail: dict = field(default_factory=dict)


@dataclass
class CampaignStageProgress:
    stage: str
    label: str
    investigation_count: int


@dataclass
class CampaignProgressSnapshot:
    """Computed cross-investigation summary for one campaign."""
    campaign_id: str
    computed_at: datetime

    total_investigations: int = 0
    total_milestones: int = 0
    total_actions_completed: int = 0
    total_evidence_artifacts: int = 0
    total_findings: int = 0

    investigations_by_stage: list[CampaignStageProgress] = field(default_factory=list)

    # Aggregated themes across all member investigations
    aggregated_themes: list = field(default_factory=list)
    # Concepts that recur but are rarely documented in evidence
    common_remediation_gaps: list = field(default_factory=list)
    # Human-readable strengths + reinforcement needs for the campaign
    strengths: list[str] = field(default_factory=list)
    unresolved_weaknesses: list[str] = field(default_factory=list)
    # Top-line narrative timeline
    timeline: list[CampaignTimelineEvent] = field(default_factory=list)

    # Phase 17 — defensive aggregates
    total_defensive_actions_completed: int = 0
    total_post_remediation_snapshots: int = 0
    posture_improvement_summary: list[str] = field(default_factory=list)
    regression_alerts: list[str] = field(default_factory=list)
    most_improved_area: str | None = None
