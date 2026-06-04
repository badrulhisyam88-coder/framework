"""FeedEntry and ActionLink — primitives for the guided investigation feed.

Not persisted. Built at query time from timeline events, findings, evidence,
and mastery records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ActionLink:
    """A clickable next-step suggestion attached to a feed entry."""
    kind: str           # "action" | "learn" | "evidence" | "tab" | "scan_profile"
    label: str          # Button text shown to the user
    target: str         # action_id / path_id / tab_name / profile_id
    icon: str = "→"
    primary: bool = False


@dataclass
class ObjectiveView:
    """One CTF objective with achievement state for rendering."""
    key: str
    text: str
    achieved: bool = False
    achieved_at: datetime | None = None


@dataclass
class ActionLifecycleView:
    """Lifecycle state of a guided action attached to a finding entry."""
    action_id: str
    state: str   # not_started | in_progress | evidence_captured | completed | abandoned
    label: str
    icon: str
    evidence_count: int = 0


@dataclass
class UnlockHint:
    """Next-step hint surfaced after a completion event."""
    narrative: str
    next_action_ids: list[str] = field(default_factory=list)
    next_milestone_keys: list[str] = field(default_factory=list)


@dataclass
class ReinforcementChipView:
    """Memory-driven chip placed next to a finding entry."""
    label: str
    tone: str       # ok | info | warn
    why: str


@dataclass
class CrossInvestigationLinkView:
    """Pointer to another investigation that shares the same theme."""
    investigation_id: str
    title: str
    matching_finding_count: int
    matching_finding_types: list[str] = field(default_factory=list)


@dataclass
class ThemeView:
    """Theme entry rendered in the feed."""
    theme_id: str
    label: str
    description: str
    confidence: str
    matching_finding_count: int
    matching_finding_types: list[str] = field(default_factory=list)
    remediation_concepts: list[str] = field(default_factory=list)
    remediation_documented: bool = False
    cross_links: list[CrossInvestigationLinkView] = field(default_factory=list)
    why: str = ""


@dataclass
class FeedEntry:
    """One chronological entry in the investigation feed.

    Rendered with one of a small set of layouts based on `kind`.
    """
    # Entry kind: scan | finding | evidence | skill | milestone
    #             | action_completed | action_started | unlock
    kind: str
    timestamp: datetime
    headline: str                               # Primary line ("Possible SQL injection identified")
    summary: str = ""                           # One-line context
    detail_paragraphs: list[str] = field(default_factory=list)  # 1–3 short paragraphs
    ctf_opportunity: str | None = None          # Legacy single-line opportunity callout
    ctf_objectives: list[str] = field(default_factory=list)     # Possible CTF/lab objectives (text)
    ctf_objective_views: list[ObjectiveView] = field(default_factory=list)  # With achievement state
    evidence_goals: list[str] = field(default_factory=list)     # What evidence to capture
    learning_concepts: list[str] = field(default_factory=list)  # Concepts exercised
    action_lifecycles: list[ActionLifecycleView] = field(default_factory=list)
    unlock_hint: UnlockHint | None = None       # Surface after completion/milestone events
    reinforcement_chips: list[ReinforcementChipView] = field(default_factory=list)
    insight_why: str = ""                       # For kind="insight": explainability trail
    theme: ThemeView | None = None              # For kind="theme": root-cause cluster info
    severity_class: str = "info"                # critical | high | medium | low | info | ok
    icon: str = "·"                             # Single-glyph icon for the entry
    actions: list[ActionLink] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)  # finding_type, scanner, etc.
