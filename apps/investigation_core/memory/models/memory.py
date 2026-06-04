"""Investigation memory model — the structured summary of demonstrated activity.

All fields are derived from existing persistence (milestones, approvals,
evidence, mastery). Memory is computed on demand; no opaque cache.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from apps.investigation_core.memory.models.evidence_quality import (
    EvidenceQualitySnapshot,
)


class MaturityLevel(StrEnum):
    EXPOSURE_ONLY = "exposure_only"   # Findings present, no activity yet
    BEGINNER      = "beginner"
    INTERMEDIATE  = "intermediate"
    ADVANCED      = "advanced"


MATURITY_LABELS: dict[str, str] = {
    MaturityLevel.EXPOSURE_ONLY: "Exposure only",
    MaturityLevel.BEGINNER:      "Beginner",
    MaturityLevel.INTERMEDIATE:  "Intermediate",
    MaturityLevel.ADVANCED:      "Advanced",
}


@dataclass
class CategoryMaturity:
    """Per-category maturity assessment with explicit reasoning."""
    category: str                       # CATEGORY_MAP value
    label: str                          # Human-readable label
    level: MaturityLevel
    findings_count: int = 0
    milestones_achieved: int = 0
    actions_completed: int = 0
    actions_abandoned: int = 0
    skills_in_progress: int = 0
    skills_completed: int = 0
    evidence_count: int = 0
    score: int = 0                      # Internal numeric used to derive level
    reasoning: list[str] = field(default_factory=list)


@dataclass
class ConceptReinforcement:
    """A learning concept the user has been exposed to.

    'practiced_count' is incremented by completed actions / achieved milestones
    whose interpretation mentions the concept. 'seen_count' counts how many
    findings surfaced the concept. needs_reinforcement = seen but not practised.
    """
    concept: str
    finding_types: list[str] = field(default_factory=list)
    seen_count: int = 0
    practiced_count: int = 0
    needs_reinforcement: bool = False


@dataclass
class AdaptiveInsight:
    """An insight surfaced to the user — always traceable to its trigger.

    kind:    maturity | evidence_quality | reinforcement | remediation
    severity: ok|info|medium|high
    """
    kind: str
    severity: str
    headline: str
    summary: str
    why: str                      # Why this insight fired — deterministic explanation
    suggested_action_ids: list[str] = field(default_factory=list)
    learning_concepts: list[str] = field(default_factory=list)


@dataclass
class InvestigationMemory:
    """Top-level structured memory snapshot for one investigation."""
    investigation_id: str
    computed_at: datetime

    maturity_by_category: dict[str, CategoryMaturity] = field(default_factory=dict)
    evidence_quality: EvidenceQualitySnapshot = field(default_factory=EvidenceQualitySnapshot)
    concept_reinforcement: list[ConceptReinforcement] = field(default_factory=list)

    # Aggregate counts (for header banners)
    total_milestones_achieved: int = 0
    total_actions_completed: int = 0
    total_actions_abandoned: int = 0
    total_evidence_artifacts: int = 0
    total_findings: int = 0

    # Patterns observed in this investigation
    repeated_milestone_keys: dict[str, int] = field(default_factory=dict)  # key → count
    incomplete_objectives: list[str] = field(default_factory=list)         # objective text repeated

    # Human-readable summaries
    strengths: list[str] = field(default_factory=list)
    needs_reinforcement: list[str] = field(default_factory=list)

    # Phase 15 — root-cause themes active in this investigation
    active_themes: list = field(default_factory=list)
    undocumented_themes: list[str] = field(default_factory=list)

    # Phase 17 — defensive maturity (parallel to offensive maturity_by_category)
    defensive_maturity_by_category: dict = field(default_factory=dict)
    posture_snapshots: list = field(default_factory=list)
    regression_alerts: list[str] = field(default_factory=list)
