"""Dataclasses for the investigation branch workspace (Phase 19).

These are pure view objects — not persisted. Built at query time from
existing storage by `assembler.py`.

NO autonomous reasoning. Every field is derived deterministically from
stored evidence / approval / milestone / defensive snapshot state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class NodeKind(StrEnum):
    """What a branch node represents in the investigation graph."""

    TARGET     = "target"      # Root: the investigation target
    SURFACE    = "surface"     # Group of findings sharing endpoint/family
    DISCOVERY  = "discovery"   # A single finding
    ACTION     = "action"      # A guided action (validation step)
    EVIDENCE   = "evidence"    # An evidence artifact
    # Phase 59a — NodeKind.MILESTONE removed alongside the milestone
    # subsystem. The value was "milestone"; no emitter creates it anymore.
    REMEDIATION = "remediation"  # A defensive verification step


class BranchState(StrEnum):
    """Visible lifecycle state of a branch node.

    Order matters — used in the template for class precedence (highest wins):
        locked
        available
        active                  ← offensive: approved
        completed               ← offensive: marked complete, no evidence
        evidence_attached       ← offensive: evidence captured
        remediation_pending     ← defensive: verification_pending (Part E)
        verification_running    ← defensive: approval in progress
        verified                ← defensive: verification complete
        regression              ← defensive: regression_detected (Part E)
    """

    LOCKED               = "locked"
    AVAILABLE            = "available"
    ACTIVE               = "active"
    COMPLETED            = "completed"
    EVIDENCE_ATTACHED    = "evidence_attached"
    REMEDIATION_PENDING  = "remediation_pending"    # alias: verification_pending
    VERIFICATION_RUNNING = "verification_running"   # Phase 21
    VERIFIED             = "verified"               # Phase 21
    REGRESSION           = "regression"             # alias: regression_detected


@dataclass
class CausalEdge:
    """Lineage edge: parent_id → child_id with deterministic reason."""

    parent_id: str
    child_id: str
    edge_kind: str   # "surface_groups" | "finding_implies_action" | "action_yields_evidence"
                     # | "evidence_confirms_milestone" | "finding_implies_theme"
                     # | "theme_implies_remediation"
    why: str = ""    # Operator-readable rationale


@dataclass
class BranchNode:
    """One node in the investigation branch tree.

    Children are stored as direct references (not IDs) — the tree is built
    once per render and discarded.
    """

    node_id: str
    kind: NodeKind
    label: str
    state: BranchState
    why: str = ""                                # Why is this node in this state?
    icon: str = "·"
    severity_class: str = "info"
    detail: str = ""                             # Short context line
    badge: str = ""                              # State badge text (e.g. "evidence ✓")
    children: list[BranchNode] = field(default_factory=list)

    # Cross-references to existing primary keys (one of these is set per kind)
    finding_id:     str | None = None
    finding_type:   str | None = None        # Phase 48 — populated for DISCOVERY nodes
    action_id:      str | None = None
    evidence_id:    str | None = None
    # Phase 59a — objective_key field removed alongside the milestone
    # subsystem (the only writer was section 3.2 of the assembler).
    theme_id:       str | None = None
    remediation_action_id: str | None = None

    # Inline content surfaced when the node is expanded — no tab navigation
    evidence_goals:    list[str] = field(default_factory=list)
    learning_concepts: list[str] = field(default_factory=list)
    ctf_objectives:    list[str] = field(default_factory=list)

    # Timestamps used by storyline rendering
    earliest_at: datetime | None = None
    latest_at:   datetime | None = None

    # Phase 21 — defensive confidence indicator (set on REMEDIATION nodes
    # via apps/investigation_workspace/branch/states.py:defensive_confidence_*).
    confidence_glyph: str = ""
    confidence_label: str = ""

    # Phase 25 — contextual narrative (Part 9 of the cognition directive).
    # Observation-grounded sentence sourced from interpretations.py `meaning`
    # for DISCOVERY nodes, or from action.explanation / why_this_matters for
    # ACTION / REMEDIATION nodes. Renders as an italic narrative on the card.
    narrative: str = ""


@dataclass
class StorylineEntry:
    """One step in the branch storyline (Part J)."""

    timestamp: datetime
    branch_id: str       # Which branch this entry belongs to
    label: str           # Human-readable storyline beat
    icon: str
    state: BranchState
    why: str = ""


@dataclass
class ThemeOverlay:
    """Root-cause theme strip shown above the graph (Part H)."""

    theme_id: str
    label: str
    description: str
    confidence: str                                  # emerging | established | strong
    matching_branch_ids: list[str] = field(default_factory=list)
    remediation_concepts: list[str] = field(default_factory=list)
    remediation_documented: bool = False
    why: str = ""

    # Phase 21 — root-cause → remediation continuity (Part G).
    # Counts come from the assembler scanning REMEDIATION nodes whose
    # parent discovery's finding_type belongs to this cluster.
    verified_remediation_count:   int = 0
    running_remediation_count:    int = 0
    unverified_remediation_count: int = 0
    regressed_remediation_count:  int = 0


@dataclass
class InvestigationBranch:
    """One top-level branch rooted at a surface or discovery cluster.

    The root is a `SURFACE` node; its children are DISCOVERY nodes;
    grandchildren are ACTION/MILESTONE; leaves are EVIDENCE/REMEDIATION.
    """

    branch_id: str
    root: BranchNode
    edges: list[CausalEdge] = field(default_factory=list)
    state: BranchState = BranchState.AVAILABLE       # Aggregate state for the badge

    # Reveal control — see assembler `_apply_progressive_reveal`
    max_revealed_depth: int = 99                     # 99 == no clamp
    hidden_descendant_count: int = 0                 # For "+N more steps hidden"


@dataclass
class WorkspaceView:
    """Assembled top-level view passed to the template."""

    investigation_id: str
    target: str
    branches: list[InvestigationBranch] = field(default_factory=list)
    theme_overlays: list[ThemeOverlay] = field(default_factory=list)
    storyline: list[StorylineEntry] = field(default_factory=list)

    # Aggregate counts for the workspace header strip (replaces the legacy
    # tab counts: pending / approved / completed). Investigation-progression
    # language only — no scanner/queue terminology.
    branch_count_total:      int = 0
    branch_count_completed:  int = 0
    branch_count_with_evidence: int = 0
    branch_count_in_remediation: int = 0
    regression_count:        int = 0

    # Phase 21 — before/after comparison (Part D). Populated when 2+
    # posture snapshots exist; pulled from PostureService.compare on the
    # most recent BASELINE / PRE_REMEDIATION → POST_REMEDIATION pair.
    comparison_available: bool = False
    comparison_before_label: str = ""
    comparison_after_label:  str = ""
    comparison_resolved:    list[dict] = field(default_factory=list)
    comparison_unchanged:   list[dict] = field(default_factory=list)
    comparison_emerging:    list[dict] = field(default_factory=list)
    comparison_regressed:   list[dict] = field(default_factory=list)
    comparison_strengthened: list[dict] = field(default_factory=list)
    comparison_why: str = ""
