"""Posture snapshot + comparison dataclasses.

A PostureSnapshot is a point-in-time capture of an investigation's risk picture.
PostureComparison computes a deterministic before-vs-after diff and labels
themes as resolved / unchanged / emerging.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class PostureSnapshotKind(StrEnum):
    BASELINE     = "baseline"            # First capture (offensive findings present)
    PRE_REMEDIATION  = "pre_remediation" # Immediately before remediation work
    POST_REMEDIATION = "post_remediation"# After remediation work — verification target
    REGRESSION_CHECK = "regression_check" # Periodic re-verification
    AD_HOC       = "ad_hoc"              # Operator-chosen


POSTURE_KIND_LABELS: dict[str, str] = {
    PostureSnapshotKind.BASELINE:         "Baseline",
    PostureSnapshotKind.PRE_REMEDIATION:  "Pre-remediation",
    PostureSnapshotKind.POST_REMEDIATION: "Post-remediation",
    PostureSnapshotKind.REGRESSION_CHECK: "Regression check",
    PostureSnapshotKind.AD_HOC:           "Ad-hoc",
}


@dataclass
class PostureSnapshot:
    """One frozen view of investigation posture."""
    snapshot_id: str
    investigation_id: str
    campaign_id: str | None
    label: str                                  # Free-text label
    snapshot_kind: PostureSnapshotKind
    captured_at: datetime
    findings_count: int                         # Total findings at capture
    findings_by_severity: dict[str, int]        # severity → count
    findings_by_type: dict[str, int]            # finding_type → count
    active_themes: list[dict]                   # [{cluster_id, label, confidence, finding_count}]
    evidence_quality_score: int                 # 0–100
    remediation_documented_themes: list[str]    # cluster_ids with documented remediation
    captured_by: str
    notes: str | None


@dataclass
class ThemeDelta:
    """Per-theme change between two snapshots."""
    cluster_id: str
    label: str
    # One of: resolved | unchanged | emerging | regressed | strengthened
    state: str
    before_finding_count: int = 0
    after_finding_count: int = 0
    before_confidence: str | None = None
    after_confidence: str | None = None


@dataclass
class PostureComparison:
    """Diff between two snapshots — fully derived, fully explainable."""
    before: PostureSnapshot
    after: PostureSnapshot

    findings_delta: int = 0
    severity_delta: dict[str, int] = field(default_factory=dict)
    finding_type_delta: dict[str, int] = field(default_factory=dict)

    themes_resolved: list[ThemeDelta] = field(default_factory=list)
    themes_emerging: list[ThemeDelta] = field(default_factory=list)
    themes_unchanged: list[ThemeDelta] = field(default_factory=list)
    themes_regressed: list[ThemeDelta] = field(default_factory=list)
    themes_strengthened: list[ThemeDelta] = field(default_factory=list)

    evidence_quality_delta: int = 0
    new_remediation_themes: list[str] = field(default_factory=list)

    summary: list[str] = field(default_factory=list)
    why: list[str] = field(default_factory=list)
