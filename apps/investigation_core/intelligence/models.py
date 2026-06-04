"""Intelligence-layer dataclasses — themes, cross-investigation links, summaries."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class InvestigationTheme:
    """A root-cause cluster materialised inside one investigation."""
    theme_id: str                          # equals cluster_id
    label: str
    description: str
    confidence: str                        # emerging | established | strong
    matching_finding_count: int            # findings matching the cluster
    matching_finding_types: list[str] = field(default_factory=list)
    matching_finding_ids: list[str] = field(default_factory=list)
    remediation_concepts: list[str] = field(default_factory=list)
    related_skill_prefixes: list[str] = field(default_factory=list)
    remediation_documented: bool = False   # any evidence linked to a concept term
    why: str = ""                          # deterministic explanation


@dataclass
class CrossInvestigationLink:
    """A pointer to another investigation that shares this cluster."""
    cluster_id: str
    investigation_id: str
    title: str
    matching_finding_count: int
    matching_finding_types: list[str] = field(default_factory=list)


@dataclass
class ThemeRepetition:
    """A theme that recurs across multiple investigations."""
    cluster_id: str
    label: str
    investigations_count: int
    total_findings: int
    investigation_ids: list[str] = field(default_factory=list)


@dataclass
class RemediationGap:
    """A remediation concept that recurs across investigations but is rarely documented."""
    concept: str
    surfaced_in_investigations: int
    documented_in_investigations: int
    cluster_ids: list[str] = field(default_factory=list)


@dataclass
class ComparisonSummary:
    """Cross-investigation comparison snapshot."""
    investigations_compared: int
    repeated_themes: list[ThemeRepetition] = field(default_factory=list)
    common_remediation_gaps: list[RemediationGap] = field(default_factory=list)
