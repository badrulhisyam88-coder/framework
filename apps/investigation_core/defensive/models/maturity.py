"""Defensive maturity — parallel to offensive maturity but focused on mitigation reasoning.

A user can be ADVANCED at finding SQLi (offensive) yet BEGINNER at documenting
parameterised queries (defensive). The two are tracked separately so the
platform can nudge the user toward defensive understanding when offensive
work is mature.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class DefensiveMaturityLevel(StrEnum):
    NONE         = "none"          # No defensive signal at all
    EMERGING     = "emerging"      # Documentation started
    DEVELOPING   = "developing"    # Some mitigation evidence captured
    PROFICIENT   = "proficient"    # Defensive actions completed
    EXEMPLARY    = "exemplary"     # Post-remediation snapshot confirms fixes


DEFENSIVE_MATURITY_LABELS: dict[str, str] = {
    DefensiveMaturityLevel.NONE:        "None",
    DefensiveMaturityLevel.EMERGING:    "Emerging",
    DefensiveMaturityLevel.DEVELOPING:  "Developing",
    DefensiveMaturityLevel.PROFICIENT:  "Proficient",
    DefensiveMaturityLevel.EXEMPLARY:   "Exemplary",
}


@dataclass
class DefensiveCategoryMaturity:
    """Per-category defensive maturity with explicit reasoning."""
    category: str
    label: str
    level: DefensiveMaturityLevel
    documented_remediation_concepts: int = 0
    completed_defensive_actions: int = 0
    remediation_evidence_count: int = 0
    post_remediation_snapshots: int = 0
    score: int = 0
    reasoning: list[str] = field(default_factory=list)
