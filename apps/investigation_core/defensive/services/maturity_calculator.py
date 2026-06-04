"""Defensive maturity calculator — explicit reasoning, deterministic weights.

Per-category score draws from four signals:

  documented_remediation_concepts ×3   (concept mentioned in evidence)
  completed_defensive_actions    ×5    (verify_* action marked complete)
  remediation_evidence_count     ×2    (evidence tagged "remediation"/"verification")
  post_remediation_snapshots     ×6    (a 'post_remediation' or 'regression_check')

Thresholds — inclusive lower bounds:
  ≥18 exemplary, ≥10 proficient, ≥4 developing, ≥1 emerging, else none.
"""

from __future__ import annotations

from apps.investigation_core.defensive.models.maturity import (
    DefensiveCategoryMaturity,
    DefensiveMaturityLevel,
)
from apps.investigation_core.memory.categories import category_label

_W_REMEDIATION_CONCEPT = 3
_W_DEFENSIVE_ACTION    = 5
_W_REMEDIATION_EV      = 2
_W_POST_SNAPSHOT       = 6

_LEVEL_THRESHOLDS = [
    (18, DefensiveMaturityLevel.EXEMPLARY),
    (10, DefensiveMaturityLevel.PROFICIENT),
    (4,  DefensiveMaturityLevel.DEVELOPING),
    (1,  DefensiveMaturityLevel.EMERGING),
]


def compute_defensive_maturity(
    category: str,
    *,
    documented_remediation_concepts: int,
    completed_defensive_actions: int,
    remediation_evidence_count: int,
    post_remediation_snapshots: int,
) -> DefensiveCategoryMaturity:
    score = (
        documented_remediation_concepts * _W_REMEDIATION_CONCEPT
        + completed_defensive_actions * _W_DEFENSIVE_ACTION
        + remediation_evidence_count * _W_REMEDIATION_EV
        + post_remediation_snapshots * _W_POST_SNAPSHOT
    )

    level = DefensiveMaturityLevel.NONE
    for threshold, lvl in _LEVEL_THRESHOLDS:
        if score >= threshold:
            level = lvl
            break

    bits: list[str] = []
    if documented_remediation_concepts:
        bits.append(
            f"{documented_remediation_concepts} concept(s) documented "
            f"(+{documented_remediation_concepts * _W_REMEDIATION_CONCEPT})"
        )
    if completed_defensive_actions:
        bits.append(
            f"{completed_defensive_actions} verification(s) completed "
            f"(+{completed_defensive_actions * _W_DEFENSIVE_ACTION})"
        )
    if remediation_evidence_count:
        bits.append(
            f"{remediation_evidence_count} remediation evidence (+"
            f"{remediation_evidence_count * _W_REMEDIATION_EV})"
        )
    if post_remediation_snapshots:
        bits.append(
            f"{post_remediation_snapshots} post-remediation snapshot(s) "
            f"(+{post_remediation_snapshots * _W_POST_SNAPSHOT})"
        )
    reasoning = (
        f"Defensive score {score}: " + ", ".join(bits)
        if bits
        else "Defensive score 0 — no remediation activity yet"
    )

    return DefensiveCategoryMaturity(
        category=category,
        label=category_label(category),
        level=level,
        documented_remediation_concepts=documented_remediation_concepts,
        completed_defensive_actions=completed_defensive_actions,
        remediation_evidence_count=remediation_evidence_count,
        post_remediation_snapshots=post_remediation_snapshots,
        score=score,
        reasoning=[reasoning],
    )
