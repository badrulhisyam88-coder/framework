"""Translate an InvestigationMemory snapshot into AdaptiveInsight entries.

Every insight carries a `why` field explaining the deterministic trigger.
The user can always answer "why did this recommendation appear?" by reading
the field — no opaque scoring.
"""

from __future__ import annotations

from apps.investigation_core.memory.models.memory import (
    AdaptiveInsight,
    InvestigationMemory,
    MaturityLevel,
)


def generate_insights(memory: InvestigationMemory) -> list[AdaptiveInsight]:
    """Produce a deterministic list of insights from a memory snapshot.

    Insight kinds, in priority order:
      1. maturity         — celebrate advanced categories, nudge exposure-only ones
      2. evidence_quality — surface evidence quality gaps with concrete weak types
      3. reinforcement    — concepts seen many times but rarely practised
      4. remediation      — advanced users get remediation prompts
    """
    out: list[AdaptiveInsight] = []

    out.extend(_maturity_insights(memory))
    out.extend(_evidence_insights(memory))
    out.extend(_reinforcement_insights(memory))
    out.extend(_remediation_insights(memory))
    out.extend(_theme_insights(memory))
    out.extend(_defensive_insights(memory))

    return out


def _maturity_insights(memory: InvestigationMemory) -> list[AdaptiveInsight]:
    out: list[AdaptiveInsight] = []
    for mat in memory.maturity_by_category.values():
        if mat.level == MaturityLevel.ADVANCED:
            out.append(AdaptiveInsight(
                kind="maturity",
                severity="ok",
                headline=f"{mat.label} — advanced activity demonstrated",
                summary=(
                    f"{mat.milestones_achieved} milestone(s), "
                    f"{mat.actions_completed} action(s) completed, "
                    f"{mat.skills_completed} skill(s) mastered. "
                    "Beginner explanations reduced; remediation paths surfaced."
                ),
                why="; ".join(mat.reasoning),
            ))
        elif mat.level == MaturityLevel.EXPOSURE_ONLY and mat.findings_count > 0:
            out.append(AdaptiveInsight(
                kind="maturity",
                severity="info",
                headline=f"{mat.label} — start an investigation step",
                summary=(
                    f"{mat.findings_count} finding(s) surfaced in this category. "
                    "Pick a guided action to begin demonstrating activity."
                ),
                why=f"Category {mat.category} has findings but score = 0",
            ))
    return out


def _evidence_insights(memory: InvestigationMemory) -> list[AdaptiveInsight]:
    eq = memory.evidence_quality
    if eq.total_artifacts == 0:
        return []
    if eq.overall_score >= 75:
        return [AdaptiveInsight(
            kind="evidence_quality",
            severity="ok",
            headline="Evidence quality strong",
            summary=(
                f"Average quality {eq.overall_score}/100 across "
                f"{eq.total_artifacts} artifact(s); "
                f"{eq.type_diversity} distinct type(s)."
            ),
            why=", ".join(eq.reasons),
        )]
    if eq.overall_score >= 50:
        return [AdaptiveInsight(
            kind="evidence_quality",
            severity="info",
            headline="Evidence quality could be improved",
            summary=(
                f"Average quality {eq.overall_score}/100. "
                "Add finding linkage, longer descriptions, and varied artifact types."
            ),
            why=", ".join(eq.reasons),
        )]
    # weak
    weak_list = ", ".join(eq.weak_types) if eq.weak_types else "multiple types"
    return [AdaptiveInsight(
        kind="evidence_quality",
        severity="medium",
        headline="Evidence quality is thin",
        summary=(
            f"Average quality {eq.overall_score}/100. "
            f"Weak in: {weak_list}. Link artifacts to findings/actions, "
            "add descriptions, and capture richer content."
        ),
        why=", ".join(eq.reasons),
    )]


def _reinforcement_insights(memory: InvestigationMemory) -> list[AdaptiveInsight]:
    out: list[AdaptiveInsight] = []
    # Top concepts that need reinforcement
    candidates = [c for c in memory.concept_reinforcement if c.needs_reinforcement]
    for c in candidates[:3]:
        finding_types = ", ".join(c.finding_types[:3])
        out.append(AdaptiveInsight(
            kind="reinforcement",
            severity="info",
            headline=f"Concept needs reinforcement: {c.concept}",
            summary=(
                f"Surfaced in {c.seen_count} finding(s) "
                f"({finding_types}), practised {c.practiced_count} time(s). "
                "Open a related learning step or complete an action to reinforce."
            ),
            why=(
                f"Concept appears in {c.seen_count} finding(s) but only "
                f"{c.practiced_count} matching action(s)/milestone(s) completed"
            ),
            learning_concepts=[c.concept],
        ))
    # Incomplete-objective patterns
    if memory.incomplete_objectives:
        sample = "; ".join(memory.incomplete_objectives[:3])
        out.append(AdaptiveInsight(
            kind="reinforcement",
            severity="info",
            headline="Recurring objectives not yet marked complete",
            summary=(
                f"Objectives surfaced repeatedly without completion: {sample}. "
                "Pursue these for stronger investigation lineage."
            ),
            why=(
                f"{len(memory.incomplete_objectives)} objective(s) appear in "
                "multiple findings and have no achieved milestone"
            ),
        ))
    return out


def _defensive_insights(memory: InvestigationMemory) -> list[AdaptiveInsight]:
    """Surface defensive maturity, regressions, and post-remediation milestones."""
    from apps.investigation_core.intelligence.clusters import (
        CLUSTER_TO_DEFENSIVE_ACTIONS,
    )
    out: list[AdaptiveInsight] = []

    # Regression alerts
    for alert in memory.regression_alerts:
        out.append(AdaptiveInsight(
            kind="defensive_regression",
            severity="high",
            headline="Regression detected",
            summary=alert,
            why="Theme reappeared after post-remediation snapshot",
        ))

    # Defensive path nudges — for any active theme without remediation evidence,
    # surface the verification actions registered for the cluster.
    for theme in memory.active_themes:
        if getattr(theme, "remediation_documented", False):
            continue
        if getattr(theme, "confidence", "emerging") == "emerging":
            continue
        defs = CLUSTER_TO_DEFENSIVE_ACTIONS.get(theme.theme_id, ())
        if not defs:
            continue
        out.append(AdaptiveInsight(
            kind="defensive_path",
            severity="info",
            headline=f"Defensive verification available for: {theme.label}",
            summary=(
                f"{len(defs)} verification step(s) registered for this theme. "
                "Run them to confirm the fix landed."
            ),
            why=(
                f"Theme '{theme.label}' is {theme.confidence} and remediation "
                "is not yet documented; cluster has verification actions."
            ),
            suggested_action_ids=list(defs),
        ))

    # Posture-improvement celebration: per-category defensive maturity ≥ proficient
    for mat in memory.defensive_maturity_by_category.values():
        level = str(mat.level)
        if level in ("proficient", "exemplary"):
            out.append(AdaptiveInsight(
                kind="defensive_posture",
                severity="ok",
                headline=f"Defensive maturity {level}: {mat.label}",
                summary=(
                    f"{mat.completed_defensive_actions} verification(s) completed, "
                    f"{mat.remediation_evidence_count} remediation evidence, "
                    f"{mat.documented_remediation_concepts} concept(s) documented."
                ),
                why="; ".join(mat.reasoning),
            ))

    return out


def _theme_insights(memory: InvestigationMemory) -> list[AdaptiveInsight]:
    """Root-cause themes — emit a per-theme insight when remediation isn't documented.

    `memory.active_themes` is populated by MemoryService with
    `InvestigationTheme` instances; we treat them as opaque here and read only
    the fields we need to keep this module decoupled from the intelligence pkg.
    """
    out: list[AdaptiveInsight] = []
    for theme in memory.active_themes:
        # Skip emerging themes — they're too thin to warrant pressure
        if getattr(theme, "confidence", "emerging") == "emerging":
            continue
        if getattr(theme, "remediation_documented", False):
            out.append(AdaptiveInsight(
                kind="remediation",
                severity="ok",
                headline=f"Root-cause theme documented: {theme.label}",
                summary=(
                    f"Evidence mentions remediation concepts linked to "
                    f"'{theme.label}'. Investigation lineage is strong."
                ),
                why=theme.why,
            ))
            continue
        # Established+ theme without remediation evidence — prompt the user
        sample = ", ".join(theme.remediation_concepts[:3])
        out.append(AdaptiveInsight(
            kind="remediation",
            severity="medium" if theme.confidence == "strong" else "info",
            headline=f"Document remediation for: {theme.label}",
            summary=(
                f"Theme established from {theme.matching_finding_count} finding(s). "
                f"Capture a note referencing: {sample}."
            ),
            why=theme.why,
        ))
    return out


def _remediation_insights(memory: InvestigationMemory) -> list[AdaptiveInsight]:
    """Advanced users get explicit remediation prompts; beginners do not."""
    advanced_categories = [
        m for m in memory.maturity_by_category.values()
        if m.level == MaturityLevel.ADVANCED
    ]
    if not advanced_categories:
        return []
    labels = ", ".join(m.label for m in advanced_categories)
    return [AdaptiveInsight(
        kind="remediation",
        severity="info",
        headline="Shift toward remediation reasoning",
        summary=(
            f"Advanced activity demonstrated in: {labels}. "
            "Document root cause + defensive concepts (parameterised queries, "
            "output encoding, defence-in-depth) alongside offensive proof."
        ),
        why=(
            f"{len(advanced_categories)} category(ies) at advanced maturity; "
            "remediation insight emitted to balance offensive + defensive understanding"
        ),
    )]
