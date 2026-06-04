"""Adaptive helpers used inline alongside finding entries.

Pure-functional over a memory snapshot. Used by the feed builder to:
  - decorate unlock hints with maturity-aware narrative
  - emit reinforcement chips per-finding (warnings, not commands)
"""

from __future__ import annotations

from dataclasses import dataclass

from apps.investigation_core.memory.categories import category_for_finding_type
from apps.investigation_core.memory.models.memory import (
    InvestigationMemory,
    MaturityLevel,
)
from apps.investigation_workspace.feed.models import UnlockHint


@dataclass
class ReinforcementChip:
    """A small inline pill placed next to a finding to flag a memory signal."""
    label: str
    tone: str   # ok | info | warn
    why: str


def adapt_unlock_hint(
    hint: UnlockHint | None,
    memory: InvestigationMemory,
    *,
    finding_type: str | None = None,
) -> UnlockHint | None:
    """Decorate (or suppress) an unlock hint based on category maturity.

    Suppression rule: if user is ADVANCED in the matching category, replace
    the narrative with a remediation-leaning version so the same unlock chain
    doesn't repeat beginner messaging.
    """
    if hint is None:
        return None
    if not finding_type:
        return hint

    cat = category_for_finding_type(finding_type)
    mat = memory.maturity_by_category.get(cat)
    if mat is None:
        return hint
    if mat.level != MaturityLevel.ADVANCED:
        return hint

    # Replace narrative with remediation framing — keep next steps as-is.
    new_narr = (
        f"{hint.narrative} (Advanced — focus on root cause, "
        "defence-in-depth, and remediation notes.)"
    )
    return UnlockHint(
        narrative=new_narr,
        next_action_ids=hint.next_action_ids,
        next_milestone_keys=hint.next_milestone_keys,
    )


def reinforcement_chips_for_finding(
    finding_type: str,
    memory: InvestigationMemory,
) -> list[ReinforcementChip]:
    """Inline chips that flag memory-driven signals on a finding entry."""
    out: list[ReinforcementChip] = []
    cat = category_for_finding_type(finding_type)
    mat = memory.maturity_by_category.get(cat)

    if mat is not None:
        if mat.level == MaturityLevel.ADVANCED:
            out.append(ReinforcementChip(
                label="⤴ Advanced — focus on remediation",
                tone="ok",
                why=(
                    f"Category {mat.label} at advanced maturity "
                    f"({mat.milestones_achieved} milestone(s), "
                    f"{mat.actions_completed} action(s) completed)"
                ),
            ))
        elif mat.level == MaturityLevel.EXPOSURE_ONLY and mat.findings_count > 0:
            out.append(ReinforcementChip(
                label="◇ Start an investigation step",
                tone="info",
                why=f"Category {mat.label} has findings but no activity yet",
            ))

    # Concept-reinforcement chips (limit one per finding)
    from apps.investigation_workspace.feed.interpretations import interpret
    interp = interpret(finding_type)
    concepts_here = set(interp.get("learning_concepts") or [])  # type: ignore[arg-type]
    needing = next(
        (c for c in memory.concept_reinforcement
         if c.needs_reinforcement and c.concept in concepts_here),
        None,
    )
    if needing is not None:
        out.append(ReinforcementChip(
            label=f"⚠ Reinforce: {needing.concept}",
            tone="warn",
            why=(
                f"Concept '{needing.concept}' seen in {needing.seen_count} finding(s) "
                f"but practised {needing.practiced_count} time(s)"
            ),
        ))

    return out
