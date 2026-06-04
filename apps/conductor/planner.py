"""Phase E — Deterministic Planner controller.

GATE WARNING: The Step 0 live gate (Phase C wire end-to-end on a real solving lab)
was NOT run before this planner was built (no lab URL available in the build
environment).  The planner logic is fully verified by mock tests.  Before relying
on the planner in production, the operator must verify on the message-differential
auth lab that: (a) STATE seeds pending from real findings, (b) facts/artifacts
accumulate as branches complete, (c) SOLVED fires on credential capture.

Planner decision algorithm (deterministic, no model reasoning for known cases):
  1. Read STATE: pending (ranked), ruled_out, completed, current_position, goal.
  2. Filter pending: drop anything in ruled_out or completed.
  3. Filter pending: drop anything whose documented precondition is unmet.
     Only documented methodology preconditions are gated — no invented rules.
  4. If reachable items: pop highest priority (ties → insertion-order, deterministic)
     → EXECUTE via orchestrator.
  5. Else (preconditions unmet but candidates exist): SWEEP (whole-tree fallback).
  6. Else (pending empty + unmet): STUCK.

Terminal states: SOLVED (check_success satisfied) | STUCK (no path forward).
No infinite loops: pending drains; completed prevents re-tries; ruled_out locks out.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger("conductor.planner")


# ── Domain mappings — populate per your engines and concepts ──────────────────

# Position-based preconditions: concept_id → {field_name: frozenset(allowed_values)}.
# A concept is only dispatched when current_position[field_name] is in allowed_values.
# Leave empty if no concepts require position gating in your domain.
_CONCEPT_PRECONDITIONS: dict[str, dict] = {}

# Goal-level preconditions: concept_id → callable(goal: dict) -> bool.
# True = precondition met; concept is dispatched. False = blocked.
_CONCEPT_GOAL_PRECONDITIONS: dict = {}


# ── concept → engine mapping (from CONCEPT_ENGINE_MAP) ────────────────────────
def _concept_to_engine(concept_id: str) -> str | None:
    try:
        from apps.conductor.constants import CONCEPT_ENGINE_MAP
        return CONCEPT_ENGINE_MAP.get(concept_id) or None
    except Exception as exc:
        logger.debug("_concept_to_engine: %s", exc)
        return None


# concept → relevant finding_types used to look up a matching finding_id in the DB.
# Populate per your domain: {"CONCEPT-MY-THING": ["my_finding_type", ...], ...}
_CONCEPT_FINDING_TYPES: dict[str, list] = {}


def concept_finding_types(concept_id: str) -> list:
    return list(_CONCEPT_FINDING_TYPES.get(concept_id, []))


# ── Precondition check ────────────────────────────────────────────────────────

def _precondition_met(
    concept_id: str,
    current_position: dict,
    goal: dict | None = None,
) -> bool:
    """Return True if current_position (and goal, when applicable) satisfies the
    concept's documented precondition.

    Only documented preconditions are checked.  Unknown concepts → always reachable.
    """
    # Position-based precondition (e.g. CONCEPT-JS-SPIDER requires authentication)
    precond = _CONCEPT_PRECONDITIONS.get(concept_id)
    if precond:
        for field_name, required_vals in precond.items():
            if current_position.get(field_name, "none") not in required_vals:
                return False

    # Goal-level precondition (e.g. CONCEPT-USERNAME-ENUM-VIA-LOCKOUT requires no known target_user)
    goal_precond = _CONCEPT_GOAL_PRECONDITIONS.get(concept_id)
    if goal_precond is not None:
        try:
            if not goal_precond(goal):
                return False
        except Exception:
            pass   # never block on predicate error

    return True


# ── Decision dataclass ────────────────────────────────────────────────────────

@dataclass
class PlannerDecision:
    """Result of one planner decision iteration."""
    action:     str         # "execute" | "sweep" | "stuck" | "park" | "solved"
    concept_id: str = ""
    engine_id:  str = ""
    priority:   int = 0
    reason:     str = ""
    # For logging in Zone C
    log_entry:  str = ""


# ── Main decision function ────────────────────────────────────────────────────

def plan_next_step(agent_state: dict) -> PlannerDecision:
    """Deterministic planner: read STATE and return the next action.

    Never raises.  Returns a PlannerDecision with action=stuck on error.
    """
    try:
        return _plan(agent_state)
    except Exception as exc:
        logger.warning("plan_next_step: unexpected error — %s", exc)
        return PlannerDecision(
            action    = "stuck",
            reason    = f"planner error: {exc}",
            log_entry = f"STUCK (planner error: {exc})",
        )


def _plan(agent_state: dict) -> PlannerDecision:
    # Already SOLVED?
    if agent_state.get("solved"):
        reason = agent_state.get("solved_reason", "goal satisfied")
        return PlannerDecision(
            action    = "solved",
            reason    = reason,
            log_entry = f"SOLVED — {reason}",
        )

    pending     = list(agent_state.get("pending") or [])
    ruled_out   = set(agent_state.get("ruled_out") or [])
    completed   = set(agent_state.get("completed") or [])
    current_pos = agent_state.get("current_position") or {}
    goal        = agent_state.get("goal") or {}

    # Step 2: filter ruled_out + completed
    candidates = [
        p for p in pending
        if p.get("concept") not in ruled_out
        and p.get("concept") not in completed
    ]

    # Step 3: filter unmet preconditions (position-based + goal-based)
    reachable = [
        p for p in candidates
        if _precondition_met(p.get("concept", ""), current_pos, goal)
    ]

    # Step 4: pop highest priority (sort by priority desc; ties → insertion order)
    # Sort here rather than relying on the caller to pre-sort, so the planner
    # is self-sufficient regardless of the order pending items arrive in.
    reachable.sort(key=lambda x: x.get("priority", 0), reverse=True)
    if reachable:
        chosen     = reachable[0]
        concept_id = chosen.get("concept", "")
        engine_id  = _concept_to_engine(concept_id) or ""
        priority   = chosen.get("priority", 50)
        reason = (
            f"Popped priority={priority} concept={concept_id} → engine={engine_id or 'none'}"
        )
        log_entry = f"EXECUTE priority={priority} [{concept_id}] via {engine_id or '?'}"
        logger.info("planner: EXECUTE %s → %s (priority=%d)", concept_id, engine_id, priority)
        return PlannerDecision(
            action    = "execute",
            concept_id = concept_id,
            engine_id  = engine_id,
            priority   = priority,
            reason    = reason,
            log_entry = log_entry,
        )

    # Step 5: candidates exist but all blocked by preconditions → SWEEP
    if candidates:
        blocked_concepts = [p.get("concept", "?") for p in candidates[:3]]
        reason = (
            f"No reachable lead — {len(candidates)} candidates blocked by preconditions "
            f"(current_pos={current_pos.get('authentication','none')}/"
            f"{current_pos.get('privilege','none')}). "
            f"Blocked: {blocked_concepts}"
        )
        log_entry = f"SWEEP — {reason}"
        logger.info("planner: SWEEP — preconditions unmet for %d candidates", len(candidates))
        return PlannerDecision(
            action    = "sweep",
            reason    = reason,
            log_entry = log_entry,
        )

    # Step 7: no candidates at all → STUCK
    facts    = len(agent_state.get("facts") or [])
    done     = len(completed)
    ruled    = len(ruled_out)
    reason = (
        f"No pending candidates — facts={facts} completed={done} ruled_out={ruled}. "
        f"Goal: {(agent_state.get('goal') or {}).get('objective', '?')}"
    )
    log_entry = f"STUCK — {reason}"
    logger.info("planner: STUCK — %s", reason)
    return PlannerDecision(
        action    = "stuck",
        reason    = reason,
        log_entry = log_entry,
    )
