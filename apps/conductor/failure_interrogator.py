"""Phase 3 — Failure Interrogation Layer (v1).

When plan_next_step() returns action="stuck" and the investigation has not
yet exceeded its interrogation budget, this module inspects the most recent
exhausted branch records and emits a typed failure-reason fact.

Design invariants:
  - Interrogation ONLY emits facts.  It never selects engines.
  - Planner remains the sole router.  It re-runs after a fact is emitted.
  - Deterministic pattern matchers only in v1.  No AI.
  - If the interrogator errors, caller falls back to STUCK (fail-closed).
  - If a matcher cannot confidently identify its reason, it returns None.

Fact taxonomy (v1) — expandable via vault grows_from edges:
  mid_run_blocked           — protection activated mid-run (429/lockout body
                              during a brute engine that is NOT the probe itself).
  wordlist_exhausted_no_signal — full wordlist consumed, no success signal and
                              no block detected (wrong target user or wrong list).
  missing_csrf_token        — CSRF extraction failed; engine ran without a valid
                              token and all attempts were rejected.
  requires_session_first    — technique requires an authenticated session that
                              has not yet been captured.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apps.conductor.exploitation.branch_store import BranchRecord

logger = logging.getLogger("conductor.failure_interrogator")

# ── Fact constants ────────────────────────────────────────────────────────────

FACT_MID_RUN_BLOCKED        = "mid_run_blocked"
FACT_WORDLIST_EXHAUSTED     = "wordlist_exhausted_no_signal"
FACT_MISSING_CSRF_TOKEN     = "missing_csrf_token"
FACT_REQUIRES_SESSION_FIRST = "requires_session_first"

# Engines whose exhaustion is handled as pre-flight facts, not mid-run blocks.
# The probe sets ip_block_detected; its exhaustion is not a mid_run_blocked event.
_PROBE_ENGINES = frozenset({"login_protection_probe"})

# Engines that require an authenticated session (planner precondition enforces this,
# but the matcher also checks for explicit exhaustion signals from these engines).
_SESSION_REQUIRED_ENGINES = frozenset({"js_spider", "access_control"})

# Block keywords in exhaustion_record reason strings.
_BLOCK_KEYWORDS = frozenset({"blocked", "rate_limit", "rate-limit", "too_many", "lockout"})

# Per-investigation interrogation cap — prevents pathological loops where
# a fact unlocks a concept that exhausts and produces the same fact again.
MAX_INTERROGATIONS = 5


# ── Public API ────────────────────────────────────────────────────────────────

def interrogate(
    recent_branches: "list[BranchRecord]",
    agent_state: dict,
) -> "str | None":
    """Run all matchers in priority order.

    Returns the first confident fact, or None when no matcher fires.
    Never raises — errors are logged and None is returned.

    Parameters:
        recent_branches: exhausted branch records to inspect.
        agent_state: current agent STATE (facts, artifacts, completed, etc.).
    """
    try:
        for matcher in (
            _match_mid_run_blocked,
            _match_wordlist_exhausted,
            _match_missing_csrf_token,
            _match_requires_session_first,
        ):
            fact = matcher(recent_branches, agent_state)
            if fact is not None:
                logger.info("failure_interrogator: matcher emitted fact=%r", fact)
                return fact
        logger.debug("failure_interrogator: no matcher fired")
        return None
    except Exception as exc:
        logger.warning("failure_interrogator: error during interrogation — %s", exc)
        return None


def budget_remaining(agent_state: dict) -> bool:
    """Return True if this investigation has not yet hit the interrogation cap."""
    return agent_state.get("interrogation_attempts", 0) < MAX_INTERROGATIONS


# ── Matchers (pure functions; no side effects) ────────────────────────────────

def _match_mid_run_blocked(
    branches: "list[BranchRecord]",
    agent_state: dict,
) -> "str | None":
    """Detects IP-block / rate-limit activated DURING a run, not by the probe.

    Inspects:
      - exhaustion_record.negative_evidence.reason containing a block keyword.
      - exhaustion_record.reason containing a block keyword (alternate location).

    Does NOT fire for probe-engine exhaustion (those set ip_block_detected via
    the protection profile, not this fact).
    """
    for branch in branches:
        if branch.state not in ("exhausted", "failed"):
            continue
        if branch.engine_id in _PROBE_ENGINES:
            continue  # probe result → ip_block_detected, not mid_run_blocked

        er = branch.exhaustion_record or {}
        ne = er.get("negative_evidence") or {}

        reason = " ".join([
            str(ne.get("reason") or ""),
            str(er.get("reason") or ""),
        ]).lower()

        if any(kw in reason for kw in _BLOCK_KEYWORDS):
            logger.debug(
                "failure_interrogator: mid_run_blocked matched engine=%r reason=%r",
                branch.engine_id, reason.strip(),
            )
            return FACT_MID_RUN_BLOCKED

    return None


def _match_wordlist_exhausted(
    branches: "list[BranchRecord]",
    agent_state: dict,
) -> "str | None":
    """Detects full wordlist consumption with no credential match and no block.

    Inspects:
      - exhaustion_record.payloads_tried: non-empty (passwords actually iterated).
      - exhaustion_record.no_signal_found: True (oracle-style engines).
      - Negative evidence reason does NOT contain a block keyword.

    A wordlist exhaustion is distinct from a block: if the run was terminated
    by a block, mid_run_blocked should have fired first (matcher ordering).
    """
    for branch in branches:
        if branch.state != "exhausted":
            continue

        er = branch.exhaustion_record or {}
        ne = er.get("negative_evidence") or {}

        # Oracle engines: explicit no_signal_found flag
        if er.get("no_signal_found"):
            return FACT_WORDLIST_EXHAUSTED

        # Brute engines: payloads_tried non-empty and no block signal
        payloads_tried = er.get("payloads_tried") or []
        reason = " ".join([
            str(ne.get("reason") or ""),
            str(er.get("reason") or ""),
        ]).lower()

        is_blocked = any(kw in reason for kw in _BLOCK_KEYWORDS)
        if payloads_tried and not is_blocked:
            logger.debug(
                "failure_interrogator: wordlist_exhausted matched engine=%r tried=%d",
                branch.engine_id, len(payloads_tried),
            )
            return FACT_WORDLIST_EXHAUSTED

    return None


def _match_missing_csrf_token(
    branches: "list[BranchRecord]",
    agent_state: dict,
) -> "str | None":
    """Detects CSRF token extraction failure.

    Inspects:
      - exhaustion_record.negative_evidence.reason or exhaustion_record.reason
        containing "csrf" — emitted by engines that record a CSRF-specific
        structured tag (e.g. "csrf_extraction_failed").

    Stage-log scanning was deliberately removed (Workstream A audit 2026-06-04):
    it would match any stage_log entry that mentions "csrf" descriptively
    (e.g. "CSRF protection: enabled") — same shape as the RC2 page-title false-positive.
    Only the structured tag in the exhaustion record is safe to match.
    """
    for branch in branches:
        if branch.state not in ("exhausted", "failed"):
            continue

        er = branch.exhaustion_record or {}
        ne = er.get("negative_evidence") or {}

        reason = " ".join([
            str(ne.get("reason") or ""),
            str(er.get("reason") or ""),
        ]).lower()

        if "csrf" in reason:
            logger.debug(
                "failure_interrogator: missing_csrf_token matched engine=%r reason=%r",
                branch.engine_id, reason.strip(),
            )
            return FACT_MISSING_CSRF_TOKEN

    return None


def _match_requires_session_first(
    branches: "list[BranchRecord]",
    agent_state: dict,
) -> "str | None":
    """Detects that a technique requires an authenticated session not yet captured.

    Inspects:
      - exhaustion_record.reason containing "requires_auth", "session_required",
        "requires_session", or "no_session".
      - Engine is in _SESSION_REQUIRED_ENGINES and no session/credential artifact
        is captured in agent_state (auth not established).

    The planner already gates session-required engines via preconditions; this
    matcher covers cases where the engine ran despite the gate (e.g., old branch
    re-evaluated) or records an explicit auth-required signal in its exhaustion.
    """
    artifacts = agent_state.get("artifacts") or {}
    has_session = bool(
        (artifacts.get("sessions") or []) or
        (artifacts.get("credentials") or [])
    )

    _SESSION_KEYWORDS = frozenset({
        "requires_auth", "session_required", "requires_session", "no_session",
        "not_authenticated", "unauthorized",
    })

    for branch in branches:
        if branch.state not in ("exhausted", "failed"):
            continue

        er = branch.exhaustion_record or {}
        ne = er.get("negative_evidence") or {}

        reason = " ".join([
            str(ne.get("reason") or ""),
            str(er.get("reason") or ""),
        ]).lower().replace("-", "_").replace(" ", "_")

        if any(kw in reason for kw in _SESSION_KEYWORDS):
            logger.debug(
                "failure_interrogator: requires_session_first matched engine=%r",
                branch.engine_id,
            )
            return FACT_REQUIRES_SESSION_FIRST

        # Session-requiring engine exhausted and no session available
        if branch.engine_id in _SESSION_REQUIRED_ENGINES and not has_session:
            return FACT_REQUIRES_SESSION_FIRST

    return None
