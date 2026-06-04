"""Phase 4 — Leaf evaluation: terminal vs blocked/dummy, stem extraction.

When a branch returns a result (a leaf is reached), the orchestrator must ask:
  - TERMINAL: reaching it IS the win → stop (don't over-reach).
  - BLOCKED: not the real win → there's a layer behind it (grow the stem).
  - NONE_YET: stem exists but no engine → record the gap, continue.
  - INCONCLUSIVE: cannot determine from available knowledge.

Classification is RAG-driven (reads concept leaf_type + stem knowledge from the
Phase-0 graph), NOT a new hard-coded switch. The existing _is_solved fast-path is
retained for clear terminal wins.

Stem engines are read from the concept's "Engine support: EXISTS" lines (parsed by
graph_resolver). When a BLOCKED leaf has EXISTS stem engines, the orchestrator queues
those engines as the next steps (bypassing normal precondition gating — the concept
knowledge guarantees appropriateness).

NONE-YET stems are RECORDED (honest engine-gap) but NOT dispatched.
TERMINAL leaves grow NO stems (anti-over-reach guard).
"""
from __future__ import annotations

import logging
import yaml
from dataclasses import dataclass, field

logger = logging.getLogger("conductor.leaf_evaluator")


@dataclass
class LeafClassification:
    """Result of evaluating one branch leaf."""
    kind:           str             # "terminal" | "blocked" | "none_yet" | "inconclusive"
    concept_id:     str             # which concept produced this leaf
    reason:         str             # human-readable explanation
    stem_engines:   list[dict]      # stem steps to queue (EXISTS only)
    none_yet_gaps:  list[dict]      # stem steps that are NONE-YET (logged, not dispatched)


@dataclass
class Verdict:
    """Result of evaluating a branch result against vault concept knowledge."""
    match_kind:         str          # "known" | "no_concept_match"
    goal_advanced:      bool
    state_changes:      list         # fact labels from vault
    artifacts_captured: dict         # {bucket: <real_object>} mapped from vault + result
    unlocks:            list         # [{concept, priority}] from vault
    rules_out:          list         # concept ids from vault


def evaluate_leaf(
    engine_id:      str,
    concept_id:     str,
    artifact:       "dict | None",
    state:          str,            # "succeeded" | "exhausted" | "failed" | "timeout"
    finding_id:     str = "",
) -> LeafClassification:
    """Classify a branch leaf as TERMINAL, BLOCKED, NONE_YET, or INCONCLUSIVE.

    Step 1 — deterministic fast path:
      _is_solved(artifact) → TERMINAL immediately (clear win, no RAG call needed).

    Step 2 — RAG-backed classification via concept knowledge:
      - Read concept's leaf_type from the Phase-0 graph.
      - "terminal" → TERMINAL (even if _is_solved returned False, the concept says
        this is the end of the branch — no stem warranted).
      - "can_be_blocked" + state in ("exhausted", "timeout") → BLOCKED.
        Grow the stem if stem engines exist (EXISTS → queue; NONE-YET → record gap).
      - "unknown" or anything else → INCONCLUSIVE.

    Never raises. Returns INCONCLUSIVE on any error.
    """
    try:
        return _evaluate(engine_id, concept_id, artifact, state, finding_id)
    except Exception as exc:
        logger.debug("leaf_evaluator: failed for %s/%s: %s", concept_id, engine_id, exc)
        return LeafClassification(
            kind="inconclusive", concept_id=concept_id,
            reason=f"evaluation error: {exc}", stem_engines=[], none_yet_gaps=[],
        )


def _evaluate(
    engine_id:  str,
    concept_id: str,
    artifact:   "dict | None",
    state:      str,
    finding_id: str,
) -> LeafClassification:
    from apps.conductor.autonomous_orchestrator import _is_solved

    # ── Fast path: deterministic terminal win ─────────────────────────────────
    if _is_solved(artifact, engine_id):
        return LeafClassification(
            kind="terminal", concept_id=concept_id,
            reason=f"_is_solved returned True for {engine_id} ({state})",
            stem_engines=[], none_yet_gaps=[],
        )

    # ── RAG path: concept-driven classification ───────────────────────────────
    branch_spec = None
    if concept_id:
        try:
            from apps.conductor.graph_resolver import get_branch_by_concept
            branch_spec = get_branch_by_concept(concept_id)
        except Exception as exc:
            logger.debug("leaf_evaluator: graph_resolver lookup failed: %s", exc)

    if branch_spec is None:
        # No concept knowledge — inconclusive (don't guess)
        return LeafClassification(
            kind="inconclusive", concept_id=concept_id,
            reason=f"concept {concept_id!r} not found in vault",
            stem_engines=[], none_yet_gaps=[],
        )

    leaf_type = branch_spec.leaf_type   # "terminal" | "can_be_blocked" | "unknown"

    # ── Concept says terminal ─────────────────────────────────────────────────
    if leaf_type == "terminal":
        return LeafClassification(
            kind="terminal", concept_id=concept_id,
            reason=f"concept {concept_id!r} leaf_type=terminal — no stem warranted",
            stem_engines=[], none_yet_gaps=[],
        )

    # ── Concept says can_be_blocked + branch exhausted ────────────────────────
    if leaf_type == "can_be_blocked" and state in ("exhausted", "timeout", "failed"):
        exists_steps  = [s for s in branch_spec.stem_engines if s.get("engine_exists")]
        none_yet_steps = [s for s in branch_spec.stem_engines if not s.get("engine_exists")]

        if exists_steps:
            logger.info(
                "leaf_evaluator: BLOCKED — concept=%r engine=%r state=%r stem_steps=%d",
                concept_id, engine_id, state, len(exists_steps),
            )
            return LeafClassification(
                kind="blocked", concept_id=concept_id,
                reason=(
                    f"concept {concept_id!r} leaf_type=can_be_blocked; "
                    f"branch state={state!r}; stem has {len(exists_steps)} EXISTS engine step(s)"
                ),
                stem_engines=exists_steps,
                none_yet_gaps=none_yet_steps,
            )
        elif none_yet_steps:
            logger.info(
                "leaf_evaluator: NONE_YET — concept=%r engine=%r; stem known but no engine",
                concept_id, engine_id,
            )
            return LeafClassification(
                kind="none_yet", concept_id=concept_id,
                reason=(
                    f"concept {concept_id!r} leaf_type=can_be_blocked; "
                    f"stem is documented but ALL engines are NONE-YET (engine-gap)"
                ),
                stem_engines=[],
                none_yet_gaps=none_yet_steps,
            )
        else:
            # can_be_blocked but no stem documented
            return LeafClassification(
                kind="inconclusive", concept_id=concept_id,
                reason=(
                    f"concept {concept_id!r} leaf_type=can_be_blocked; "
                    f"no stem engines documented — cannot grow stem"
                ),
                stem_engines=[], none_yet_gaps=[],
            )

    # ── Succeeded but not _is_solved ──────────────────────────────────────────
    # e.g. captured_session that is a setup step, not the objective
    if state == "succeeded" and leaf_type == "can_be_blocked":
        # A succeeded result on a can_be_blocked concept may mean the bypass worked
        # but the account is locked (the session is for setup, not win).
        # Treat as blocked: grow the stem.
        exists_steps  = [s for s in branch_spec.stem_engines if s.get("engine_exists")]
        none_yet_steps = [s for s in branch_spec.stem_engines if not s.get("engine_exists")]
        if exists_steps:
            logger.info(
                "leaf_evaluator: BLOCKED (succeeded but not terminal) — concept=%r stem=%d steps",
                concept_id, len(exists_steps),
            )
            return LeafClassification(
                kind="blocked", concept_id=concept_id,
                reason=(
                    f"concept {concept_id!r} leaf_type=can_be_blocked; "
                    f"succeeded but result is a setup step — growing stem"
                ),
                stem_engines=exists_steps,
                none_yet_gaps=none_yet_steps,
            )

    # ── Fallback ──────────────────────────────────────────────────────────────
    return LeafClassification(
        kind="inconclusive", concept_id=concept_id,
        reason=f"leaf_type={leaf_type!r} state={state!r} — no classification rule matched",
        stem_engines=[], none_yet_gaps=[],
    )


def build_stem_work_orders(
    leaf_eval:      LeafClassification,
    finding_id:     str,
    target_account: str = "",
) -> list[dict]:
    """Convert a BLOCKED LeafClassification into a list of stem work-order seed dicts.

    Returns [{engine_id, primitive_id, strategy, params, rationale, source}]
    for injection into the autonomous loop's stem_queue.
    """
    if leaf_eval.kind != "blocked" or not leaf_eval.stem_engines:
        return []

    steps: list[dict] = []
    for step in leaf_eval.stem_engines:
        eid   = step.get("engine_id", "")
        pid   = step.get("primitive_id", eid)
        strat = step.get("strategy", "")
        if not eid:
            continue

        params: dict = {}
        if strat:
            params["strategy"] = strat
        # Carry the parent concept_id so the stem engine knows which template to use
        params["concept_id"] = leaf_eval.concept_id
        if target_account:
            params["target_account"] = target_account

        steps.append({
            "engine_id":    eid,
            "primitive_id": pid,
            "params":       params,
            "rationale":    f"Stem: {step.get('rationale', strat or eid)} (blocked leaf: {leaf_eval.concept_id})",
            "source":       "stem",
            "finding_id":   finding_id,
        })
    return steps


def _load_concept_agent_fields(concept_id: str) -> dict:
    """Read state_changes/artifacts_captured/unlocks/rules_out from a concept .md file.

    Uses yaml.safe_load on the frontmatter block.  Returns {} if not found/parseable.
    Never raises.
    """
    import os
    from pathlib import Path
    vault_path = Path(os.environ.get("KNOWLEDGE_VAULT_PATH", "/app/knowledge-vault"))
    # concept_id like "CONCEPT-CREDENTIAL-BRUTE" -> "concept-credential-brute"
    filename = concept_id.lower().replace("_", "-") + ".md"
    filepath = vault_path / "concepts" / filename
    if not filepath.exists():
        logger.debug("_load_concept_agent_fields: %s not found", filepath)
        return {}
    try:
        text = filepath.read_text(encoding="utf-8")
        if not text.startswith("---"):
            return {}
        end = text.find("\n---", 3)
        if end == -1:
            return {}
        fm_block = text[3:end]
        fm = yaml.safe_load(fm_block) or {}
        return {
            "state_changes":      fm.get("state_changes", []),
            "artifacts_captured": fm.get("artifacts_captured", []),
            "unlocks":            fm.get("unlocks", []),
            "rules_out":          fm.get("rules_out", []),
        }
    except Exception as exc:
        logger.debug("_load_concept_agent_fields: parse error for %s: %s", concept_id, exc)
        return {}


def evaluate_verdict(
    engine_id:  str,
    concept_id: str,
    artifact:   "dict | None",
    state:      str,
    finding_id: str = "",
) -> "Verdict":
    """Evaluate a branch result and produce a structured VERDICT.

    KNOWN   — concept found in vault → emit verdict with state_changes/unlocks/etc.
    UNKNOWN — no concept match → return no_concept_match marker (logged only).

    Does NOT apply the verdict to STATE (Phase C wire).  Safe to call alongside
    existing orchestrator flow — read-only with respect to all execution state.
    Never raises.
    """
    try:
        return _evaluate_verdict(engine_id, concept_id, artifact, state, finding_id)
    except Exception as exc:
        logger.debug("evaluate_verdict: failed for %s/%s: %s", concept_id, engine_id, exc)
        return Verdict(
            match_kind="no_concept_match",
            goal_advanced=False,
            state_changes=[], artifacts_captured={}, unlocks=[], rules_out=[],
        )


def _evaluate_verdict(
    engine_id:  str,
    concept_id: str,
    artifact:   "dict | None",
    state:      str,
    finding_id: str,
) -> "Verdict":
    if not concept_id:
        logger.debug("evaluate_verdict: no concept_id — no_concept_match")
        return Verdict(
            match_kind="no_concept_match",
            goal_advanced=False,
            state_changes=[], artifacts_captured={}, unlocks=[], rules_out=[],
        )

    fields = _load_concept_agent_fields(concept_id)
    if not fields:
        logger.debug("evaluate_verdict: concept %r not in vault — no_concept_match", concept_id)
        return Verdict(
            match_kind="no_concept_match",
            goal_advanced=False,
            state_changes=[], artifacts_captured={}, unlocks=[], rules_out=[],
        )

    # Map captured objects into artifact buckets
    artifacts_captured: dict = {}
    vault_buckets: list = fields.get("artifacts_captured", []) or []
    if artifact and vault_buckets:
        for bucket in vault_buckets:
            if bucket in ("credentials", "sessions", "tokens", "files"):
                artifacts_captured[bucket] = artifact

    goal_advanced = state == "succeeded" or bool(artifacts_captured)

    # Fix 3 — Couple credential-related facts to artifact landing.
    # If no credential artifact was captured (artifacts_captured is empty), do NOT emit
    # "credential_obtained" or "session_authenticated" into STATE facts.  Without a
    # classifiable artifact object, the fact is unverifiable and creates a "fact without
    # artifact" inconsistency that triggers the fact-fallback false-positive (now closed
    # by Fix 2).  Both the fact AND the artifact must arrive together for a real capture.
    _CREDENTIAL_FACTS = frozenset({"credential_obtained", "session_authenticated"})
    _has_cred_artifact = bool(artifacts_captured)
    _filtered_state_changes = [
        f for f in (fields.get("state_changes", []) or [])
        if f not in _CREDENTIAL_FACTS or _has_cred_artifact
    ]

    verdict = Verdict(
        match_kind="known",
        goal_advanced=goal_advanced,
        state_changes=_filtered_state_changes,
        artifacts_captured=artifacts_captured,
        unlocks=list(fields.get("unlocks", []) or []),
        rules_out=list(fields.get("rules_out", []) or []),
    )
    logger.info(
        "evaluate_verdict: KNOWN concept=%r engine=%r state=%r "
        "goal_advanced=%s state_changes=%r unlocks=%d",
        concept_id, engine_id, state,
        verdict.goal_advanced, verdict.state_changes, len(verdict.unlocks),
    )
    return verdict
