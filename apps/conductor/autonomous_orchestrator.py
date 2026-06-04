"""Autonomous Solve Loop — driven by plan_next_step() (single selection authority).

OPT-IN mode: the operator confirms ONCE; the loop selects → executes → assesses →
repeats, walking all applicable paths until solved or exhausted.

Selection authority: plan_next_step() from apps.conductor.planner — the ONE engine
selector for both the /planner/run path and this autonomous path.  agent_state must be
initialized via /planner/run before calling run_autonomous().  If agent_state is absent,
the loop FAILS CLOSED (reason="park") with a clear operator-facing message.

FOUR hard termination conditions (ALL implemented; loop cannot run forever):
  1. SOLVED      — win condition detected in the result artifact.
  2. BUDGET      — max_attempts / max_requests / max_wall_clock_s exceeded.
  3. NO_PROGRESS — N consecutive executions that produced no new finding.
  4. OPERATOR_STOPPED — stop flag set in InvestigationState.

C6 boundary: the single operator confirmation at run_autonomous() call time.
The STOP control allows the operator to halt before the next dispatch at any time.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger("conductor.autonomous_orchestrator")

# Module-level imports so tests can patch these by name.
# Each has a sentinel fallback so the attribute always exists even when
# the underlying module is unavailable (e.g. aiosqlite absent on host).

async def _sentinel_async(*_a, **_k):
    raise NotImplementedError("import failed — only available inside Docker")

try:
    from apps.conductor.investigation_state import load_state_async, save_state_async
except ImportError:
    load_state_async = _sentinel_async  # type: ignore[assignment]
    save_state_async = _sentinel_async  # type: ignore[assignment]

# generate_work_order / package_findings_context removed — plan_next_step() is now the
# sole selection authority on ALL paths (autonomous loop + context panel).
# generate_work_order exists only in model_advisor.py and is not called from any
# selection path in this codebase.

try:
    from apps.conductor.result_parser import parse_engine_result
except ImportError:
    parse_engine_result = None  # type: ignore[assignment]

try:
    from apps.validation.database import get_db
except ImportError:
    get_db = _sentinel_async  # type: ignore[assignment]

# ── Module-level running task registry ────────────────────────────────────────
# Maps investigation_id → asyncio.Task so the stop endpoint can cancel if needed.
_running_tasks: dict[str, asyncio.Task] = {}


# ── Config / Budget ───────────────────────────────────────────────────────────

@dataclass
class AutonomousBudget:
    """Hard caps for the autonomous loop.

    Defaults chosen to be safe on a real lab:
    - 12 attempts is more than enough for a 3-step exploit chain (recon→enum→exploit)
    - 600 total engine requests matches the oracle_search cap per run
    - 12 minutes wall clock prevents forgetting a run is live
    """
    max_attempts:     int   = 12
    max_requests:     int   = 600    # aggregated across all engine invocations
    max_wall_clock_s: float = 720.0  # 12 minutes
    no_progress_limit: int  = 3      # consecutive no-new-finding iterations before stop
    max_parallel:     int   = 2      # Part B: max concurrent independent work orders per batch


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class LoopStop:
    """Reason the autonomous loop stopped."""
    reason:   str         # "solved"|"budget"|"no_progress"|"no_path"|"operator_stopped"|"error"
    partial:  bool = False
    outcome:  str  = ""   # human-readable summary
    walk:     list[dict] = field(default_factory=list)   # {attempt, primitive, rationale, result}


# ── Work-order signature ───────────────────────────────────────────────────────

def _signature(primitive_id: str, params: dict) -> str:
    """Stable dedup key for a work order (primitive + sorted params)."""
    sorted_params = json.dumps(dict(sorted(params.items())), sort_keys=True)
    return f"{primitive_id}:{sorted_params}"


# ── Solved detection ──────────────────────────────────────────────────────────

def _is_solved(artifact: dict | None, engine_id: str) -> bool:
    """Generic win-condition detector over a branch artifact.

    Win condition (any of):
    - oracle_extraction_confirmed with incomplete=False  (field value fully extracted)
    - oracle_enumeration_confirmed (fields discovered — partial win; loop continues to extract)
    - credentials_obtained                               (auth captured)
    - access_control_confirmed with response_excerpt containing success signal

    NOTE: For the NoSQL extract-data lab, "solved" = extraction complete + value present.
    We do NOT check the PortSwigger "Congratulations" banner here; that requires a browser.
    The operator uses the extracted value to complete the final login.
    """
    if not artifact:
        return False
    inner = artifact.get("artifact", artifact)
    if not isinstance(inner, dict):
        return False

    atype = inner.get("artifact_type", "")

    if atype == "oracle_extraction_result":
        # Solved when extraction is complete and a value is present
        return (
            not inner.get("incomplete", True)
            and bool(inner.get("extracted_value", ""))
        )

    if atype == "captured_session":
        # A captured session means auth succeeded — the objective depends on what the
        # session is FOR. If the objective is "log in as X" and we captured a session
        # as a DIFFERENT user (bypass login), this is a precondition not a solve.
        # Only treat it as solved when the session user matches the objective account.
        # For now: captured_session is a setup step, not the terminal win condition.
        # The real win is oracle_extraction_result (token or password extracted).
        return False   # was True — changed: session capture is a setup, not a solve

    if atype == "credentials_obtained":
        return False   # same reasoning: credentials are a setup step

    # Auth bypass result with locked account signal = setup, not solved
    if atype == "auth_bypass_result":
        return False

    return False


# ── Independence check (Part B) ──────────────────────────────────────────────

# Work orders that explicitly DEPEND on the output of another (must stay sequential).
# A dependent pair: dictionary_scan must complete before binary_search uses its result.
_DEPENDENT_ON: dict[str, str] = {
    "oracle_search.binary_search": "oracle_search.dictionary_scan",
}


def _is_independent(wo_primitive_id: str, batch_primitives: set[str]) -> bool:
    """Return False if wo_primitive_id depends on any primitive already in the batch."""
    dep = _DEPENDENT_ON.get(wo_primitive_id)
    return dep not in batch_primitives if dep else True


# ── Oracle-strategy exhaustion helper ────────────────────────────────────────

async def _read_branch_exhaustion(
    investigation_id: str, engine_id: str, finding_id: str
) -> dict:
    """Read the exhaustion record from the most recent exhausted branch.

    Returns the parsed exhaustion_record dict (may contain oracle_strategy,
    no_signal_found, etc.) or {} when not found / parsing fails.
    """
    try:
        from apps.validation.database import get_db
        async with get_db() as db:
            cur = await db.execute(
                """SELECT stage_log FROM exploitation_branches
                   WHERE investigation_id=? AND engine_id=? AND finding_id=?
                     AND state='exhausted'
                   ORDER BY updated_at DESC LIMIT 1""",
                (investigation_id, engine_id, finding_id),
            )
            row = await cur.fetchone()
        if not row or not row[0]:
            return {}
        log_data = json.loads(row[0]) if isinstance(row[0], str) else row[0]
        if not isinstance(log_data, list):
            return {}
        for entry in reversed(log_data):
            if entry.get("state") == "exhausted":
                raw = entry.get("exhaustion_record", "")
                if raw:
                    return json.loads(raw) if isinstance(raw, str) else raw
    except Exception as _e:
        logger.debug("autonomous: _read_branch_exhaustion failed: %s", _e)
    return {}


# ── Execute one work order ────────────────────────────────────────────────────

async def execute_work_order(
    investigation_id: str,
    finding_id: str,
    engine_id: str,
    params: dict,
    target: str,
) -> tuple[str, dict | None]:
    """Dispatch one engine with the work order's params; poll to terminal state.

    Returns (state: str, artifact: dict | None).
    state is "succeeded" | "exhausted" | "failed" | "timeout" | "error".

    Uses the SAME dispatch_engine path that execute_suggestion calls — the autonomous
    loop bypasses the per-step card click but not the conductor dispatch machinery.
    """
    try:
        return await _execute(investigation_id, finding_id, engine_id, params, target)
    except Exception as exc:
        logger.warning("execute_work_order failed: %s", exc)
        return "error", None


async def _execute(
    investigation_id: str,
    finding_id: str,
    engine_id: str,
    params: dict,
    target: str,
) -> tuple[str, dict | None]:
    from apps.conductor.conductor import _InvestigationContext
    from apps.conductor.shared import get_shared_conductor
    from apps.validation.database import get_db

    conductor = get_shared_conductor()
    ctx = conductor.get_context(investigation_id)

    # ── DIAGNOSTIC INSTRUMENTATION (log-only, no logic change) ───────────────
    import time as _diag_time
    _diag_ts = _diag_time.monotonic()
    _ctx_exists = ctx is not None
    _exec_id_before = id(ctx.exec_orch) if ctx else None
    _cancelled_before = getattr(ctx.exec_orch, "_cancelled", None) if ctx else None
    _running_before   = list(getattr(ctx.exec_orch, "_running", {}).keys()) if ctx else []
    logger.info(
        "DIAG execute_work_order [ORCHESTRATOR PATH] inv=%s engine=%s finding=%s | "
        "ctx_exists=%s exec_id=%s executor_cancelled=%s running_keys=%s",
        investigation_id, engine_id, finding_id,
        _ctx_exists, _exec_id_before, _cancelled_before, _running_before,
    )
    # ── END DIAGNOSTIC ────────────────────────────────────────────────────────

    # If the executor is cancelled (investigation phase transition, delete, etc.),
    # treat it like a missing context and reconstruct with a fresh executor.
    # Root-cause: when autonomous dispatch fires during an active recon/enum phase,
    # the phase orchestrator may have already cancelled the executor.  The cancelled
    # exec_orch.dispatch_engine() returns silently without launching (self._cancelled=True).
    _needs_reconstruction = (ctx is None) or getattr(ctx.exec_orch, "_cancelled", False)

    if _needs_reconstruction:
        _reason = "context_absent" if ctx is None else "executor_cancelled"
        logger.info(
            "autonomous: reconstructing context for %s (%s)",
            investigation_id, _reason,
        )
        recon_config: dict = {}
        try:
            row = conductor._db.execute(
                "SELECT config_json FROM investigations WHERE id=?",
                (investigation_id,),
            ).fetchone()
            if row and row[0]:
                recon_config = json.loads(row[0])
        except Exception:
            pass
        ctx = _InvestigationContext(
            investigation_id=investigation_id,
            target=target,
            config=recon_config,
            bus=conductor._bus,
            db_path=conductor._db_path,
        )
        conductor._active[investigation_id] = ctx
        await ctx.exec_orch.start_health_monitor()
        try:
            from apps.conductor.session_persistence import rehydrate_session
            rehydrated = await rehydrate_session(ctx.session_orch, investigation_id)
            logger.info("autonomous: context reconstructed for %s (session_rehydrated=%s)",
                        investigation_id, rehydrated)
        except Exception as _reh_exc:
            logger.debug("autonomous: session rehydration failed (non-fatal): %s", _reh_exc)

    # ── DIAGNOSTIC: executor state after possible reconstruction ─────────────
    _reconstructed = _needs_reconstruction
    _exec_id_after  = id(ctx.exec_orch)
    _cancelled_after = getattr(ctx.exec_orch, "_cancelled", None)
    _running_after   = list(getattr(ctx.exec_orch, "_running", {}).keys())
    logger.info(
        "DIAG execute_work_order [PRE-DISPATCH] inv=%s engine=%s | "
        "reconstruction_fired=%s exec_id_changed=%s executor_cancelled=%s running_keys=%s",
        investigation_id, engine_id,
        _reconstructed, (_exec_id_after != _exec_id_before),
        _cancelled_after, _running_after,
    )
    # ── END DIAGNOSTIC ────────────────────────────────────────────────────────

    extra_config = dict(params)
    extra_config["correlation_id"] = finding_id
    _running_before_dispatch = set(ctx.exec_orch._running.keys())
    await ctx.exec_orch.dispatch_engine(
        engine_id,
        correlation_id=finding_id,
        extra_config=extra_config,
    )
    _running_after_dispatch  = set(ctx.exec_orch._running.keys())
    _new_run_ids = _running_after_dispatch - _running_before_dispatch
    logger.info(
        "autonomous: dispatched %s for %s/%s params=%r",
        engine_id, investigation_id, finding_id, params,
    )
    # ── DIAGNOSTIC: did _launch fire? ────────────────────────────────────────
    logger.info(
        "DIAG execute_work_order [POST-DISPATCH] inv=%s engine=%s | "
        "launch_fired=%s new_run_ids=%s executor_cancelled_after=%s",
        investigation_id, engine_id,
        bool(_new_run_ids), list(_new_run_ids),
        getattr(ctx.exec_orch, "_cancelled", None),
    )
    # ── END DIAGNOSTIC ────────────────────────────────────────────────────────

    # Poll exploitation_branches for terminal state.
    # Timeout: 900s (15 min) to cover sequential timing-oracle escalation.
    # Sequential timing (the correct approach for timing measurement, proven on live lab)
    # requires ~228s per escalation level × up to 3 levels = ~700s + Phase 2 brute.
    # 900s provides headroom for all three sequential levels and Phase 2.
    # Effect on other engines: none — credential_brute / js_spider / etc. complete in
    # <120s and the polling loop exits on terminal state, not the deadline.
    # Fail-fast: after 60s with no branch row, check the executor's _running dict.
    # If the engine is not there, the dispatch was silently swallowed (still-cancelled
    # executor race) — fail immediately rather than burning 15 minutes.
    deadline = time.monotonic() + 900.0
    _branch_check_start = time.monotonic()
    async with get_db() as db:
        while time.monotonic() < deadline:
            await asyncio.sleep(5)
            cur = await db.execute(
                """SELECT state, artifact
                   FROM exploitation_branches
                   WHERE investigation_id=? AND engine_id=? AND finding_id=?
                   ORDER BY updated_at DESC LIMIT 1""",
                (investigation_id, engine_id, finding_id),
            )
            row = await cur.fetchone()
            if row and row[0] in ("succeeded", "exhausted", "failed"):
                state = row[0]
                artifact = None
                if row[1]:
                    try:
                        artifact = json.loads(row[1]) if isinstance(row[1], str) else row[1]
                    except Exception:
                        pass
                logger.info(
                    "autonomous: %s finished state=%r for %s",
                    engine_id, state, investigation_id,
                )
                return state, artifact

            # Fail-fast: if 60s elapsed and no branch row yet, the engine likely
            # never started (cancelled executor race). Detect and bail out early.
            if not row and time.monotonic() - _branch_check_start > 60.0:
                engine_in_running = any(
                    r.engine_id == engine_id
                    for r in ctx.exec_orch._running.values()
                )
                if not engine_in_running:
                    logger.error(
                        "autonomous: %s dispatch silently failed for %s — "
                        "no branch after 60s and not in executor._running. "
                        "Executor cancelled=%s. Failing fast.",
                        engine_id, investigation_id,
                        getattr(ctx.exec_orch, "_cancelled", "?"),
                    )
                    return "error", None

    logger.warning("autonomous: %s timed out polling for %s", engine_id, investigation_id)
    return "timeout", None


# ── Main loop ─────────────────────────────────────────────────────────────────

# ── Finding discovery for whole-tree traversal ───────────────────────────────

async def _discover_all_findings(investigation_id: str) -> dict[str, dict]:
    """Load all normalized findings for an investigation from DB.

    Returns {finding_id: {type, title, endpoint}} for ALL findings.
    The whole-tree orchestrator iterates over all of these, not just one.
    """
    try:
        async with get_db() as db:
            cur = await db.execute(
                "SELECT finding_id, finding_type, title, endpoint "
                "FROM normalized_findings WHERE investigation_id=?",
                (investigation_id,),
            )
            rows = await cur.fetchall()
        return {
            row[0]: {
                "type":     row[1] or "",
                "title":    row[2] or "",
                "endpoint": row[3] or "",
            }
            for row in rows if row[0]
        }
    except Exception as exc:
        logger.debug("autonomous: _discover_all_findings failed: %s", exc)
        return {}


def _build_gap_report(
    workable_findings: dict,
    tried: set[str],
    exhausted_fids: "set[str]",
) -> str:
    """Build human-readable explanation of what blocked further progress.

    Used for the TREE_EXHAUSTED terminal state so the operator knows:
    - How many findings were worked
    - Which engines ran
    - What finding-types are in the tree (so they know what was covered)
    """
    tried_engines = sorted({sig.split(":")[0] for sig in tried if ":" in sig})
    finding_types = sorted({meta.get("type", "?") for meta in workable_findings.values()})
    exhausted_count = len(exhausted_fids)
    total_count = len(workable_findings)
    return (
        f"Tree exhausted: worked {exhausted_count}/{total_count} finding(s) "
        f"({', '.join(finding_types)}). "
        f"Engines tried: [{', '.join(tried_engines) or 'none'}]. "
        f"Check NONE-YET engine-gaps and FUTURE finding-type enum-gaps for remaining paths."
    )


async def run_autonomous(
    investigation_id: str,
    finding_id: str = "",               # legacy compat — used as seed when finding_ids absent
    target: str = "",
    budget: AutonomousBudget | None = None,
    seeded_batch: "list[dict] | None" = None,
    finding_ids: "list[str] | None" = None,   # Phase 3: multi-finding tree
    operator_params: "dict | None" = None,    # Workstream A: threaded into planner selection
) -> LoopStop:
    """Phase 3 — Whole-tree autonomous orchestrator.

    Works ALL executable branches of ALL findings before concluding.

    Changes from Phase 1/2:
    - Multi-finding: iterates over all investigation findings (not one focus finding).
    - Relentless: NO_PROGRESS fires only when the whole workable tree is exhausted,
      not after N dead attempts when untried branches remain.
    - Cross-finding: when a branch produces new findings (e.g. js_spider →
      api_endpoint_discovered), those findings' branches join the workable tree.
    - New terminal: TREE_EXHAUSTED (all executable branches tried) reports the
      NONE-YET and FUTURE gaps that blocked further progress.
    - Operator-seeded step 1 still takes precedence (Layer 2 contract, unchanged).

    finding_ids: explicit list of finding_ids to start from. If None, auto-discovers
    all findings from DB. finding_id (legacy) is added to the set when provided.
    """
    if budget is None:
        budget = AutonomousBudget()

    _op_params: dict = dict(operator_params or {})  # Workstream A: planner param source

    walk: list[dict] = []
    tried:   set[str] = set()
    attempt: int      = 0
    start_time = time.monotonic()
    _seed_pending = bool(seeded_batch)

    # ── Initialise the workable finding set ──────────────────────────────────
    # Phase 3: start with ALL findings (or the provided list + any legacy single finding).
    workable_findings: dict[str, dict] = {}

    _initial_fids: list[str] = list(finding_ids or [])
    if finding_id and finding_id not in _initial_fids:
        _initial_fids.append(finding_id)

    if _initial_fids:
        # Populate metadata from DB for provided finding_ids
        try:
            async with get_db() as db:
                for fid in _initial_fids:
                    cur = await db.execute(
                        "SELECT finding_type, title, endpoint FROM normalized_findings WHERE finding_id=?",
                        (fid,),
                    )
                    frow = await cur.fetchone()
                    workable_findings[fid] = {
                        "type":     (frow[0] if frow else "") or "",
                        "title":    (frow[1] if frow else "") or "",
                        "endpoint": (frow[2] if frow else "") or "",
                    }
        except Exception as exc:
            logger.debug("autonomous: initial finding lookup failed: %s", exc)
            for fid in _initial_fids:
                workable_findings.setdefault(fid, {"type": "", "title": "", "endpoint": ""})
    else:
        # Auto-discover all investigation findings
        workable_findings = await _discover_all_findings(investigation_id)

    # exhausted_fids: findings where generate_work_order returned None with the current
    # tried set. Reset after any successful result (preconditions may open new branches).
    exhausted_fids: set[str] = set()

    # Phase 4: Stem queue — work orders injected by leaf evaluation for BLOCKED leaves.
    # These are tried BEFORE AI-generated work orders in each iteration, allowing the
    # orchestrator to clear a blocked leaf via its stem engines (e.g. keys_enumeration
    # → where_extract after "Account locked" signal on nosql-operator-injection).
    import collections as _collections
    stem_queue: "collections.deque" = _collections.deque()

    # Mark running
    state = await load_state_async(investigation_id)
    state.autonomous_status  = "running"
    state.autonomous_run_log = []
    await save_state_async(state)

    def _elapsed() -> float:
        return time.monotonic() - start_time

    async def _persist_log(entry: dict) -> None:
        s = await load_state_async(investigation_id)
        s.autonomous_run_log = list(walk)
        s.autonomous_status  = "running"
        await save_state_async(s)

    async def _terminate(reason: str, partial: bool = False, outcome: str = "") -> LoopStop:
        s = await load_state_async(investigation_id)
        s.autonomous_status  = reason
        s.autonomous_run_log = list(walk)
        await save_state_async(s)
        if investigation_id in _running_tasks:
            del _running_tasks[investigation_id]
        logger.info(
            "autonomous: STOP reason=%r attempt=%d elapsed=%.0fs findings=%d",
            reason, attempt, _elapsed(), len(workable_findings),
        )
        return LoopStop(reason=reason, partial=partial, outcome=outcome, walk=list(walk))

    try:
        while True:
            # ── Termination checks ─────────────────────────────────────────────
            state = await load_state_async(investigation_id)

            if state.autonomous_stop_requested:
                return await _terminate("operator_stopped")

            if attempt >= budget.max_attempts:
                return await _terminate("budget", partial=True,
                                        outcome=f"Budget: {attempt} attempts reached")
            if _elapsed() >= budget.max_wall_clock_s:
                return await _terminate("budget", partial=True,
                                        outcome=f"Budget: wall clock {_elapsed():.0f}s reached")

            # ── Build work order batch ────────────────────────────────────────
            batch: list = []
            reason = ""

            if _seed_pending:
                # Operator-seeded dispatch — whole-tree with prioritized first pick.
                #
                # The seeded_batch may contain a single AI-picked engine (classic case)
                # OR a comprehensive list of engine-finding pairs (chat-approve case where
                # the UI gathers all unbranched nodes and sends them all at once).
                #
                # Processing:
                #   • First seed  → batch  (runs immediately as the priority branch).
                #   • Remaining   → stem_queue (run in order after the first, before Phase 3).
                #     Each remaining seed carries its own finding_id so multiple findings
                #     are worked correctly without relying on Qwen Phase-3 generation.
                #
                # Result: the AI's pick runs first; the orchestrator then continues through
                # ALL remaining branches to tree_exhausted or solve — deterministically,
                # without depending on Qwen to re-propose them.
                _seed_pending = False
                import uuid as _uuid_mod
                try:
                    from apps.conductor.model_advisor import WorkOrder as _WorkOrder
                except ImportError:
                    _WorkOrder = None  # type: ignore[assignment]
                if _WorkOrder is not None:
                    _seed_fid = finding_id or (next(iter(workable_findings)) if workable_findings else "")
                    _all_seeds = list(seeded_batch or [])
                    for _idx, seed in enumerate(_all_seeds):
                        _eid = seed.get("engine_id", "")
                        _pid = seed.get("primitive_id", _eid)
                        _params = dict(seed.get("params") or {})
                        if seed.get("concept_id"):
                            _params.setdefault("concept_id", seed["concept_id"])
                        # Per-seed finding_id (whole-tree seeds target different findings).
                        _this_fid = seed.get("finding_id") or _seed_fid
                        _sig = _signature(_pid, _params)
                        if _sig in tried:
                            continue

                        if _idx == 0:
                            # Priority: first seed runs immediately in the current batch.
                            _wo = _WorkOrder(
                                id=str(_uuid_mod.uuid4()), primitive_id=_pid,
                                engine_id=_eid, params=_params,
                                rationale=seed.get("rationale", f"Operator selected: {_eid}"),
                                finding_id=_this_fid, source="operator",
                            )
                            batch.append(_wo)
                            tried.add(_sig)
                        else:
                            # Continuation: remaining seeds go to stem_queue so they run
                            # BEFORE Phase-3 AI generation, in deterministic order.
                            stem_queue.append({
                                "engine_id":    _eid,
                                "primitive_id": _pid,
                                "params":       _params,
                                "finding_id":   _this_fid,
                                "rationale":    seed.get("rationale", f"Operator selected: {_eid}"),
                            })
                            logger.info(
                                "autonomous: queued seed[%d] %s for %s/%s (whole-tree continuation)",
                                _idx, _eid, investigation_id, _this_fid,
                            )
                if not batch:
                    reason = "seeded_batch_empty_or_dedup"

            elif stem_queue:
                # Phase 4: Drain stem queue — BLOCKED-leaf stem steps take precedence
                # over AI-generated work orders. The stem engines are prescribed by concept
                # knowledge, not by AI selection, so they bypass precondition gating.
                import uuid as _stem_uuid
                try:
                    from apps.conductor.model_advisor import WorkOrder as _StemWorkOrder
                except ImportError:
                    _StemWorkOrder = None  # type: ignore[assignment]
                while stem_queue and len(batch) < budget.max_parallel:
                    seed = stem_queue.popleft()
                    if _StemWorkOrder is None:
                        continue
                    _eid = seed.get("engine_id", "")
                    _pid = seed.get("primitive_id", _eid)
                    _params = dict(seed.get("params") or {})
                    _fid = seed.get("finding_id", finding_id)
                    _stem_wo = _StemWorkOrder(
                        id=str(_stem_uuid.uuid4()),
                        primitive_id=_pid,
                        engine_id=_eid,
                        params=_params,
                        rationale=seed.get("rationale", f"Stem: {_eid}"),
                        finding_id=_fid,
                        source="stem",
                    )
                    _sig = _signature(_stem_wo.primitive_id, _stem_wo.params)
                    if _sig not in tried:
                        batch.append(_stem_wo)
                        tried.add(_sig)
                if not batch and not stem_queue:
                    reason = "stem_queue_empty_after_drain"

            if not batch and not _seed_pending:
                # plan_next_step() is the ONE selection authority.
                # FAIL CLOSED if agent_state is absent — no second selector.
                try:
                    from apps.conductor.planner import plan_next_step as _plan_next
                    from apps.conductor.agent_state import (
                        load_agent_state_async as _load_as,
                        save_agent_state_async as _save_as,
                    )
                    _as = await _load_as(investigation_id)
                except Exception as _ae:
                    logger.debug("autonomous: agent_state load failed: %s", _ae)
                    _as = None

                if not (_as and "goal" in _as):
                    # FAIL CLOSED: no agent_state → no selection.
                    # Surface a clear reason; operator must call /planner/run first.
                    logger.warning(
                        "autonomous: agent_state absent for %s — failing closed (park). "
                        "Call /planner/run to initialize agent_state before autonomous run.",
                        investigation_id,
                    )
                    return await _terminate(
                        "park",
                        outcome=(
                            "autonomous run requires initialized agent_state — "
                            "call /planner/run first to initialize"
                        ),
                    )

                else:
                    # Planner-driven selection — ONE authority.
                    # All existing machinery (verdict wire, leaf eval, oracle progression,
                    # unknown store) runs unchanged after this block.
                    _decision = _plan_next(_as)
                    logger.info(
                        "autonomous: planner decision action=%s concept=%r engine=%r",
                        _decision.action, _decision.concept_id, _decision.engine_id,
                    )

                    if _decision.action == "solved":
                        return await _terminate("solved", outcome=_decision.reason)

                    elif _decision.action in ("stuck",):
                        return await _terminate("tree_exhausted", outcome=_decision.reason)

                    elif _decision.action == "sweep":
                        # Planner sees candidates but all preconditions unmet —
                        # no engine can run until a prerequisite branch completes.
                        return await _terminate("tree_exhausted", outcome=_decision.reason)

                    elif _decision.action == "execute":
                        _pe_concept = _decision.concept_id
                        _pe_engine  = _decision.engine_id

                        if not _pe_engine:
                            # No engine mapped for this concept — mark done.
                            try:
                                _skip_s = await _load_as(investigation_id)
                                _skip_s.setdefault("planner_log", []).append(
                                    f"SKIP (no engine for {_pe_concept})"
                                )
                                _skip_s.setdefault("completed", [])
                                if _pe_concept not in _skip_s["completed"]:
                                    _skip_s["completed"].append(_pe_concept)
                                await _save_as(investigation_id, _skip_s)
                            except Exception as _se:
                                logger.debug("autonomous: skip-no-engine write failed: %s", _se)
                        else:
                            _pe_fid = await _find_finding_for_concept(
                                investigation_id, _pe_concept, _pe_engine
                            )
                            if _pe_fid:
                                _pe_params = _assemble_engine_params(
                                    _pe_engine, _pe_concept, _op_params, _as
                                )
                                # Workstream C: self_pass guard — counter-reset cannot run
                                # without self_pass (never stored in STATE; must come from
                                # operator_params at loop start time).
                                if (
                                    _pe_engine == "credential_brute_counter_reset"
                                    and "self_pass" not in _pe_params
                                ):
                                    _park_msg = (
                                        "PARK — credential_brute_counter_reset: "
                                        "self_pass required, not supplied"
                                    )
                                    try:
                                        _pk_s = await _load_as(investigation_id)
                                        _pk_s.setdefault("planner_log", []).append(_park_msg)
                                        await _save_as(investigation_id, _pk_s)
                                    except Exception:
                                        pass
                                    return await _terminate(
                                        "park",
                                        outcome="self_pass required, not supplied",
                                    )
                                # Dedup: if this signature was already dispatched (state
                                # hasn't updated yet via fire-and-forget verdict wire),
                                # mark the concept completed so the planner advances.
                                _pe_sig = _signature(_pe_engine, _pe_params)
                                if _pe_sig in tried:
                                    try:
                                        _dup_s = await _load_as(investigation_id)
                                        _dup_s.setdefault("planner_log", []).append(
                                            f"SKIP (dedup: {_pe_engine} already dispatched)"
                                        )
                                        _dup_s.setdefault("completed", [])
                                        if _pe_concept not in _dup_s["completed"]:
                                            _dup_s["completed"].append(_pe_concept)
                                        _dup_s["pending"] = [
                                            p for p in _dup_s.get("pending", [])
                                            if p.get("concept") != _pe_concept
                                        ]
                                        await _save_as(investigation_id, _dup_s)
                                    except Exception:
                                        pass
                                else:
                                    try:
                                        import uuid as _pu
                                        from apps.conductor.model_advisor import WorkOrder as _PWO
                                        _pw = _PWO(
                                            id=str(_pu.uuid4()),
                                            primitive_id=_pe_engine,
                                            engine_id=_pe_engine,
                                            params=_pe_params,
                                            rationale=_decision.log_entry,
                                            finding_id=_pe_fid,
                                            source="planner",
                                        )
                                        batch.append(_pw)
                                        # Write decision to planner_log → visible in Zone C
                                        try:
                                            _pl_s = await _load_as(investigation_id)
                                            _pl_s.setdefault("planner_log", []).append(
                                                _decision.log_entry
                                            )
                                            await _save_as(investigation_id, _pl_s)
                                        except Exception:
                                            pass
                                    except ImportError as _ie:
                                        logger.debug(
                                            "autonomous: WorkOrder import failed: %s", _ie
                                        )
                            else:
                                # No matching finding — mark concept done; planner advances
                                try:
                                    _nf_s = await _load_as(investigation_id)
                                    _nf_s.setdefault("planner_log", []).append(
                                        f"SKIP — no matching finding for "
                                        f"{_pe_concept}/{_pe_engine}"
                                    )
                                    _nf_s.setdefault("completed", [])
                                    if _pe_concept not in _nf_s["completed"]:
                                        _nf_s["completed"].append(_pe_concept)
                                    await _save_as(investigation_id, _nf_s)
                                except Exception as _nfe:
                                    logger.debug(
                                        "autonomous: skip-no-finding write failed: %s", _nfe
                                    )

            if not batch:
                # Phase 3: TREE_EXHAUSTED — all findings' branches are tried.
                # This replaces NO_PATH (which was "one finding has no more paths").
                # Check: are ALL workable findings now exhausted?
                if len(exhausted_fids) >= len(workable_findings) or not workable_findings:
                    gap_report = _build_gap_report(workable_findings, tried, exhausted_fids)
                    return await _terminate("tree_exhausted", outcome=gap_report)
                else:
                    # Some findings still theoretically have branches but couldn't get work orders
                    # (e.g. preconditions block all remaining branches). Report as exhausted.
                    gap_report = _build_gap_report(workable_findings, tried, exhausted_fids)
                    return await _terminate("tree_exhausted", outcome=gap_report)

            # Dedup: register batch signatures atomically before dispatch.
            for b in batch:
                sig = _signature(b.primitive_id, b.params)
                if sig not in tried:
                    tried.add(sig)
            attempt += len(batch)

            # Create log entries
            batch_logs: list[dict] = []
            for i, b_wo in enumerate(batch):
                entry = {
                    "attempt":        attempt - len(batch) + i + 1,
                    "primitive_id":   b_wo.primitive_id,
                    "engine_id":      b_wo.engine_id,
                    "rationale":      b_wo.rationale,
                    "params":         b_wo.params,
                    "result_state":   "running",
                    "result_summary": "",
                    "solved":         False,
                    "parallel_batch": len(batch) > 1,
                    "source":         getattr(b_wo, "source", "ai"),
                    "finding_id":     getattr(b_wo, "finding_id", finding_id),
                }
                walk.append(entry)
                batch_logs.append(entry)
            await _persist_log(batch_logs[-1])

            # ── Execute batch concurrently ────────────────────────────────────
            sem = asyncio.Semaphore(budget.max_parallel)
            solved_event = asyncio.Event()

            async def _exec_one(b_wo, log_e):
                async with sem:
                    if solved_event.is_set():
                        log_e["result_state"] = "cancelled"
                        return log_e, "cancelled", None
                    exec_st, art = await execute_work_order(
                        investigation_id = investigation_id,
                        finding_id       = getattr(b_wo, "finding_id", finding_id) or finding_id,
                        engine_id        = b_wo.engine_id,
                        params           = b_wo.params,
                        target           = target,
                    )
                    return log_e, exec_st, art

            tasks = [
                asyncio.create_task(_exec_one(b_wo, log_e))
                for b_wo, log_e in zip(batch, batch_logs)
            ]

            batch_solved = False
            batch_any_finding = False
            solve_outcome = ""
            batch_results: list[tuple] = []

            for coro in asyncio.as_completed(tasks):
                log_e, exec_st, art = await coro
                batch_results.append((log_e, exec_st, art))

                art_inner = (art or {}).get("artifact", art or {}) if art else {}
                parsed = parse_engine_result(
                    engine_id         = log_e["engine_id"],
                    artifact          = art_inner if isinstance(art_inner, dict) else {},
                    exhaustion_record = None,
                    state             = exec_st,
                )
                log_e["result_state"]   = exec_st
                log_e["result_summary"] = parsed.summary

                if _is_solved(art, log_e["engine_id"]):
                    log_e["solved"] = True
                    solved_event.set()
                    inner = (art or {}).get("artifact", art or {})
                    ev = inner.get("extracted_value", "") if isinstance(inner, dict) else ""
                    solve_outcome = f"Extracted value: {ev!r}" if ev else "Win condition met"
                    batch_solved = True

                if parsed.status in ("success", "partial"):
                    batch_any_finding = True

            if batch_solved:
                for t in tasks:
                    t.cancel()
                await _persist_log(walk[-1])
                return await _terminate("solved", outcome=solve_outcome)

            # Phase 4: Leaf evaluation — classify each result as TERMINAL/BLOCKED/NONE_YET.
            # BLOCKED leaves with EXISTS stem engines grow the stem (stem_queue injection).
            # NONE-YET stems are logged as engine-gaps, not dispatched.
            # TERMINAL leaves: when concept says leaf_type=terminal AND exec succeeded,
            #   trigger SOLVED (knowledge-driven terminal, not just artifact-type switch).
            #   Same artifact (captured_session) can be TERMINAL for a terminal concept
            #   (e.g. username_enum success) or BLOCKED for a can_be_blocked concept
            #   (e.g. NoSQL with account-locked signal) — concept knowledge decides.
            _late_solve_result: tuple | None = None   # (outcome_str, log_entry)
            try:
                from apps.conductor.leaf_evaluator import evaluate_leaf, build_stem_work_orders
                # Fix 1: concept_id reverse-lookup when not in params.
                # Stage 2 of generate_work_order is skipped for engines with no required_params
                # (e.g. username_enum), leaving params={} and no concept_id. Derive it from the
                # engine_id via CONCEPT_ENGINE_MAP so Phase 4 can evaluate the leaf.
                from apps.conductor.constants import CONCEPT_ENGINE_MAP as _CEM
                _engine_to_concept = {v: k for k, v in _CEM.items() if v}

                for log_e, exec_st, art in batch_results:
                    _concept_id = (log_e.get("params") or {}).get("concept_id", "")
                    if not _concept_id:
                        # Fall back to reverse lookup from engine_id
                        _concept_id = _engine_to_concept.get(log_e.get("engine_id", ""), "")
                    _fid = log_e.get("finding_id", finding_id)
                    if not _concept_id:
                        continue  # still no concept_id — nothing to evaluate

                    leaf_eval = evaluate_leaf(
                        engine_id  = log_e["engine_id"],
                        concept_id = _concept_id,
                        artifact   = art,
                        state      = exec_st,
                        finding_id = _fid,
                    )

                    log_e["leaf_kind"] = leaf_eval.kind
                    log_e["leaf_reason"] = leaf_eval.reason[:80]

                    if leaf_eval.kind == "blocked" and leaf_eval.stem_engines:
                        # BLOCKED: inject stem work orders into the stem_queue
                        stem_steps = build_stem_work_orders(leaf_eval, _fid)
                        for s in stem_steps:
                            s_sig = _signature(s.get("primitive_id", s["engine_id"]), s.get("params", {}))
                            if s_sig not in tried:
                                stem_queue.append(s)
                                logger.info(
                                    "autonomous: BLOCKED leaf — queued stem step %r for %s/%s",
                                    s.get("primitive_id"), _concept_id, _fid,
                                )
                        # Reset finding exhaustion so stem iterations are not blocked
                        if _fid in exhausted_fids:
                            exhausted_fids.discard(_fid)

                    elif leaf_eval.kind == "none_yet":
                        # NONE-YET: stem known but no engine — record gap
                        for gap in leaf_eval.none_yet_gaps:
                            logger.info(
                                "autonomous: NONE-YET gap — concept=%r stem_engine=%r has no engine impl",
                                _concept_id, gap.get("engine_id"),
                            )

                    elif leaf_eval.kind == "terminal" and exec_st == "succeeded":
                        # Fix 2: TERMINAL concept + succeeded execution → SOLVED.
                        # The existing _is_solved fast-path fires for oracle_extraction.
                        # For other terminal-leaf concepts (e.g. username_enum), the concept's
                        # leaf_type=terminal declares that any successful execution IS the win.
                        # Only fire when exec actually succeeded (not exhausted/timeout).
                        if not log_e.get("solved"):
                            log_e["solved"] = True
                            inner = (art or {}).get("artifact", art or {})
                            # Build a meaningful outcome from whatever the artifact carries
                            _outcome_fields = []
                            if isinstance(inner, dict):
                                for _k in ("username", "extracted_value", "confirmed_username"):
                                    _v = inner.get(_k, "")
                                    if _v:
                                        _outcome_fields.append(f"{_k}={_v!r}")
                            _outcome = (
                                f"Terminal win: {log_e['engine_id']} succeeded "
                                f"(concept {_concept_id!r} leaf_type=terminal)"
                                + (f" — {', '.join(_outcome_fields)}" if _outcome_fields else "")
                            )
                            _late_solve_result = (_outcome, log_e)
                            logger.info(
                                "autonomous: TERMINAL leaf → SOLVED — concept=%r engine=%r",
                                _concept_id, log_e["engine_id"],
                            )

                    else:
                        logger.debug(
                            "autonomous: leaf=%r concept=%r engine=%r state=%r",
                            leaf_eval.kind, _concept_id, log_e["engine_id"], exec_st,
                        )

            except Exception as _leaf_exc:
                logger.debug("autonomous: leaf evaluation failed (non-fatal): %s", _leaf_exc)

            # ── Phase C: verdict → STATE wire ─────────────────────────────────
            # Fire-and-forget: the lock in apply_verdict_to_state_async serialises
            # concurrent updates; no await needed here (doesn't block the loop).
            try:
                from apps.conductor.leaf_evaluator import evaluate_verdict
                from apps.conductor.agent_state import apply_verdict_to_state_async

                for log_e, exec_st, art in batch_results:
                    _verdict_concept = (log_e.get("params") or {}).get("concept_id", "")
                    if not _verdict_concept:
                        from apps.conductor.constants import CONCEPT_ENGINE_MAP as _CEM2
                        _e2c = {v: k for k, v in _CEM2.items() if v}
                        _verdict_concept = _e2c.get(log_e.get("engine_id", ""), "")
                    if not _verdict_concept:
                        continue
                    _verd = evaluate_verdict(
                        engine_id  = log_e.get("engine_id", ""),
                        concept_id = _verdict_concept,
                        artifact   = art,
                        state      = exec_st,
                        finding_id = log_e.get("finding_id", finding_id),
                    )
                    if _verd.match_kind == "known":
                        asyncio.create_task(
                            apply_verdict_to_state_async(
                                investigation_id = investigation_id,
                                verdict          = _verd,
                                concept_id       = _verdict_concept,
                                engine_id        = log_e.get("engine_id", ""),
                                exec_state       = exec_st,
                            )
                        )
                    elif _verd.match_kind == "no_concept_match":
                        # Phase D: park as Unknown Artifact (non-blocking, fire-and-forget).
                        # The existing flow continues immediately — park does NOT halt execution.
                        try:
                            from apps.conductor.unknown_store import park_unknown_async
                            _unk_ctx = (
                                f"exploitation, finding={_fid}, "
                                f"attempting={_verdict_concept or log_e.get('engine_id', '')}"
                            )
                            asyncio.create_task(
                                park_unknown_async(
                                    investigation_id = investigation_id,
                                    context          = _unk_ctx,
                                    raw_result       = art,
                                    expected_concept = _verdict_concept or None,
                                    evidence         = {
                                        "engine_id":   log_e.get("engine_id", ""),
                                        "exec_state":  exec_st,
                                        "finding_id":  _fid,
                                    },
                                )
                            )
                        except Exception as _park_exc:
                            logger.debug(
                                "autonomous: park_unknown failed (non-fatal): %s", _park_exc
                            )
            except Exception as _verd_exc:
                logger.debug("autonomous: verdict STATE update failed (non-fatal): %s", _verd_exc)

            # ── Oracle-strategy progression on exhaustion (knowledge-driven) ──
            # For differential enumeration engines, when a strategy exhausts with
            # no_signal_found=True, advance to the next strategy in the knowledge-
            # defined progression WITHOUT the AI needing to infer the retry.
            # The progression is declared in oracle_progression.py (data, not logic).
            # Injected into stem_queue so it runs before AI-generated work orders.
            try:
                from apps.conductor.engines.oracle_progression import get_next_oracle_strategy
                for log_e, exec_st, _art in batch_results:
                    # Advance on "exhausted" (normal path) OR "timeout" (executor couldn't
                    # dispatch — read prior exhaustion record if one exists so the next
                    # oracle strategy is still tried rather than silently giving up).
                    if exec_st not in ("exhausted", "timeout"):
                        continue
                    _eng_id = log_e.get("engine_id", "")
                    _fid    = log_e.get("finding_id", finding_id)
                    # Read the exhaustion record from DB to get the authoritative strategy
                    _exh = await _read_branch_exhaustion(investigation_id, _eng_id, _fid)
                    if not _exh.get("no_signal_found"):
                        continue
                    _used_strategy = _exh.get("oracle_strategy", "message")
                    _next_strategy = get_next_oracle_strategy(_eng_id, _used_strategy)
                    if _next_strategy is None:
                        logger.info(
                            "autonomous: oracle progression exhausted for %s — "
                            "all strategies tried for %s",
                            _eng_id, _fid,
                        )
                        continue
                    _next_sig = _signature(_eng_id, {"oracle_strategy": _next_strategy})
                    if _next_sig in tried:
                        continue
                    # Inject as a left-priority stem — runs before AI generation
                    stem_queue.appendleft({
                        "engine_id":    _eng_id,
                        "primitive_id": _eng_id,
                        "params":       {"oracle_strategy": _next_strategy},
                        "finding_id":   _fid,
                        "rationale": (
                            f"Oracle progression: {_eng_id}({_used_strategy}) exhausted "
                            f"(no_signal_found) — advancing to {_next_strategy}"
                        ),
                    })
                    logger.info(
                        "autonomous: oracle progression — %s(%s) no signal → queued %s(%s)",
                        _eng_id, _used_strategy, _eng_id, _next_strategy,
                    )
            except Exception as _oracle_prog_exc:
                logger.debug("autonomous: oracle progression check failed: %s", _oracle_prog_exc)

            # Fix 2 cont.: if Phase 4 detected a late terminal win, resolve it now.
            if _late_solve_result is not None:
                _late_outcome, _ = _late_solve_result
                await _persist_log(walk[-1])
                return await _terminate("solved", outcome=_late_outcome)

            # Phase 3: NO_PROGRESS is replaced by TREE_EXHAUSTED as the primary exhaustion
            # signal. We still track it as a safety valve but only fire it when:
            #   - All findings are in exhausted_fids (truly exhausted), OR
            #   - We've looped many times without any finding producing new work.
            if batch_any_finding or stem_queue:
                # A successful/partial result: reset exhausted tracking.
                # Preconditions may have changed → previously-exhausted findings may
                # now have new executable branches.
                exhausted_fids.clear()

                # Phase 3: Cross-finding expansion.
                # When a branch produces new findings (e.g. js_spider → api_endpoint_discovered),
                # add those findings to the workable tree so their branches get worked too.
                try:
                    new_all = await _discover_all_findings(investigation_id)
                    for nf_id, nf_meta in new_all.items():
                        if nf_id not in workable_findings:
                            workable_findings[nf_id] = nf_meta
                            logger.info(
                                "autonomous: cross-finding expansion — added %s (%s) to workable tree",
                                nf_id, nf_meta.get("type", "?"),
                            )
                except Exception as _exp_exc:
                    logger.debug("autonomous: cross-finding expansion failed: %s", _exp_exc)

            await _persist_log(walk[-1])

    except asyncio.CancelledError:
        return await _terminate("operator_stopped")
    except Exception as exc:
        logger.error("autonomous: loop exception: %s", exc, exc_info=True)
        return await _terminate("error", outcome=str(exc))


# ── Stop control ──────────────────────────────────────────────────────────────

async def request_stop(investigation_id: str) -> None:
    """Set the stop flag in InvestigationState. The loop checks this before each dispatch."""
    from apps.conductor.investigation_state import load_state_async, save_state_async
    state = await load_state_async(investigation_id)
    state.autonomous_stop_requested = True
    await save_state_async(state)
    # Also cancel the task if it's in the registry
    task = _running_tasks.get(investigation_id)
    if task and not task.done():
        task.cancel()
    logger.info("autonomous: stop requested for %s", investigation_id)


async def get_status(investigation_id: str) -> dict:
    """Return current autonomous loop status for the progress UI."""
    from apps.conductor.investigation_state import load_state_async
    state = await load_state_async(investigation_id)
    return {
        "status":      state.autonomous_status,
        "run_log":     state.autonomous_run_log,
        "stop_requested": state.autonomous_stop_requested,
    }


def start_autonomous_task(
    investigation_id: str,
    finding_id: str = "",
    target: str = "",
    budget: AutonomousBudget | None = None,
    seeded_batch: "list[dict] | None" = None,
    finding_ids: "list[str] | None" = None,
    operator_params: "dict | None" = None,    # Workstream A: self_pass + target_user
) -> asyncio.Task:
    """Create and register the background loop task. Returns the Task.

    Phase 3: finding_ids accepts multiple findings for whole-tree traversal.
    If None, run_autonomous auto-discovers all investigation findings.
    seeded_batch: operator-selected technique(s) for step 1 (Layer 2 precedence).
    operator_params: threaded to the planner path; carries self_pass for counter-reset.
    """
    task = asyncio.create_task(
        run_autonomous(investigation_id, finding_id, target, budget, seeded_batch,
                       finding_ids=finding_ids, operator_params=operator_params),
        name=f"autonomous-{investigation_id[:8]}",
    )
    _running_tasks[investigation_id] = task
    # Guarantee cleanup regardless of how the coroutine exits (normal return,
    # exception, or CancelledError interrupting _terminate before its deletion).
    task.add_done_callback(lambda _: _running_tasks.pop(investigation_id, None))
    return task


def is_running(investigation_id: str) -> bool:
    task = _running_tasks.get(investigation_id)
    if task is None:
        return False
    if task.done():
        # Stale entry — _terminate was interrupted before cleanup; remove now.
        _running_tasks.pop(investigation_id, None)
        return False
    return True


# ══════════════════════════════════════════════════════════════════════════════
# Phase E — Planner execution bridge
# ══════════════════════════════════════════════════════════════════════════════
# The planner calls these functions.  ALL existing machinery (Phase C verdict
# wire, oracle progression, leaf evaluation, unknown store) fires automatically
# through execute_work_order — nothing is bypassed or rewritten.

def _assemble_engine_params(
    engine_id:       str,
    concept_id:      str,
    operator_params: dict,
    agent_state:     dict,
) -> dict:
    """General param assembly for the planner path.

    Merges in priority order (highest first):
      1. operator_params  — from the planner/run call (explicit operator input)
      2. STATE.goal       — provided_self_user → self_user; target_user → target_user
      3. concept_id       — always injected for the engine's context

    Intentionally general: any future engine can source its required params from
    these same mechanisms without adding engine-specific special-casing here.

    NOTE: provided_self_pass (password) is NOT stored in STATE for security reasons;
    it must be supplied in operator_params.  If a parameterized engine requires
    self_pass and it's absent, the engine handles the "not configured" case itself
    (currently logs a warning and returns success+0). The planner logs the dispatch
    so the operator sees the unconfigured situation, rather than it being silent.
    """
    params: dict = dict(operator_params)   # caller-supplied params take precedence
    goal   = agent_state.get("goal") or {}

    # Source self_user from STATE.goal.provided_self_user (Phase 2 field, set by
    # counter-reset engine or operator context).  This makes counter-reset configurable
    # via the planner path without hardcoding the username.
    if "self_user" not in params and goal.get("provided_self_user"):
        params["self_user"] = goal["provided_self_user"]

    # Source target_user from STATE.goal.target_user (Phase 2 objective field).
    if "target_user" not in params and goal.get("target_user"):
        params["target_user"] = goal["target_user"]

    # Always inject concept_id so downstream engines / evaluators have the concept context.
    params.setdefault("concept_id", concept_id)

    # Log when engine likely needs params we cannot source (self_pass absent — can't
    # be stored in STATE; must come from operator_params).
    if "self_pass" not in params and engine_id == "credential_brute_counter_reset":
        logger.info(
            "_assemble_engine_params: %s needs self_pass but it's not in operator_params "
            "or STATE (passwords are not stored in STATE). Provide self_pass via "
            "operator_params in the planner/run call.",
            engine_id,
        )

    return params


async def planner_execute_step(
    investigation_id: str,
    engine_id:        str,
    finding_id:       str,
    target:           str,
    params:           dict,
    concept_id:       str = "",
) -> "tuple[str, dict | None]":
    """Single-step execution for the planner controller.

    Thin wrapper around execute_work_order.  ALL existing orchestration machinery
    fires (Phase C wire, oracle progression, leaf eval, unknown store, vault export).
    Orchestrator demotion: this replaces only the self-direct entry point; the
    execution machinery is fully reused.

    Returns (exec_state, artifact).  Never raises.
    """
    try:
        _params = dict(params)
        if concept_id:
            _params.setdefault("concept_id", concept_id)
        exec_st, art = await execute_work_order(
            investigation_id = investigation_id,
            engine_id        = engine_id,
            finding_id       = finding_id,
            params           = _params,
            target           = target,
        )
        logger.info(
            "planner_execute_step: %s/%s → %s (concept=%r)",
            engine_id, finding_id[:12] if finding_id else "", exec_st, concept_id,
        )
        return exec_st, art
    except Exception as exc:
        logger.warning(
            "planner_execute_step: failed for %s/%s — %s", engine_id, finding_id, exc
        )
        return "failed", None


async def _find_finding_for_concept(
    investigation_id: str,
    concept_id:       str,
    engine_id:        str,
) -> "str | None":
    """Return first non-dropped finding_id matching the concept's finding_types.

    Queries normalized_findings in the DB.  Returns None on any error.
    """
    try:
        from apps.conductor.planner import concept_finding_types
        finding_types = concept_finding_types(concept_id)
        if not finding_types:
            logger.debug(
                "_find_finding_for_concept: no finding_types for concept %r engine %r",
                concept_id, engine_id,
            )
            return None

        from apps.validation.database import get_db
        async with get_db() as db:
            for ft in finding_types:
                cur = await db.execute(
                    """SELECT finding_id FROM normalized_findings
                       WHERE investigation_id=? AND finding_type=?
                         AND (validation_status IS NULL
                              OR validation_status NOT IN ('dropped', 'ignored'))
                       LIMIT 1""",
                    (investigation_id, ft),
                )
                row = await cur.fetchone()
                if row:
                    logger.debug(
                        "_find_finding_for_concept: %s/%s → finding_id=%s (type=%s)",
                        concept_id, engine_id, str(row[0])[:12], ft,
                    )
                    return row[0]
    except Exception as exc:
        logger.warning("_find_finding_for_concept: %s", exc)
    return None


async def run_planner_loop(
    investigation_id: str,
    target:           str,
    max_iterations:   int = 10,
    operator_params:  "dict | None" = None,
) -> dict:
    """Planner-driven exploitation loop.

    GATE WARNING: This function was built before the Step 0 live gate passed.
    Verify Phase C wire end-to-end on a real lab before relying on this in production.

    Each iteration:
      1. Read STATE from DB
      2. Call plan_next_step() for a deterministic decision
      3. If EXECUTE: call planner_execute_step() → execute_work_order (all existing
         machinery fires, including Phase C verdict wire and success check)
      4. Append decision to planner_log in STATE (surfaced in Zone C)
      5. Repeat until SOLVED, STUCK, or budget exhausted

    Orchestrator demotion: the planner reads STATE and decides; execute_work_order
    runs it.  The existing autonomous loop is NOT modified — it still exists as the
    SWEEP fallback strategy when the planner has no pending reachable leads.

    Returns final status dict.
    """
    from apps.conductor.planner import plan_next_step, PlannerDecision
    from apps.conductor.agent_state import (
        load_agent_state_async,
        save_agent_state_async,
    )

    _op_params: dict = dict(operator_params or {})   # operator-supplied params for this run
    results = []

    for iteration in range(1, max_iterations + 1):
        # Read current STATE
        try:
            agent_state = await load_agent_state_async(investigation_id)
        except Exception as exc:
            logger.warning("run_planner_loop: load_agent_state failed — %s", exc)
            return {"action": "stuck", "reason": f"load error: {exc}", "iterations": iteration}

        if not agent_state or "goal" not in agent_state:
            return {
                "action": "stuck",
                "reason": "agent_state not initialized — run investigation first",
                "iterations": iteration,
            }

        # Already SOLVED?
        if agent_state.get("solved"):
            return {
                "action": "solved",
                "reason": agent_state.get("solved_reason", "goal satisfied"),
                "iterations": iteration,
            }

        # Planner decision
        decision: PlannerDecision = plan_next_step(agent_state)

        # Append to planner_log in STATE
        planner_log = agent_state.setdefault("planner_log", [])
        planner_log.append(f"[{iteration}] {decision.log_entry}")
        try:
            await save_agent_state_async(investigation_id, agent_state)
        except Exception as exc:
            logger.warning("run_planner_loop: save_agent_state failed — %s", exc)

        results.append({"iteration": iteration, "action": decision.action, "reason": decision.reason})
        logger.info(
            "run_planner_loop [%d/%d]: action=%s concept=%r engine=%r",
            iteration, max_iterations, decision.action, decision.concept_id, decision.engine_id,
        )

        # Terminal states — report and stop (STUCK intercept for Phase 3 interrogation)
        if decision.action in ("solved", "park"):
            return {
                "action":     decision.action,
                "reason":     decision.reason,
                "iterations": iteration,
                "results":    results,
            }

        if decision.action == "stuck":
            # Phase 3 — Failure Interrogation.
            # Before accepting STUCK, inspect recent exhausted branches for a
            # typed failure-reason fact.  If one is emitted, seed pending from
            # the vault and re-call plan_next_step (same iteration budget).
            # Fail-closed: any error here falls through to the STUCK terminal.
            try:
                from apps.conductor.failure_interrogator import interrogate, budget_remaining
                from apps.conductor.graph_resolver import resolve_branches as _gres
                from apps.conductor.agent_state import _get_state_lock
                from datetime import datetime, timezone

                _fresh_state = await load_agent_state_async(investigation_id)
                if _fresh_state and budget_remaining(_fresh_state):
                    # Load recent exhausted branches for the current investigation
                    _recent_branches: list = []
                    try:
                        from apps.conductor.exploitation.branch_store import BranchReader as _IBR
                        _all_br = await _IBR().list_for_investigation(investigation_id)
                        _recent_branches = [
                            b for b in _all_br
                            if b.state in ("exhausted", "failed")
                        ]
                    except Exception as _br_exc:
                        logger.debug("run_planner_loop interrogation: branch load failed — %s", _br_exc)

                    _emitted_fact: "str | None" = interrogate(_recent_branches, _fresh_state)

                    _int_attempt = _fresh_state.get("interrogation_attempts", 0)
                    _ts = datetime.now(timezone.utc).isoformat()

                    if _emitted_fact and _emitted_fact not in (_fresh_state.get("facts") or []):
                        # Fact is new — write it and re-seed pending
                        try:
                            async with _get_state_lock(investigation_id):
                                _lock_state = await load_agent_state_async(investigation_id)

                                # Append fact
                                _lock_state.setdefault("facts", []).append(_emitted_fact)

                                # Re-seed pending from vault (grows_from: <fact>)
                                _new_specs = _gres(_emitted_fact)
                                _existing_pending  = {p.get("concept") for p in _lock_state.get("pending", [])}
                                _existing_complete = set(_lock_state.get("completed") or [])
                                for _spec in _new_specs:
                                    if (_spec.concept_id and
                                            _spec.concept_id not in _existing_pending and
                                            _spec.concept_id not in _existing_complete):
                                        _lock_state.setdefault("pending", []).append(
                                            {"concept": _spec.concept_id, "priority": _spec.priority}
                                        )
                                        _existing_pending.add(_spec.concept_id)
                                _lock_state["pending"] = sorted(
                                    _lock_state.get("pending", []),
                                    key=lambda x: x.get("priority", 0),
                                    reverse=True,
                                )

                                # Update interrogation tracking
                                _lock_state["interrogation_attempts"] = _int_attempt + 1
                                _lock_state.setdefault("interrogation_log", []).append({
                                    "fact":      _emitted_fact,
                                    "iteration": iteration,
                                    "ts":        _ts,
                                })
                                _ilog = f"[{iteration}] INTERROGATE → emitted fact={_emitted_fact!r}"
                                _lock_state.setdefault("planner_log", []).append(_ilog)

                                await save_agent_state_async(investigation_id, _lock_state)

                            logger.info(
                                "run_planner_loop: interrogation emitted fact=%r for %s (attempt %d)",
                                _emitted_fact, investigation_id, _int_attempt + 1,
                            )
                            results.append({
                                "iteration": iteration,
                                "action":    "interrogate",
                                "fact":      _emitted_fact,
                            })
                            # Continue loop — planner will re-decide with the new fact
                            continue

                        except Exception as _write_exc:
                            logger.warning(
                                "run_planner_loop interrogation: state write failed — %s", _write_exc
                            )
                    else:
                        # Interrogator found nothing (or duplicate fact) → real STUCK
                        try:
                            async with _get_state_lock(investigation_id):
                                _nf_state = await load_agent_state_async(investigation_id)
                                _nf_state["interrogation_attempts"] = _int_attempt + 1
                                _nf_state.setdefault("interrogation_log", []).append({
                                    "fact":      None,
                                    "iteration": iteration,
                                    "ts":        _ts,
                                })
                                _nf_log = (
                                    f"[{iteration}] INTERROGATE → no actionable reason "
                                    f"(attempts={_int_attempt + 1})"
                                )
                                _nf_state.setdefault("planner_log", []).append(_nf_log)
                                await save_agent_state_async(investigation_id, _nf_state)
                        except Exception:
                            pass
                        logger.info(
                            "run_planner_loop: interrogation yielded no fact for %s — STUCK terminal",
                            investigation_id,
                        )

                else:
                    # Budget exhausted — log and fall through to STUCK
                    logger.info(
                        "run_planner_loop: interrogation budget exhausted (%d/%d) for %s — STUCK",
                        (_fresh_state or {}).get("interrogation_attempts", 0),
                        __import__("apps.conductor.failure_interrogator",
                                   fromlist=["MAX_INTERROGATIONS"]).MAX_INTERROGATIONS,
                        investigation_id,
                    )

            except Exception as _int_exc:
                logger.warning(
                    "run_planner_loop: interrogation error (fail-closed → STUCK): %s", _int_exc
                )

            return {
                "action":     "stuck",
                "reason":     decision.reason,
                "iterations": iteration,
                "results":    results,
            }

        if decision.action == "sweep":
            # SWEEP: fall back to the existing autonomous loop for whole-tree execution.
            # The planner delegates to the existing machinery — no new code needed.
            return {
                "action":  "sweep",
                "reason":  decision.reason,
                "note":    (
                    "Planner chose sweep strategy — trigger /autonomous/seed to run "
                    "the whole-tree autonomous loop (existing machinery)."
                ),
                "iterations": iteration,
                "results":    results,
            }

        if decision.action == "execute":
            concept_id = decision.concept_id
            engine_id  = decision.engine_id

            if not engine_id:
                # No engine for this concept — mark completed and continue
                _log = f"[{iteration}] SKIP (no engine for {concept_id})"
                agent_state = await load_agent_state_async(investigation_id)
                agent_state.setdefault("planner_log", []).append(_log)
                agent_state.setdefault("completed", [])
                if concept_id not in agent_state["completed"]:
                    agent_state["completed"].append(concept_id)
                await save_agent_state_async(investigation_id, agent_state)
                continue

            # Find the relevant finding_id for this engine
            finding_id = await _find_finding_for_concept(
                investigation_id, concept_id, engine_id
            )

            if not finding_id:
                # No matching finding — can't execute; mark as completed (no-op for now)
                _log = f"[{iteration}] SKIP — no matching finding for {concept_id}/{engine_id}"
                agent_state = await load_agent_state_async(investigation_id)
                agent_state.setdefault("planner_log", []).append(_log)
                agent_state.setdefault("completed", [])
                if concept_id not in agent_state["completed"]:
                    agent_state["completed"].append(concept_id)
                await save_agent_state_async(investigation_id, agent_state)
                continue

            # Bug 1 fix: assemble engine params from operator_params + STATE/objective.
            # General mechanism: any engine can receive its required params this way.
            _step_params = _assemble_engine_params(
                engine_id       = engine_id,
                concept_id      = concept_id,
                operator_params = _op_params,
                agent_state     = agent_state,
            )

            # Workstream C: self_pass guard for counter-reset.
            # self_pass is never stored in STATE (security invariant); it must come from
            # operator_params at each /planner/run call.  If absent, PARK this concept
            # rather than launching a counter-reset that interleaves with no password.
            if engine_id == "credential_brute_counter_reset" and "self_pass" not in _step_params:
                _park_log = (
                    f"[{iteration}] PARK — credential_brute_counter_reset: "
                    "self_pass required, not supplied via operator_params"
                )
                try:
                    agent_state = await load_agent_state_async(investigation_id)
                    agent_state.setdefault("planner_log", []).append(_park_log)
                    await save_agent_state_async(investigation_id, agent_state)
                except Exception:
                    pass
                return {
                    "action":     "park",
                    "reason":     "self_pass required, not supplied",
                    "iterations": iteration,
                    "results":    results,
                }

            # Execute the planner-selected step via the orchestrator
            exec_st, art = await planner_execute_step(
                investigation_id = investigation_id,
                engine_id        = engine_id,
                finding_id       = finding_id,
                target           = target,
                params           = _step_params,
                concept_id       = concept_id,
            )

            # Log the result to planner_log
            result_log = f"[{iteration}] {engine_id}/{finding_id[:8]} → {exec_st}"
            try:
                agent_state = await load_agent_state_async(investigation_id)
                agent_state.setdefault("planner_log", []).append(result_log)
                await save_agent_state_async(investigation_id, agent_state)
            except Exception:
                pass

            results[-1]["exec_state"] = exec_st

    return {
        "action":     "budget",
        "reason":     f"max_iterations={max_iterations} reached",
        "iterations": max_iterations,
        "results":    results,
    }
