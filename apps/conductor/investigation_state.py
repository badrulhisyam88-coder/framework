"""Phase E Part 3 — Investigation state: shared context + attempt tree.

Stores per-investigation context that spans multiple engine executions:
  - Captured credentials and session cookies
  - Discovered endpoints
  - Attempt tree: which engine was tried on which finding, and the result

Storage: JSON blob in the exploitation_branches table using a synthetic
branch_id of "state_{investigation_id}" and engine_id "investigation_state".
This reuses the existing DB schema without adding a new table.

Never raises in load_state/save_state — returns empty/default state on error.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field

logger = logging.getLogger("conductor.investigation_state")

_STATE_ENGINE_ID = "investigation_state"  # synthetic engine_id for state rows


@dataclass
class InvestigationState:
    investigation_id: str
    target:           str = ""
    objective:        str | None = None          # operator-provided objective text
    credentials:      dict | None = None          # {"username": ..., "password": ...}
    session:          dict | None = None           # captured session cookies
    endpoints:        list[str] = field(default_factory=list)  # discovered endpoints
    tokens:           dict = field(default_factory=dict)        # CSRF + other tokens
    # attempt_tree: list of {engine_id, finding_id, status, parent_id, technique_title}
    attempt_tree:     list[dict] = field(default_factory=list)
    parsed_objective: str | None = None           # extracted from objective text
    # ranked_lists: {finding_id → [engine_id, ...]} — A2 pre-ranked ordering
    # Used by Part C fallback loop without re-ranking.
    ranked_lists:     dict = field(default_factory=dict)
    # pending_work_orders: {work_order_id → WorkOrder dict} — AI work orders (Bundle 2).
    # Keyed by UUID string; TechniqueOption.work_order_id references these.
    # execute_suggestion route reads the full dict to get filled params.
    pending_work_orders: dict = field(default_factory=dict)
    # Session Unification — single durable session record.
    # Persists the captured session (cookies + username + target_base) so a freshly
    # reconstructed SessionOrchestrator can rehydrate it without needing the original
    # in-memory instance. This is the source-of-truth that survives context reconstruction.
    captured_session: dict | None = None   # {"cookies":{}, "username":"", "target_base":""}

    # Bundle 3 — Autonomous Solve Loop fields.
    # autonomous_stop_requested: set by POST /autonomous/stop; checked before each dispatch.
    autonomous_stop_requested: bool = False
    # autonomous_status: current loop state ("idle"|"running"|"solved"|"budget"|"no_progress"|
    #   "no_path"|"operator_stopped").
    autonomous_status: str = "idle"
    # autonomous_run_log: [{attempt, primitive_id, rationale, result_status, summary}]
    # Written after each execution; polled by the progress UI.
    autonomous_run_log: list[dict] = field(default_factory=list)

    # Phase A agent loop — GOAL + STATE blob (see agent_state.py).
    # Not applied to execution; data layer only until Phase C wire.
    agent_state: dict = field(default_factory=dict)


def _state_branch_id(investigation_id: str) -> str:
    return f"state_{investigation_id}"


def load_state(investigation_id: str) -> InvestigationState:
    """Load investigation state from DB. Returns a fresh empty state on error or miss."""
    try:
        return _load(investigation_id)
    except Exception as exc:
        logger.debug("load_state(%s) failed: %s — returning empty state", investigation_id, exc)
        return InvestigationState(investigation_id=investigation_id)


def _load(investigation_id: str) -> InvestigationState:
    import asyncio
    from apps.validation.database import get_db

    branch_id = _state_branch_id(investigation_id)

    async def _fetch():
        async with get_db() as db:
            cur = await db.execute(
                "SELECT artifact FROM exploitation_branches WHERE branch_id=?",
                (branch_id,),
            )
            row = await cur.fetchone()
            return row

    # Run synchronously if no event loop is running; else schedule
    try:
        loop = asyncio.get_running_loop()
        # Can't block in a running loop — return empty state
        # (callers in async routes should call load_state_async instead)
        return InvestigationState(investigation_id=investigation_id)
    except RuntimeError:
        row = asyncio.run(_fetch())

    if not row or not row[0]:
        return InvestigationState(investigation_id=investigation_id)

    data = json.loads(row[0]) if isinstance(row[0], str) else row[0]
    return InvestigationState(
        investigation_id = investigation_id,
        target           = data.get("target", ""),
        objective        = data.get("objective"),
        credentials      = data.get("credentials"),
        session          = data.get("session"),
        endpoints        = list(data.get("endpoints", [])),
        tokens           = dict(data.get("tokens", {})),
        attempt_tree     = list(data.get("attempt_tree", [])),
        parsed_objective = data.get("parsed_objective"),
        ranked_lists               = dict(data.get("ranked_lists", {})),
        pending_work_orders        = dict(data.get("pending_work_orders", {})),
        captured_session           = data.get("captured_session"),
        autonomous_stop_requested  = bool(data.get("autonomous_stop_requested", False)),
        autonomous_status          = str(data.get("autonomous_status", "idle")),
        autonomous_run_log         = list(data.get("autonomous_run_log", [])),
        agent_state              = dict(data.get("agent_state", {})),
    )


async def load_state_async(investigation_id: str) -> InvestigationState:
    """Async variant for use inside async routes."""
    try:
        return await _load_async(investigation_id)
    except Exception as exc:
        logger.debug("load_state_async(%s) failed: %s", investigation_id, exc)
        return InvestigationState(investigation_id=investigation_id)


async def _load_async(investigation_id: str) -> InvestigationState:
    from apps.validation.database import get_db

    branch_id = _state_branch_id(investigation_id)
    async with get_db() as db:
        cur = await db.execute(
            "SELECT artifact FROM exploitation_branches WHERE branch_id=?",
            (branch_id,),
        )
        row = await cur.fetchone()

    if not row or not row[0]:
        return InvestigationState(investigation_id=investigation_id)

    data = json.loads(row[0]) if isinstance(row[0], str) else row[0]
    return InvestigationState(
        investigation_id = investigation_id,
        target           = data.get("target", ""),
        objective        = data.get("objective"),
        credentials      = data.get("credentials"),
        session          = data.get("session"),
        endpoints        = list(data.get("endpoints", [])),
        tokens           = dict(data.get("tokens", {})),
        attempt_tree     = list(data.get("attempt_tree", [])),
        parsed_objective = data.get("parsed_objective"),
        ranked_lists               = dict(data.get("ranked_lists", {})),
        pending_work_orders        = dict(data.get("pending_work_orders", {})),
        captured_session           = data.get("captured_session"),
        autonomous_stop_requested  = bool(data.get("autonomous_stop_requested", False)),
        autonomous_status          = str(data.get("autonomous_status", "idle")),
        autonomous_run_log         = list(data.get("autonomous_run_log", [])),
        agent_state              = dict(data.get("agent_state", {})),
    )


async def save_state_async(state: InvestigationState) -> None:
    """Persist investigation state to DB (async)."""
    try:
        await _save_async(state)
    except Exception as exc:
        logger.warning("save_state_async(%s) failed: %s", state.investigation_id, exc)


async def _save_async(state: InvestigationState) -> None:
    from apps.validation.database import get_db
    from datetime import datetime, timezone

    branch_id = _state_branch_id(state.investigation_id)
    now = datetime.now(timezone.utc).isoformat()
    payload = json.dumps(asdict(state))

    async with get_db() as db:
        await db.execute(
            """INSERT OR REPLACE INTO exploitation_branches
               (branch_id, investigation_id, finding_id, engine_id,
                technique_class, operator_params, state, artifact,
                artifact_type, exhaustion_record, stage_log,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                branch_id,
                state.investigation_id,
                state.investigation_id,   # finding_id: synthetic
                _STATE_ENGINE_ID,
                "investigation.state",
                "{}",
                "succeeded",
                payload,
                "investigation_state",
                None,
                "[]",
                now,
                now,
            ),
        )
        await db.commit()


def get_siblings(state: InvestigationState, finding_id: str) -> list[dict]:
    """Return attempt_tree entries for this finding_id that have NOT been tried.

    In practice returns entries that are NOT in the attempt_tree for this finding
    — i.e., siblings not yet attempted.
    """
    tried_engines = {
        a["engine_id"]
        for a in state.attempt_tree
        if a.get("finding_id") == finding_id
    }
    # Return the attempted ones so the caller knows what's been tried
    return [a for a in state.attempt_tree if a.get("finding_id") == finding_id]
