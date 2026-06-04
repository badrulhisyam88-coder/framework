"""Phase A+C — Agent loop GOAL + STATE objects with live state-update wire.

Phase A (data layer): GOAL + STATE objects, enumerated vocab, init/load/save.
Phase C (state-update): verdict -> STATE wire, concurrency-safe via per-investigation
    asyncio.Lock, success check gate (SOLVED signal, observable only).

GOAL  = {objective, success_conditions}
STATE = {goal, facts, artifacts, pending, ruled_out, completed, current_position}
        + solved: bool  (set by check_success, never clears)
        + solved_reason: str

Persistence: piggybacks on InvestigationState JSON blob (state_{inv_id} row).
Acceptable at this scale: branches finish seconds apart (not microseconds); the
blob is <50 KB; SQLite INSERT OR REPLACE is atomic. The per-investigation lock
serializes in-memory read-modify-write so concurrent branch completions cannot
clobber each other's updates.

current_position enumerated vocabulary (LOCKED):
  AUTHENTICATION = ["none", "authenticated", "admin"]
  PRIVILEGE      = ["none", "user", "admin", "root"]
  EXECUTION      = ["none", "file_read", "rce"]
  access_scope   = free list of strings (not enumerated)
"""
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

logger = logging.getLogger("conductor.agent_state")

# ── Vocabulary constants ──────────────────────────────────────────────────────

AUTHENTICATION_VOCAB: frozenset[str] = frozenset({"none", "authenticated", "admin"})
PRIVILEGE_VOCAB:      frozenset[str] = frozenset({"none", "user", "admin", "root"})
EXECUTION_VOCAB:      frozenset[str] = frozenset({"none", "file_read", "rce"})

_KNOWLEDGE_VAULT_PATH = Path(os.environ.get("KNOWLEDGE_VAULT_PATH", "/app/knowledge-vault"))


# ── Default constructors ──────────────────────────────────────────────────────

def default_goal() -> dict:
    return {
        "objective":          "obtain credentials / access",
        "success_conditions": ["valid_credentials_found"],
        # Phase 2 — success precision: distinguish provided vs discovered credentials.
        # provided_self_user: the operator's own account (used for setup/counter-reset);
        #   credentials FOR this user are NOT an objective solve.
        # target_user: the account the objective asks to compromise; credentials FOR
        #   this user ARE the solve. If None, any non-provided credential is the solve.
        "provided_self_user": None,
        "target_user":        None,
    }


def default_current_position() -> dict:
    return {
        "authentication": "none",
        "privilege":      "none",
        "access_scope":   [],
        "execution":      "none",
    }


def default_agent_state(goal: dict | None = None) -> dict:
    return {
        "goal":             goal if goal is not None else default_goal(),
        "facts":            [],
        "artifacts":        {"credentials": [], "sessions": [], "tokens": [], "files": []},
        "pending":          [],
        "ruled_out":        [],
        "completed":        [],
        "current_position": default_current_position(),
        "planner_log":      [],   # Phase E: planner decision trace surfaced in Zone C
        # Phase 3: failure interrogation tracking
        "interrogation_attempts": 0,    # total interrogations fired (capped at MAX_INTERROGATIONS)
        "interrogation_log":      [],   # [{fact, iteration, ts}] — one entry per interrogation
    }


# ── Validation ────────────────────────────────────────────────────────────────

def validate_current_position(cp: dict) -> dict:
    """Validate authentication/privilege/execution against vocab sets.

    Raises ValueError with the field name + bad value if invalid.
    Leaves access_scope as-is.  Returns normalized cp.
    """
    for field_name, vocab in (
        ("authentication", AUTHENTICATION_VOCAB),
        ("privilege",      PRIVILEGE_VOCAB),
        ("execution",      EXECUTION_VOCAB),
    ):
        val = cp.get(field_name, "none")
        if val not in vocab:
            raise ValueError(
                f"validate_current_position: invalid {field_name!r} value {val!r}; "
                f"must be one of {sorted(vocab)}"
            )
    return cp


# ── Concept priority helper ───────────────────────────────────────────────────

def _concept_priority(concept_id: str) -> int:
    """Return the priority field from a concept .md frontmatter.

    Reads KNOWLEDGE_VAULT_PATH/concepts/<concept_id.lower()>.md.
    Returns 50 on any error (never raises).
    """
    try:
        import yaml
        filename   = concept_id.lower().replace("_", "-") + ".md"
        filepath   = _KNOWLEDGE_VAULT_PATH / "concepts" / filename
        if not filepath.exists():
            return 50
        text = filepath.read_text(encoding="utf-8")
        if not text.startswith("---"):
            return 50
        end = text.find("\n---", 3)
        if end == -1:
            return 50
        fm_block = text[3:end]
        fm = yaml.safe_load(fm_block) or {}
        return int(fm.get("priority", 50))
    except Exception as exc:
        logger.debug("_concept_priority(%r): error — %s", concept_id, exc)
        return 50


# ── Async init / load / save ──────────────────────────────────────────────────

async def init_agent_state_async(
    investigation_id: str,
    target:           str = "",
    objective:        str | None = None,
) -> dict:
    """Build a fresh STATE dict seeded from existing findings.

    - Reads all findings for investigation_id via NormalizedFindingRepository.
    - Maps each finding_type → concept_id via graph_resolver.resolve_branches.
    - Seeds pending as [{concept, priority}] deduped by concept_id, sorted desc.
    - Sets goal from objective param or default_goal().
    Never raises; returns partial state on error.
    """
    state = default_agent_state()
    if objective:
        state["goal"] = {"objective": objective, "success_conditions": ["valid_credentials_found"]}

    try:
        from apps.validation.database import get_db
        from apps.scanner_orchestration.storage.finding_repo import NormalizedFindingRepository
        from apps.conductor.graph_resolver import resolve_branches

        async with get_db() as db:
            repo = NormalizedFindingRepository(db)
            findings = await repo.list_for_investigation(investigation_id)

        concept_ids: dict[str, int] = {}  # concept_id → priority

        for finding in findings:
            ft = getattr(finding, "finding_type", None) or ""
            if not ft:
                continue
            try:
                branches = resolve_branches(ft)
                for branch in branches:
                    cid = getattr(branch, "concept_id", None) or ""
                    if cid and cid not in concept_ids:
                        concept_ids[cid] = _concept_priority(cid)
            except Exception as exc:
                logger.debug(
                    "init_agent_state_async: graph_resolver error for %r: %s", ft, exc
                )

        pending = [
            {"concept": cid, "priority": pri}
            for cid, pri in concept_ids.items()
        ]
        pending.sort(key=lambda x: x["priority"], reverse=True)
        state["pending"] = pending

    except Exception as exc:
        logger.warning(
            "init_agent_state_async(%s): partial init due to error — %s",
            investigation_id, exc,
        )

    return state


async def load_agent_state_async(investigation_id: str) -> dict:
    """Load agent_state from the persisted InvestigationState blob.

    Returns state.agent_state if non-empty dict, else {}.
    """
    try:
        from apps.conductor.investigation_state import load_state_async
        state = await load_state_async(investigation_id)
        agent_state = getattr(state, "agent_state", {}) or {}
        if isinstance(agent_state, dict):
            return agent_state
        return {}
    except Exception as exc:
        logger.debug("load_agent_state_async(%s): %s", investigation_id, exc)
        return {}


async def save_agent_state_async(investigation_id: str, agent_state: dict) -> None:
    """Persist agent_state into the InvestigationState blob.

    Never raises; logs errors.
    """
    try:
        from apps.conductor.investigation_state import load_state_async, save_state_async
        state = await load_state_async(investigation_id)
        state.agent_state = agent_state
        await save_state_async(state)
    except Exception as exc:
        logger.warning("save_agent_state_async(%s): %s", investigation_id, exc)


async def get_or_init_agent_state_async(
    investigation_id: str,
    target:           str = "",
    objective:        str | None = None,
) -> dict:
    """Return existing agent_state if present, else init, persist, and return it."""
    existing = await load_agent_state_async(investigation_id)
    if existing and "goal" in existing:
        return existing

    fresh = await init_agent_state_async(investigation_id, target=target, objective=objective)
    await save_agent_state_async(investigation_id, fresh)
    return fresh


# ══════════════════════════════════════════════════════════════════════════════
# Phase C — STATE-UPDATE WIRE
# ══════════════════════════════════════════════════════════════════════════════

# ── Per-investigation lock (concurrency safety) ───────────────────────────────
# Multiple branch verdicts can arrive near-simultaneously (parallel batches).
# A naive read-modify-write on the blob = lost updates.  The lock serializes
# all STATE updates for the same investigation; no two verdicts update STATE
# at the same time for the same investigation.

_STATE_LOCKS: dict[str, asyncio.Lock] = {}


def _get_state_lock(investigation_id: str) -> asyncio.Lock:
    """Return (creating if needed) the asyncio.Lock for this investigation."""
    if investigation_id not in _STATE_LOCKS:
        _STATE_LOCKS[investigation_id] = asyncio.Lock()
    return _STATE_LOCKS[investigation_id]


# ── Position implications (sourced from real methodology) ─────────────────────
# Which concepts imply a current_position update on SUCCESSFUL execution.
# Sources: OWASP WSTG, PortSwigger Web Academy, PTES, MITRE ATT&CK T1059/T1190.
# Engine gaps (no engine impl): privilege escalation, lateral movement, XSS-theft.
_CONCEPT_POSITION_IMPLIES: dict[str, dict] = {
    # WSTG-ATHN-04/07 + PortSwigger: credential capture = authenticated session
    "CONCEPT-CREDENTIAL-BRUTE":     {"authentication": "authenticated"},
    # OWASP WSTG-INPV-05, PTES SQLi: SQL bypass = session obtained = authenticated
    "CONCEPT-SQLI-AUTH-BYPASS":     {"authentication": "authenticated"},
    # MITRE ATT&CK T1059.004, WSTG-INPV-12: OS cmd = remote code execution
    "CONCEPT-CMDI-REFLECTED":       {"execution": "rce"},
    "CONCEPT-CMDI-BLIND-TIME":      {"execution": "rce"},
    "CONCEPT-CMDI-BLIND-BOOLEAN":   {"execution": "rce"},
    # WSTG-INPV-10: file upload with shell = at minimum file read, often rce
    "CONCEPT-FILE-UPLOAD":          {"execution": "file_read"},
    # Auth bypass login engine (any flavour) = authenticated
    "CONCEPT-AUTH-BYPASS-LOGIN":    {"authentication": "authenticated"},
}

# ── Credential origin tagging helpers (Phase 2 — success precision) ──────────

def _tag_credential_origin(obj: dict, goal: dict) -> dict:
    """Return a copy of a credential artifact tagged with origin=provided|discovered.

    Classification (deterministic, no model):
    - provided_self_user set AND username matches → "provided" (NOT a solve)
    - target_user set AND username matches → "discovered" (IS a solve)
    - provided_self_user set AND username does NOT match → "discovered"
    - Neither set → "discovered" (backward compat: any captured cred is objective)

    No hardcoded usernames — driven by goal.provided_self_user / goal.target_user.
    """
    if not isinstance(obj, dict):
        return obj
    username          = str(obj.get("username") or obj.get("user") or "").lower()
    provided_self     = str(goal.get("provided_self_user") or "").lower()
    target            = str(goal.get("target_user") or "").lower()

    if provided_self and username == provided_self:
        origin = "provided"
    elif target and username == target:
        origin = "discovered"
    elif provided_self and username != provided_self:
        # Know who's "self" and this isn't them → it's a real find
        origin = "discovered"
    else:
        # No provided_self context → any capture is the objective (backward compat)
        origin = "discovered"

    return {**obj, "origin": origin}


def _has_discovered_credential(s: dict) -> bool:
    """Return True only when a DISCOVERED/TARGET credential exists in STATE.

    Conservative: if all credentials are tagged 'provided', returns False.
    Ambiguous (no origin tag, no provided_self set) → treated as discovered
    (backward compat — if no context distinguishes provided from discovered,
    any capture is the objective).
    """
    creds = (s.get("artifacts") or {}).get("credentials") or []
    if not creds:
        # Fix 2: bare credential_obtained fact is NOT sufficient — it carries no username
        # or origin tag, so it cannot be checked against provided-vs-discovered.
        # A solve requires a classifiable credential object in the bucket (Fix 3 ensures
        # real captures land there).  Conservative: no classifiable artifact → not-yet-solved.
        return False
    provided_self = str((s.get("goal") or {}).get("provided_self_user") or "").lower()
    for cred in creds:
        if not isinstance(cred, dict):
            continue
        origin   = cred.get("origin")
        username = str(cred.get("username") or cred.get("user") or "").lower()
        if origin == "discovered":
            return True
        if origin == "provided":
            continue   # explicitly provided — not the objective
        # No origin tag:
        if not provided_self:
            # No provided_self context → any capture counts (backward compat)
            return True
        if username != provided_self:
            # Has provided_self context and this isn't it → discovered
            return True
    return False   # all credentials are tagged or inferred 'provided'


def _discovered_credential_username(s: dict) -> str:
    """Return the username of the first discovered credential, or '' if none."""
    creds = (s.get("artifacts") or {}).get("credentials") or []
    provided_self = str((s.get("goal") or {}).get("provided_self_user") or "").lower()
    for cred in creds:
        if not isinstance(cred, dict):
            continue
        origin   = cred.get("origin")
        username = str(cred.get("username") or cred.get("user") or "")
        if origin == "discovered":
            return username
        if origin == "provided":
            continue
        if not provided_self:
            return username
        if username.lower() != provided_self:
            return username
    return ""


# ── Success condition mapping (goal-scoped) ───────────────────────────────────
# Maps a success_condition string to a predicate over STATE.
# Predicates return True when the condition is satisfied.
_SUCCESS_PREDICATES: dict[str, "object"] = {
    # Phase 2 — objective-aware: requires a DISCOVERED credential, not the provided self-login.
    # A capture of the provided self-account (e.g. wiener:peter for counter-reset setup)
    # does NOT satisfy this condition; only credentials for the objective target do.
    "valid_credentials_found": _has_discovered_credential,
    # Authenticated session exists
    "session_authenticated": lambda s: (
        (s.get("current_position") or {}).get("authentication", "none") != "none" or
        bool((s.get("artifacts") or {}).get("sessions"))
    ),
    # Remote code execution achieved
    "rce_achieved": lambda s: (
        (s.get("current_position") or {}).get("execution", "none") == "rce"
    ),
    # Access control bypass confirmed
    "access_control_bypassed": lambda s: (
        "access_control_bypassed" in (s.get("facts") or [])
    ),
    # Any artifact captured
    "any_artifact_captured": lambda s: any(
        bool(v) for v in (s.get("artifacts") or {}).values()
    ),
}


def check_success(agent_state: dict) -> tuple[bool, str]:
    """Check if any success_condition in GOAL is satisfied by current STATE.

    Phase 2 — objective-aware: valid_credentials_found requires a DISCOVERED/TARGET
    credential, NOT a provided self-login.  Returns a specific reason naming the
    discovered user so Zone A/C messaging is precise.

    Returns (solved: bool, reason: str).
    Does NOT mutate agent_state — caller applies the result.
    """
    goal = agent_state.get("goal") or {}
    conditions = goal.get("success_conditions") or []
    for cond in conditions:
        pred = _SUCCESS_PREDICATES.get(cond)
        if pred is None:
            # Unknown condition: check if the exact string is in facts
            if cond in (agent_state.get("facts") or []):
                return True, f"success_condition {cond!r} matched fact"
        else:
            try:
                if pred(agent_state):
                    # Phase 2 — precise reason: include the discovered username if available
                    if cond == "valid_credentials_found":
                        _user = _discovered_credential_username(agent_state)
                        reason = (
                            f"discovered credentials for {_user!r}"
                            if _user else "valid_credentials_found satisfied"
                        )
                    else:
                        reason = f"success_condition {cond!r} satisfied"
                    return True, reason
            except Exception as exc:
                logger.debug("check_success predicate %r failed: %s", cond, exc)
    return False, ""


def _apply_verdict_in_place(
    agent_state: dict,
    verdict:     "object",   # Verdict dataclass from leaf_evaluator
    concept_id:  str,
    engine_id:   str,
    exec_state:  str,        # "succeeded" | "exhausted" | "failed"
) -> None:
    """Apply a KNOWN verdict to agent_state IN PLACE (caller holds the lock).

    Updates:
      facts      += verdict.state_changes (dedup)
      artifacts  += verdict.artifacts_captured (append to right bucket)
      pending    += verdict.unlocks (ranked, exclude ruled_out + completed)
      ruled_out  += verdict.rules_out (dedup)
      pending    -= verdict.rules_out (remove ruled-out from pending)
      completed  += concept_id step
      current_position updated if concept implies it (on succeeded only)
    """
    facts       = agent_state.setdefault("facts", [])
    artifacts   = agent_state.setdefault("artifacts",
                    {"credentials": [], "sessions": [], "tokens": [], "files": []})
    pending     = agent_state.setdefault("pending", [])
    ruled_out   = agent_state.setdefault("ruled_out", [])
    completed   = agent_state.setdefault("completed", [])
    cur_pos     = agent_state.setdefault("current_position", default_current_position())

    # ── facts: dedup append ───────────────────────────────────────────────────
    for fact in (verdict.state_changes or []):
        if fact and fact not in facts:
            facts.append(fact)

    # ── artifacts: append real objects to the right bucket ────────────────────
    # Phase 2 — tag credential artifacts with origin (provided vs discovered)
    # so check_success can distinguish the provided self-login from the objective target.
    _goal_for_tag = agent_state.get("goal") or {}
    for bucket, obj in (verdict.artifacts_captured or {}).items():
        if bucket in artifacts and obj:
            if bucket == "credentials" and isinstance(obj, dict):
                obj = _tag_credential_origin(obj, _goal_for_tag)
            artifacts[bucket].append(obj)

    # ── ruled_out: dedup append ───────────────────────────────────────────────
    for ro in (verdict.rules_out or []):
        if ro and ro not in ruled_out:
            ruled_out.append(ro)

    # ── pending: remove rules_out + add unlocks (sorted by priority desc) ─────
    ro_set        = set(ruled_out)
    completed_set = set(completed)
    # Remove ruled-out from pending
    pending[:] = [p for p in pending if p.get("concept") not in ro_set]
    # Add unlocks (exclude already in ruled_out, completed, or already pending)
    existing_pending_concepts = {p.get("concept") for p in pending}
    for unlock in (verdict.unlocks or []):
        cid = unlock.get("concept", "")
        if cid and cid not in ro_set and cid not in completed_set \
                and cid not in existing_pending_concepts:
            pending.append({"concept": cid, "priority": unlock.get("priority", 50)})
            existing_pending_concepts.add(cid)
    # Re-sort pending descending
    pending.sort(key=lambda x: x.get("priority", 0), reverse=True)

    # ── completed: add this step ──────────────────────────────────────────────
    step_key = concept_id or engine_id
    if step_key and step_key not in completed:
        completed.append(step_key)
    # Also remove from pending (this step is done)
    pending[:] = [p for p in pending if p.get("concept") != step_key]

    # ── current_position: update on succeeded only (enumerated vocab enforced) ─
    # Phase 2 — for authentication advancement: only advance when the artifact is
    # a DISCOVERED credential (not the provided self-login, which doesn't reflect
    # genuine target access). Other position fields (execution, privilege) advance normally.
    if exec_state == "succeeded":
        implies = _CONCEPT_POSITION_IMPLIES.get(concept_id, {})
        _skip_auth = False
        if "authentication" in implies and not _has_discovered_credential(agent_state):
            # No discovered credential yet — don't advance authentication position
            # (the captured credential may be the provided self-login, not the target)
            _skip_auth = True
        for field_name, new_val in implies.items():
            if field_name == "authentication" and _skip_auth:
                continue   # don't advance auth on provided-only credential captures
            if field_name == "access_scope":
                scope = cur_pos.setdefault("access_scope", [])
                if isinstance(new_val, list):
                    for tag in new_val:
                        if tag not in scope:
                            scope.append(tag)
            else:
                vocab = {
                    "authentication": AUTHENTICATION_VOCAB,
                    "privilege":      PRIVILEGE_VOCAB,
                    "execution":      EXECUTION_VOCAB,
                }.get(field_name)
                if vocab and new_val in vocab:
                    cur_pos[field_name] = new_val

    # ── success check ─────────────────────────────────────────────────────────
    if not agent_state.get("solved"):
        solved, reason = check_success(agent_state)
        if solved:
            agent_state["solved"] = True
            agent_state["solved_reason"] = reason
            logger.info(
                "agent_state: SOLVED — investigation=%s reason=%r",
                agent_state.get("_inv_id", ""), reason,
            )


async def apply_verdict_to_state_async(
    investigation_id: str,
    verdict:          "object",   # Verdict dataclass from leaf_evaluator
    concept_id:       str = "",
    engine_id:        str = "",
    exec_state:       str = "",
) -> None:
    """Concurrency-safe verdict → STATE wire.

    Acquires the per-investigation lock, performs the full read-modify-write,
    then persists.  Fire-and-forget from the orchestrator (asyncio.create_task).
    Never raises; logs errors.

    Persistence decision (Part 1): the blob approach is kept; the lock (Part 2)
    prevents lost updates.  At exploitation scale (one verdict every few seconds)
    this is adequate; a dedicated JSONB column would only be warranted at >10 Hz.
    """
    if not investigation_id:
        return
    try:
        lock = _get_state_lock(investigation_id)
        async with lock:
            agent_state = await load_agent_state_async(investigation_id)
            if not agent_state or "goal" not in agent_state:
                # Not yet initialized — skip gracefully (no-op)
                logger.debug(
                    "apply_verdict_to_state_async(%s): agent_state not initialized — skip",
                    investigation_id,
                )
                return
            agent_state["_inv_id"] = investigation_id   # for logging in _apply
            _apply_verdict_in_place(agent_state, verdict, concept_id, engine_id, exec_state)
            agent_state.pop("_inv_id", None)
            await save_agent_state_async(investigation_id, agent_state)
            logger.debug(
                "apply_verdict_to_state_async(%s): applied concept=%r engine=%r state=%r "
                "facts=%d pending=%d solved=%s",
                investigation_id, concept_id, engine_id, exec_state,
                len(agent_state.get("facts", [])),
                len(agent_state.get("pending", [])),
                agent_state.get("solved", False),
            )
    except Exception as exc:
        logger.warning(
            "apply_verdict_to_state_async(%s): failed — %s", investigation_id, exc
        )
