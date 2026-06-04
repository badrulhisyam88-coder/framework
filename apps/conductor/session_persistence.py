"""Session Persistence — single durable session source (Session Unification fix).

Root cause fixed here:
  Before: credential_brute wrote to TWO in-memory dicts (_api_auth_store keyed by
    investigation_id; _target_auth keyed by target_base). Context reconstruction
    creates a FRESH SessionOrchestrator → both dicts empty → session lost.

  After: ONE persistent write to InvestigationState.captured_session (in the
    exploitation_branches table, branch_id=state_{investigation_id}). On every
    context reconstruction, the new SessionOrchestrator rehydrates from this record.
    The session survives reconstruction because it lives in durable storage.

Public API:
  store_session()  — called by credential_brute (and any other session capture path)
                     to persist the captured session.
  rehydrate_session() — called after context reconstruction to populate the fresh
                     SessionOrchestrator from the durable record.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("conductor.session_persistence")

# Module-level imports so tests can patch by name without path gymnastics.
async def _sentinel(*_a, **_k): raise NotImplementedError("import not available")

try:
    from apps.conductor.investigation_state import load_state_async, save_state_async
except ImportError:
    load_state_async = _sentinel  # type: ignore[assignment]
    save_state_async = _sentinel  # type: ignore[assignment]


async def store_session(
    investigation_id: str,
    auth_payload: dict,      # {"cookies": {...}, "username": "..."}
    target_base: str,        # e.g. "https://0aXX.web-security-academy.net"
    session_store=None,      # SessionOrchestrator — also update in-memory for current context
) -> None:
    """Persist the captured session to InvestigationState (durable) AND update the
    current in-memory SessionOrchestrator (for immediate use in the current context).

    This is the SINGLE write-path that replaces the write-to-both bridge.
    The durable write survives context reconstruction; the in-memory write serves
    the current dispatch without a round-trip to the DB.
    """
    try:
        await _store(investigation_id, auth_payload, target_base, session_store)
    except Exception as exc:
        logger.warning("store_session(%s) failed: %s", investigation_id, exc)


async def _store(
    investigation_id: str,
    auth_payload: dict,
    target_base: str,
    session_store,
) -> None:
    # ── Durable write (source of truth) ───────────────────────────────────────
    state = await load_state_async(investigation_id)
    state.captured_session = {
        **auth_payload,
        "target_base": target_base,
    }
    await save_state_async(state)
    logger.info(
        "session_persistence: stored session for %s (username=%r target_base=%r)",
        investigation_id,
        auth_payload.get("username", "?"),
        target_base,
    )

    # ── In-memory update (current context, no reconstruction needed) ──────────
    if session_store is not None:
        try:
            store_auth = getattr(session_store, "store_auth", None)
            if store_auth:
                store_auth(investigation_id, auth_payload)
            store_target = getattr(session_store, "store_target_auth", None)
            if store_target and target_base:
                store_target(target_base, auth_payload)
        except Exception as exc:
            logger.debug("store_session: in-memory update failed (non-fatal): %s", exc)


async def rehydrate_session(
    session_orch,           # SessionOrchestrator instance
    investigation_id: str,
) -> bool:
    """Load the captured session from InvestigationState and populate the
    SessionOrchestrator's in-memory caches.

    Called after every context reconstruction so a fresh SessionOrchestrator
    immediately has the captured session without a DB lookup on each get_auth call.

    Returns True if a session was found and loaded, False otherwise.
    """
    try:
        return await _rehydrate(session_orch, investigation_id)
    except Exception as exc:
        logger.debug("rehydrate_session(%s) failed: %s", investigation_id, exc)
        return False


async def _rehydrate(session_orch, investigation_id: str) -> bool:
    state = await load_state_async(investigation_id)
    rec = state.captured_session
    if not rec:
        return False

    # Extract cookies + username; target_base is stored alongside but not part of auth
    target_base = rec.get("target_base", "")
    auth_payload = {k: v for k, v in rec.items() if k != "target_base"}

    # Populate both in-memory stores
    try:
        store_auth = getattr(session_orch, "store_auth", None)
        if store_auth:
            store_auth(investigation_id, auth_payload)
        store_target = getattr(session_orch, "store_target_auth", None)
        if store_target and target_base:
            store_target(target_base, auth_payload)
    except Exception as exc:
        logger.debug("rehydrate_session: store failed: %s", exc)
        return False

    logger.info(
        "session_persistence: rehydrated session for %s (username=%r)",
        investigation_id,
        auth_payload.get("username", "?"),
    )
    return True
