"""Phase D — Unknown Artifact store.

When evaluate_verdict returns match_kind="no_concept_match", a structured
Unknown Artifact is created and parked here (non-blocking).  Unknowns accumulate
across runs AND labs in their own table (agent_loop_unknowns in validation.db),
designed for cross-run batch review.

Why a real table, not the agent_state blob:
  - Unknowns survive investigation deletion and are a cross-run BACKLOG.
  - They need to be queryable by status across all investigations.
  - Writing them into the per-investigation blob would make them invisible
    to the batch-review query (which spans multiple investigations).

Public API:
  park_unknown_async(...)             fire-and-forget; non-blocking
  list_unknowns_async(status, limit)  batch listing (cross-investigation)
  update_unknown_status_async(id, status, resolution)  resolve/ignore
  count_pending_async()               for Zone B badge
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

logger = logging.getLogger("conductor.unknown_store")

_VALID_STATUSES = frozenset({"pending_review", "resolved", "ignored"})


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class UnknownArtifact:
    id:               str
    created_at:       str
    investigation_id: str
    context:          str   # "exploitation, finding=<type>, attempting=<concept/engine>"
    raw_result:       str   # JSON-serialized tool output / artifact
    expected_concept: str | None
    evidence:         dict  # {engine_id, state, finding_id, raw_artifact_keys, ...}
    status:           str = "pending_review"
    resolution:       str | None = None


def make_unknown_artifact(
    investigation_id: str,
    context:          str,
    raw_result:       "dict | str | None",
    expected_concept: str | None = None,
    evidence:         "dict | None" = None,
) -> UnknownArtifact:
    """Build a structured UnknownArtifact from evaluator output.

    raw_result is serialized to JSON string for storage.
    evidence is a free dict of whatever context is available.
    """
    now = datetime.now(timezone.utc).isoformat()
    if isinstance(raw_result, (dict, list)):
        raw_str = json.dumps(raw_result, default=str)
    else:
        raw_str = str(raw_result or "")

    return UnknownArtifact(
        id               = str(uuid.uuid4()),
        created_at       = now,
        investigation_id = investigation_id,
        context          = context or "",
        raw_result       = raw_str,
        expected_concept = expected_concept or None,
        evidence         = dict(evidence or {}),
        status           = "pending_review",
        resolution       = None,
    )


# ── Dedup fingerprint ─────────────────────────────────────────────────────────

def _fingerprint(investigation_id: str, context: str, raw_result: str) -> str:
    """Stable fingerprint for dedup: same investigation + context + raw_result."""
    import hashlib
    key = f"{investigation_id}|{context}|{raw_result[:500]}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ── Async store operations ────────────────────────────────────────────────────

async def store_unknown_artifact_async(artifact: UnknownArtifact) -> None:
    """Insert into agent_loop_unknowns.  Never raises; logs errors.

    Uses INSERT OR IGNORE — the primary key (uuid) prevents exact duplicates.
    """
    try:
        from apps.validation.database import get_db
        async with get_db() as db:
            await db.execute(
                """INSERT OR IGNORE INTO agent_loop_unknowns
                   (id, created_at, investigation_id, context,
                    raw_result, expected_concept, evidence, status, resolution)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    artifact.id,
                    artifact.created_at,
                    artifact.investigation_id,
                    artifact.context,
                    artifact.raw_result,
                    artifact.expected_concept,
                    json.dumps(artifact.evidence, default=str),
                    artifact.status,
                    artifact.resolution,
                ),
            )
            await db.commit()
        logger.debug(
            "unknown_store: parked unknown %s inv=%s context=%r",
            artifact.id[:8], artifact.investigation_id, artifact.context[:60],
        )
    except Exception as exc:
        logger.warning("unknown_store: store failed — %s", exc)


async def _is_duplicate_async(
    investigation_id: str,
    context:          str,
    raw_result:       str,
) -> bool:
    """Return True if a pending_review artifact with the same context+raw_result exists."""
    try:
        from apps.validation.database import get_db
        async with get_db() as db:
            cur = await db.execute(
                """SELECT id FROM agent_loop_unknowns
                   WHERE investigation_id=? AND context=?
                     AND raw_result=? AND status='pending_review'
                   LIMIT 1""",
                (investigation_id, context, raw_result[:500]),
            )
            row = await cur.fetchone()
        return row is not None
    except Exception as exc:
        logger.debug("unknown_store: dedup check failed — %s", exc)
        return False  # If check fails, allow creation (better to duplicate than lose data)


async def park_unknown_async(
    investigation_id:        str,
    context:                 str,
    raw_result:              "dict | str | None",
    expected_concept:        str | None = None,
    evidence:                "dict | None" = None,
    # Structured-error fields (unknown-resolution-playbook.md Part 1).
    # Stored inside `evidence` JSON blob — no DB schema change.
    what_was_tried:          str | None = None,   # engine + objective at the time
    unclassifiable_signal:   str | None = None,   # specific signal that couldn't be matched
    suggested_concept_shape: "dict | None" = None, # best-effort authoring starting point
) -> None:
    """Create and store an Unknown Artifact.  NON-BLOCKING (fire-and-forget).

    Deduplicates: same investigation + context + raw_result creates at most one
    pending_review artifact.  Subsequent identical results are silently dropped.

    The three optional structured-error fields (what_was_tried, unclassifiable_signal,
    suggested_concept_shape) are merged into the evidence dict for playbook-driven
    resolution.  Callers that omit them get the existing behaviour unchanged.
    """
    try:
        _ev = dict(evidence or {})
        if what_was_tried:
            _ev["what_was_tried"] = what_was_tried
        if unclassifiable_signal:
            _ev["unclassifiable_signal"] = unclassifiable_signal
        if suggested_concept_shape:
            _ev["suggested_concept_shape"] = suggested_concept_shape

        artifact = make_unknown_artifact(
            investigation_id = investigation_id,
            context          = context,
            raw_result       = raw_result,
            expected_concept = expected_concept,
            evidence         = _ev,
        )
        # Dedup: check before inserting
        is_dup = await _is_duplicate_async(
            investigation_id, artifact.context, artifact.raw_result
        )
        if is_dup:
            logger.debug(
                "unknown_store: dedup — skipping duplicate unknown for inv=%s context=%r",
                investigation_id, context[:60],
            )
            return
        await store_unknown_artifact_async(artifact)
    except Exception as exc:
        logger.warning("park_unknown_async: failed — %s", exc)


async def list_unknowns_async(
    status:          str | None = None,
    investigation_id: str | None = None,
    limit:           int = 50,
) -> list[dict]:
    """List Unknown Artifacts, newest first.

    Filters by status if provided (pending_review | resolved | ignored).
    Filters by investigation_id if provided (cross-run when None).
    Returns list of dicts (JSON-serializable).
    """
    try:
        from apps.validation.database import get_db

        where_clauses = []
        params: list = []
        if status:
            where_clauses.append("status=?")
            params.append(status)
        if investigation_id:
            where_clauses.append("investigation_id=?")
            params.append(investigation_id)
        where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        params.append(limit)

        async with get_db() as db:
            cur = await db.execute(
                f"""SELECT id, created_at, investigation_id, context, raw_result,
                           expected_concept, evidence, status, resolution
                    FROM agent_loop_unknowns
                    {where}
                    ORDER BY created_at DESC
                    LIMIT ?""",
                params,
            )
            rows = await cur.fetchall()

        results = []
        for r in rows:
            evidence = {}
            try:
                evidence = json.loads(r[6]) if r[6] else {}
            except Exception:
                pass
            results.append({
                "id":               r[0],
                "created_at":       r[1],
                "investigation_id": r[2],
                "context":          r[3],
                "raw_result":       r[4][:300] if r[4] else "",  # truncate for display
                "expected_concept": r[5],
                "evidence":         evidence,
                "status":           r[7],
                "resolution":       r[8],
            })
        return results
    except Exception as exc:
        logger.warning("list_unknowns_async: failed — %s", exc)
        return []


async def count_pending_async(investigation_id: str | None = None) -> int:
    """Return count of pending_review artifacts (cross-run unless investigation_id given)."""
    try:
        from apps.validation.database import get_db
        if investigation_id:
            query = ("SELECT COUNT(*) FROM agent_loop_unknowns "
                     "WHERE status='pending_review' AND investigation_id=?")
            params = (investigation_id,)
        else:
            query = "SELECT COUNT(*) FROM agent_loop_unknowns WHERE status='pending_review'"
            params = ()
        async with get_db() as db:
            cur = await db.execute(query, params)
            row = await cur.fetchone()
        return int(row[0]) if row else 0
    except Exception as exc:
        logger.debug("count_pending_async: failed — %s", exc)
        return 0


async def update_unknown_status_async(
    artifact_id: str,
    status:      str,
    resolution:  str | None = None,
) -> bool:
    """Update the status of an Unknown Artifact.  Returns True on success.

    status must be one of: pending_review, resolved, ignored.
    """
    if status not in _VALID_STATUSES:
        logger.warning("update_unknown_status: invalid status %r", status)
        return False
    try:
        from apps.validation.database import get_db
        from datetime import datetime, timezone
        async with get_db() as db:
            await db.execute(
                "UPDATE agent_loop_unknowns SET status=?, resolution=? WHERE id=?",
                (status, resolution, artifact_id),
            )
            await db.commit()
        logger.debug("update_unknown_status: %s → %s", artifact_id[:8], status)
        return True
    except Exception as exc:
        logger.warning("update_unknown_status: failed — %s", exc)
        return False
