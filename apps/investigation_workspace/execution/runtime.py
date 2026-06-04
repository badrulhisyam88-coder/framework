"""In-process execution runtime.

Tracks ExecutionRun instances in module-level memory while they animate.
Each run owns an ordered list of stages (one starts every STAGE_DELAY_MS)
and a list of results that materialise once all stages have finished. The
runner is a single asyncio task per run; the topology serializer reads
the current state synchronously, so the operator-facing graph evolves
naturally as the runner advances.

Single-process uvicorn (--reload) means a plain module-level dict is the
right storage: no DB churn, no migrations, lost on restart (which matches
the "live runtime" mental model).

Deterministic: the script for a given action_id is fixed; the runner just
animates it. There is no scoring or autonomous decision making.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass, field

# Phase 59b — scripts module imports removed. The canned-script
# execution mechanism (DEFAULT_SCRIPT / EXECUTION_SCRIPTS / for_action /
# Script / ResultSpec) is gone. _runner_from_probe is now the only
# execution path; kick_off requires probe_runner.

# Tuneables — kept low so the operator sees motion without waiting too long.
STAGE_DELAY_S       = 1.0    # Phase 41 — slower so causality reads cinematic
RESULT_PAUSE_S      = 0.55   # pause after last stage before results emerge
# Phase 42 — execution runs are now persistent forensic memory; no GC.
# Each completed run stays in _RUNS for the rest of the process lifetime so
# its stage + result nodes remain part of the investigation lineage.


# ── Run records ─────────────────────────────────────────────────────────


@dataclass
class StageState:
    label:        str
    started_at:   float
    completed_at: float | None = None
    # Phase 49 — real probes carry actions/tools/detected metadata so the
    # context panel can render the same reasoning view as bootstrap stages.
    actions:    tuple[str, ...] = ()
    tools:      tuple[str, ...] = ()
    detected:   tuple[str, ...] = ()
    confidence: str             = "—"


@dataclass
class ResultState:
    label:      str
    kind:       str
    emitted_at: float
    # Phase 49 — real probes attach concrete evidence (URLs fetched, paths
    # discovered, response bodies) so the operator can verify the result.
    evidence:   dict = field(default_factory=dict)
    # Phase 54 — structured exploit payload (see ResultEvent docstring
    # for the schema). None on legacy outcomes. Phase 56 — probe-emitted
    # next_actions live INSIDE this dict under the "next_actions" key,
    # not as a separate field on ResultState.
    payload:    dict | None = None


# Phase 58 — runtime-set context var carrying the originating finding's
# evidence dict to probe invocations. Lets a probe (e.g., the SQLi
# attack probe) read hints recorded by an earlier recon probe (e.g.,
# the SQLi recon probe's `detected_login_endpoints` list) without
# changing probe function signatures.
#
# Probes that don't read it stay unaffected. Probes that read it
# fall back gracefully when the var is empty (direct invocation,
# back-door route hits, tests).
#
# Default sentinel is None (not {}) because mutable defaults on
# ContextVar share the same object across all readers (ruff B039).
# Readers do `(FINDING_EVIDENCE_CTX.get() or {})` to handle the
# sentinel uniformly.
FINDING_EVIDENCE_CTX: ContextVar[dict | None] = ContextVar(
    "investigation_workspace.finding_evidence", default=None,
)

# Action id ContextVar — set before calling a probe so the probe can read
# which specific action_kind the operator clicked.  Needed when multiple
# action cards share the same probe_runner (e.g. api_method_* cards
# all route to the same probe but each must fire a different request).
# Default empty string — probes that don't read it stay unaffected.
ACTION_ID_CTX: ContextVar[str] = ContextVar(
    "investigation_workspace.action_id", default="",
)

# Operator inputs ContextVar — set by the execute route when the operator
# fills one or more input fields on an action card (e.g. api_method_*
# cards ask for path and method). The probe reads this dict to substitute
# values into the outgoing request without changing its function signature.
# Default None — probes that don't read it stay unaffected; readers do
# `(OPERATOR_INPUTS_CTX.get() or {})` for safety.
OPERATOR_INPUTS_CTX: ContextVar[dict | None] = ContextVar(
    "investigation_workspace.operator_inputs", default=None,
)

# Investigation ID ContextVar — set in _runner_from_probe so that probe
# functions (which have no investigation_id parameter) can route auth reads
# and writes to the correct per-investigation SessionOrchestrator.
# Default None — probes invoked directly (tests, back-door route hits)
# receive None; _get_session_orch() in probes.py falls back gracefully.
INVESTIGATION_ID_CTX: ContextVar[str | None] = ContextVar(
    "investigation_workspace.investigation_id", default=None,
)


@dataclass
class ExecutionRun:
    run_id:          str
    investigation_id: str
    action_id:       str
    parent_node_id:  str
    started_at:      float
    completed_at:    float | None = None
    stages:          list[StageState] = field(default_factory=list)
    results:         list[ResultState] = field(default_factory=list)
    # Phase 54b — the exploitation_path this run was executed FROM (the
    # path the operator chose when clicking a ghost or panel button). When
    # set, _emit_ghost_actions reads it directly as the source of truth
    # for ghost attribution, bypassing the action_kind reverse-lookup.
    # Optional for back-compat: runs that started before Phase 54b are
    # still attributed via the legacy reverse-lookup fallback.
    exploit_path_id: str | None = None
    # Explicit finding_id for DB lookups. Set when parent_node_id is NOT
    # disc-{finding_id} (e.g. mutate runs anchored under a result node for
    # mind-map hierarchy). None means derive from parent_node_id as before.
    finding_id: str | None = None


# Module-level state.
_RUNS:   dict[str, ExecutionRun] = {}
_BY_INV: dict[str, list[str]]    = {}

# Phase 57 — per-key dedup locks. The dedup key is
# (finding_id, action_kind, exploit_path_id). Lazy-created on first
# use; never deleted (memory-bounded by the count of distinct
# investigation-action-path triples, typically < 100).
#
# A per-key lock keeps two near-simultaneous kick_offs with the same
# dedup key from BOTH passing the find_active_run check before either
# registers its run. Global lock not used — that would serialize all
# unrelated kick_offs.
_DEDUP_LOCKS: dict[tuple[str, str, str], asyncio.Lock] = {}


def _get_dedup_lock(key: tuple[str, str, str]) -> asyncio.Lock:
    """Lazy-create (or return existing) the per-key lock.

    asyncio is cooperative single-threaded; this get-or-create runs
    synchronously without yielding, so no race in lock creation itself.
    """
    lock = _DEDUP_LOCKS.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _DEDUP_LOCKS[key] = lock
    return lock


# ── Public API ──────────────────────────────────────────────────────────


def active_runs(investigation_id: str) -> list[ExecutionRun]:
    """Runs currently visible on the topology for this investigation."""
    ids = _BY_INV.get(investigation_id, [])
    return [_RUNS[i] for i in ids if i in _RUNS]


def find_active_run(
    investigation_id: str,
    finding_id:       str,
    action_kind:      str,
    exploit_path_id:  str,
) -> ExecutionRun | None:
    """Phase 57 — return an active run matching the dedup key, or None.

    Dedup key: (finding_id, action_kind, exploit_path_id). "Active"
    means `completed_at is None`. Linear scan over the investigation's
    active runs — O(n) where n is typically small (< 20 active runs
    per investigation). Flag for future optimization if this becomes
    a hot path.

    The same action_kind under two different exploit paths on the
    same finding is NOT a duplicate — those are parallel
    investigation branches and both must run. The exploit_path_id
    component of the key enforces that distinction.

    Nested runs anchor under an outcome node rather than disc-{finding_id}.
    They carry an explicit finding_id field — match on that as a fallback
    so dedup works even when parent_node_id is an exec-* node.
    """
    disc_node_id     = f"disc-{finding_id}"
    target_action_id = f"suggestion:{action_kind}"
    expected_path    = exploit_path_id or ""
    for run in active_runs(investigation_id):
        if run.completed_at is not None:
            continue
        # Primary: disc-based parent; secondary: explicit finding_id on nested runs.
        if (run.parent_node_id != disc_node_id
                and run.finding_id != finding_id):
            continue
        if run.action_id != target_action_id:
            continue
        if (run.exploit_path_id or "") != expected_path:
            continue
        return run
    return None


def latest_run_for_action(
    investigation_id: str, action_id: str,
) -> ExecutionRun | None:
    """Most recent run (active or recently finished) for this action."""
    runs = [r for r in active_runs(investigation_id) if r.action_id == action_id]
    if not runs:
        return None
    return max(runs, key=lambda r: r.started_at)


def has_been_executed(investigation_id: str, finding_id: str, action_kind: str) -> bool:
    """True if any run (active or completed) exists for this finding + action_kind pair.

    Matches both disc-based parent_node_id (top-level runs) and explicit
    finding_id (nested runs whose parent is an exec-* outcome node).
    """
    disc_node_id     = f"disc-{finding_id}"
    target_action_id = f"suggestion:{action_kind}"
    return any(
        (r.parent_node_id == disc_node_id or r.finding_id == finding_id)
        and r.action_id == target_action_id
        for r in active_runs(investigation_id)
    )


def has_active_execution(investigation_id: str) -> bool:
    """True while any run in this investigation still has stages to do."""
    return any(r.completed_at is None for r in active_runs(investigation_id))


async def kick_off(
    *,
    investigation_id: str,
    action_id:        str,
    parent_node_id:   str,
    on_complete:      Callable[[], Awaitable[None]] | None = None,
    probe_runner:     Callable[[str], AsyncIterator],
    canonical_target: str = "",
    exploit_path_id:  str | None = None,
    dedup_key:        tuple[str, str, str] | None = None,
    finding_id:       str | None = None,
) -> ExecutionRun:
    """Spawn a runner for this action. Returns immediately.

    Phase 49 — `probe_runner` is now REQUIRED. It's a real async
    generator that yields StageEvent + ResultEvent records based on
    real HTTP traffic. canonical_target is the target URL the probe
    runs against.

    Phase 59b — the canned-script fallback path is gone. There is no
    `script` parameter. Callers that hit this without a probe_runner
    raise TypeError at call time.

    Phase 46 — `canonical_target` is part of the run's identity. The
    probe reads ONLY this — never re-derives a URL from anywhere else.

    Phase 54b — `exploit_path_id` records which exploitation_path the
    operator chose when activating this action. _emit_ghost_actions
    reads it as the source of truth for ghost attribution.

    Phase 57 — `dedup_key` is the (finding_id, action_kind, path_id)
    triple. When provided, kick_off acquires a per-key lock, checks
    `find_active_run`, and returns the existing active run if one is
    in flight — idempotent, no duplicate runner spawn.

    CALLER INVARIANT — when `dedup_key` is supplied, its third element
    (exploit_path_id) MUST equal the `exploit_path_id` kwarg passed to
    this function. If they diverge, `find_active_run` compares the
    dedup-key's path against the run's stored path and fails to match
    the previously registered run — dedup silently misses, allowing
    duplicate runs to spawn. The production caller (execute_suggestion
    route in api/routes.py) maintains this invariant by deriving both
    from the same source.
    """
    from sdk import Logger

    # Phase 57 — dedup path. Per-key lock around find_active_run AND
    # the registration write so two near-simultaneous kick_offs cannot
    # both pass the check.
    if dedup_key is not None:
        lock = _get_dedup_lock(dedup_key)
        async with lock:
            existing = find_active_run(
                investigation_id,
                dedup_key[0], dedup_key[1], dedup_key[2],
            )
            if existing is not None:
                Logger.info(
                    "execution.kick_off.dedup_hit",
                    extra={
                        "investigation_id": investigation_id,
                        "dedup_key":        list(dedup_key),
                        "existing_run_id":  existing.run_id,
                    },
                )
                return existing
            return await _create_and_register_run(
                investigation_id  = investigation_id,
                action_id         = action_id,
                parent_node_id    = parent_node_id,
                on_complete       = on_complete,
                probe_runner      = probe_runner,
                canonical_target  = canonical_target,
                exploit_path_id   = exploit_path_id,
                finding_id        = finding_id,
            )

    # No dedup_key — always creates a fresh run.
    return await _create_and_register_run(
        investigation_id  = investigation_id,
        action_id         = action_id,
        parent_node_id    = parent_node_id,
        on_complete       = on_complete,
        probe_runner      = probe_runner,
        canonical_target  = canonical_target,
        exploit_path_id   = exploit_path_id,
        finding_id        = finding_id,
    )


async def _create_and_register_run(
    *,
    investigation_id: str,
    action_id:        str,
    parent_node_id:   str,
    on_complete:      Callable[[], Awaitable[None]] | None,
    probe_runner:     Callable[[str], AsyncIterator],
    canonical_target: str,
    exploit_path_id:  str | None,
    finding_id:       str | None = None,
) -> ExecutionRun:
    """Phase 57 — extracted from kick_off so the dedup path can call it
    without code duplication. Creates the ExecutionRun, registers it in
    the module-level state, spawns the runner task. Returns the run."""
    from sdk import Logger
    Logger.info(
        "execution.kick_off",
        extra={
            "investigation_id": investigation_id,
            "action_id":        action_id,
            "parent_node_id":   parent_node_id,
            "canonical_target": canonical_target,
            "exploit_path_id":  exploit_path_id,
            "probe":            probe_runner.__name__,
            "stage":            "execution",
        },
    )

    run = ExecutionRun(
        run_id           = uuid.uuid4().hex[:12],
        investigation_id = investigation_id,
        action_id        = action_id,
        parent_node_id   = parent_node_id,
        started_at       = time.time(),
        exploit_path_id  = exploit_path_id,
        finding_id       = finding_id,
    )
    _RUNS[run.run_id] = run
    _BY_INV.setdefault(investigation_id, []).append(run.run_id)

    asyncio.create_task(
        _runner_from_probe(run, probe_runner, canonical_target, on_complete),
    )
    return run


# ── Internal — the actual driver ────────────────────────────────────────


# Phase 59b — `_runner` (canned-script driver) and `_materialise_result`
# removed alongside the broader canned-execution mechanism. The only
# runner is `_runner_from_probe` below — every kick_off now requires a
# real probe_runner.

# ── Phase 49 — event-driven runner for real probes ─────────────────────


async def _load_finding_evidence(parent_node_id: str) -> dict:
    """Phase 58 — read raw_data from the originating finding so the
    probe can consume recon hints. parent_node_id is `disc-{finding_id}`."""
    if not parent_node_id.startswith("disc-"):
        return {}
    finding_id = parent_node_id[len("disc-"):]
    from apps.scanner_orchestration.storage.finding_repo import (
        NormalizedFindingRepository,
    )
    from apps.validation.database import get_db
    async with get_db() as db:
        finding = await NormalizedFindingRepository(db).get_by_id(finding_id)
    return (finding.raw_data or {}) if finding else {}


async def _runner_from_probe(
    run:              ExecutionRun,
    probe_runner:     Callable,
    canonical_target: str,
    on_complete:      Callable[[], Awaitable[None]] | None,
) -> None:
    """Consume StageEvent / ResultEvent from a real probe.

    Stage lifecycle: a stage is appended as "running" (completed_at=None)
    the moment its StageEvent is received and stays running while the probe
    executes the corresponding phase.  When the *next* event arrives (another
    StageEvent or a ResultEvent) the previous stage is marked complete and a
    brief inter-stage pause lets the UI render the transition before the new
    state appears.  This means the operator always sees a running card that
    accurately describes the work in progress, not a card that completes
    before the work even starts.
    """
    from apps.investigation_workspace.probe.events import ResultEvent, StageEvent

    # Phase 58 — load the originating finding's evidence dict and
    # publish it via FINDING_EVIDENCE_CTX so the probe can read recon
    # hints (e.g., detected_login_endpoints from sqli_recon). Best-
    # effort: failures here never block the probe — they just mean
    # the probe re-enumerates whatever it needs.
    try:
        evidence_hints = await _load_finding_evidence(run.parent_node_id)
    except Exception:
        evidence_hints = {}
    FINDING_EVIDENCE_CTX.set(evidence_hints)
    ACTION_ID_CTX.set(run.action_id)
    INVESTIGATION_ID_CTX.set(run.investigation_id)

    pending_stage: StageState | None = None

    async def _complete_pending() -> None:
        """Mark the current running stage complete and pause for UI render."""
        nonlocal pending_stage
        if pending_stage is not None:
            pending_stage.completed_at = time.time()
            pending_stage = None
            await asyncio.sleep(STAGE_DELAY_S)

    try:
        async for evt in probe_runner(canonical_target):
            if isinstance(evt, StageEvent):
                # Complete the stage that was running during this phase's work,
                # then immediately surface the new stage as running.
                await _complete_pending()
                stage = StageState(
                    label       = evt.label,
                    started_at  = time.time(),
                    actions     = evt.actions,
                    tools       = evt.tools,
                    detected    = evt.detected,
                    confidence  = evt.confidence,
                )
                run.stages.append(stage)
                pending_stage = stage
            elif isinstance(evt, ResultEvent):
                # Complete the last running stage before the result appears.
                await _complete_pending()
                # Phase 58 — probes signal post-exploit capture via a
                # `_pending_capture` descriptor inside payload. The
                # probe doesn't know investigation_id, so the bundler
                # is invoked HERE where we have run.investigation_id.
                # On success we replace `_pending_capture` with
                # `captured_bundle_id` so the topology can emit the
                # Capture node.
                payload = evt.payload
                pending = (payload or {}).get("_pending_capture")
                if pending:
                    from apps.investigation_workspace.capture import (
                        capture_post_exploit,
                    )
                    finding_id = run.finding_id or (
                        run.parent_node_id[len("disc-"):]
                        if run.parent_node_id.startswith("disc-")
                        else run.parent_node_id
                    )
                    try:
                        bundle = await capture_post_exploit(
                            investigation_id = run.investigation_id,
                            finding_id       = finding_id,
                            action_id        = run.action_id,
                            exploit_path_id  = run.exploit_path_id or "",
                            session_state    = pending["session_state"],
                            target_base_url  = pending["target_base_url"],
                            endpoints        = pending["endpoints"],
                            exploit_request  = pending["exploit_request"],
                            exploit_response = pending["exploit_response"],
                            label            = pending.get("label", "Post-exploit capture"),
                            # Phase 57c — optional probe-supplied
                            # operator reproduction guide. Bundler
                            # prepends it as the first artifact.
                            reproduction_artifact = pending.get("reproduction_artifact"),
                            # Phase 59z — optional probe-supplied
                            # one-click impersonation bookmarklet.
                            # OPERATOR-ACCEPTED RISK: see the
                            # ArtifactBundle.bookmarklet_href field
                            # docstring in capture/bundler.py for the
                            # full risk reasoning.
                            bookmarklet_href = pending.get("bookmarklet_href"),
                            # Phase 60a — optional probe-captured
                            # extra artifacts (e.g. whoami_output.txt).
                            extra_artifacts  = pending.get("extra_artifacts"),
                            captured_value   = pending.get("captured_value"),
                        )
                        # Rewrite payload: drop the descriptor, add the id.
                        payload = {k: v for k, v in payload.items()
                                   if k != "_pending_capture"}
                        payload["captured_bundle_id"] = bundle.bundle_id
                    except Exception as e:   # pragma: no cover — defensive
                        from sdk import Logger
                        Logger.warning(
                            "execution_runtime.capture_failed",
                            extra={"action_id": run.action_id, "msg": str(e),
                                   "exc_type": type(e).__name__},
                        )
                        payload = {k: v for k, v in payload.items()
                                   if k != "_pending_capture"}
                        payload["captured_bundle_id"] = None
                run.results.append(ResultState(
                    label      = evt.label,
                    kind       = evt.kind,
                    emitted_at = time.time(),
                    evidence   = evt.evidence,
                    payload    = payload,
                ))
                await asyncio.sleep(0.15)
                # Merge probe evidence back into finding raw_data so that subsequent
                # probes on the same finding can read it via FINDING_EVIDENCE_CTX.
                # Best-effort — failures never block the probe.
                if evt.evidence and run.parent_node_id.startswith("disc-"):
                    _finding_id = run.parent_node_id[len("disc-"):]
                    try:
                        from apps.scanner_orchestration.storage.finding_repo import (
                            NormalizedFindingRepository,
                        )
                        from apps.validation.database import get_db
                        async with get_db() as _db:
                            await NormalizedFindingRepository(_db).merge_raw_data(
                                _finding_id, evt.evidence
                            )
                    except Exception:
                        pass  # best-effort; does not affect probe output
            # Other event types are ignored silently — keeps the runtime
            # forward-compatible with new event vocab.

        # Probe finished — complete any stage still running.
        await _complete_pending()
        run.completed_at = time.time()

        if on_complete is not None:
            try:
                await on_complete()
            except Exception as e:  # pragma: no cover — defensive
                from sdk import Logger
                Logger.warning(
                    "execution_runtime.on_complete_failed",
                    extra={"action_id": run.action_id, "msg": str(e)},
                )
    except Exception as e:   # pragma: no cover — defensive
        from sdk import Logger
        Logger.warning(
            "execution_runtime.probe_runner_failed",
            extra={"action_id": run.action_id, "msg": str(e),
                   "exc_type": type(e).__name__},
        )
        # Complete any stage that was left running before the exception.
        if pending_stage is not None:
            pending_stage.completed_at = time.time()
        # Surface the failure as a result node so the operator sees what
        # went wrong instead of a silent hang.
        run.results.append(ResultState(
            label      = f"probe failed: {e!s}",
            kind       = "note",
            emitted_at = time.time(),
            evidence   = {"error_type": type(e).__name__, "message": str(e)},
        ))
        run.completed_at = time.time()
