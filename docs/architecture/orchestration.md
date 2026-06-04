# Orchestration Architecture

## Purpose

This document is the definitive contract for the new orchestration system in
ai-assist-tool. The problem it solves: coordinating multiple security engines
(HTTP probes, nmap, nuclei, ZAP, Metasploit, validation plugins) through a
unified investigation flow, without leaking engine names to the operator and
without engines interfering with each other's state, auth sessions, or rate
limits. All PRs from PR A onward implement this design exactly. Deviations
require explicit operator approval and an update to this document.

---

## Design principles

- Operator drives car. Engine names never surface in UI. The operator sees
  phases, findings, and exploitation paths — not "nmap" or "nuclei".
- Engines are stateless and replaceable. A swap in Level 1 has zero effect on
  Level 2 or 3.
- Single ingress for findings. All findings — from all engines — enter via the
  Findings Orchestrator. No side-channels.
- Architecture-first. Nothing is wired to a real engine until Conductor and all
  five orchestrators are in place and verified. Engine explosion killed the old
  design.
- Three orchestration levels, no more. Adding a fourth level is not permitted.
- Session inheritance is non-negotiable. Engines read auth from the Session
  Orchestrator. They never authenticate themselves.
- No lab-specific code. Probes and engines may not contain host checks or
  conditional logic keyed to a specific lab target.
- Documentation-first. Every PR ends by updating the canonical .md files.
  Context loss across restarts is a first-class risk; docs are the mitigation.

---

## Three-level overview

```
  ┌──────────────────────────────────────────────────────────────┐
  │  LEVEL 3 — CONDUCTOR                                         │
  │  Knows nothing about individual engines.                     │
  │  Receives operator intent; emits investigation-level events. │
  └──────────────────────────────┬───────────────────────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
  ┌───────▼──────────────────────▼──────────────────────▼───────┐
  │  LEVEL 2 — FIVE DOMAIN ORCHESTRATORS                        │
  │                                                             │
  │  Phase        Execution      Findings    Chain    Session   │
  │  Orchestrator Orchestrator   Orch        Orch     Orch      │
  │                                                             │
  │  Each owns one concern.                                     │
  │  Cross-orchestrator calls go through narrow interfaces.     │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
  ┌───────▼──────────────────────▼──────────────────────▼───────┐
  │  LEVEL 1 — ENGINES                                          │
  │  Stateless. Conform to Engine ABC.                          │
  │  nmap | nuclei | ZAP | HTTP probes | validation plugins |   │
  │  Metasploit | ... (future engines added here)              │
  └─────────────────────────────────────────────────────────────┘
```

Three levels because two collapses orchestrator concerns into a god object,
and four introduces cross-layer coupling. The boundary between L3 and L2 is
intent vs. mechanism; the boundary between L2 and L1 is coordination vs.
execution.

---

## Conductor specification

### Responsibilities

- Receive operator intent ("start investigation against target X with config Y").
- Instantiate investigation context (id, target, configuration, timestamp).
- Boot and hold references to the five orchestrators with the shared context.
- Subscribe to high-level status events from each orchestrator.
- Emit investigation-level events to the UI event stream.
- Handle operator stop signal — broadcast cancel to all orchestrators, wait for
  clean exit, log unclean exits.
- Persist investigation lifecycle state to SQLite for restart recovery.

### Public interface

```python
class Conductor:
    async def start_investigation(
        self,
        target: str,
        config: dict,
    ) -> str:
        # Returns investigation_id. Boots orchestrators, begins Recon phase.
        ...

    async def cancel_investigation(self, investigation_id: str) -> None:
        # Broadcasts cancel to all orchestrators. Waits up to 10s for clean exit.
        ...

    async def get_investigation_status(self, investigation_id: str) -> dict:
        # Returns lifecycle state, active phase, finding count, chain depth.
        ...

    async def list_active_investigations(self) -> list[dict]:
        # Returns all non-terminal investigations with summary status.
        ...
```

### What Conductor does NOT do

- Does not know individual engine names.
- Does not read raw findings.
- Does not manage per-target rate limits.
- Does not make exploitation decisions.
- Does not route next_actions.
- Does not hold auth tokens.

### State managed by Conductor

- Active investigations registry — in-memory dict keyed by `investigation_id`,
  backed by SQLite for restart recovery.
- Investigation lifecycle state — `CREATED | RUNNING | COMPLETED | FAILED |
  CANCELLED`.

---

## Domain Orchestrator specifications

### Phase Orchestrator

#### Responsibilities

- Owns the investigation phase state machine: `Recon → Enumeration →
  Exploitation`.
- Defines and enforces phase transition rules. A phase is complete when all
  **phase-initial engines** (those dispatched when the phase started) have
  finished. Chain-dispatched engines (spawned by Chain Orchestrator mid-phase
  as next_actions fire) do not block phase transition; they continue running
  under the new phase's context until they complete or are cancelled.
- Emits phase status events consumed by the UI phase badges.

#### Public interface

```python
class PhaseOrchestrator:
    async def advance_if_ready(self, investigation_id: str) -> None:
        # Checks completion criteria for current phase; transitions if met.
        ...

    def current_phase(self, investigation_id: str) -> str:
        # Returns "recon" | "enumeration" | "exploitation" | "complete".
        ...

    def phase_history(self, investigation_id: str) -> list[dict]:
        # Returns list of {phase, started_at, completed_at} records.
        ...
```

#### What it does NOT do

- Does not know which engines ran during a phase.
- Does not track individual engine completion.
- Does not dispatch engines.
- Does not read finding content.

#### State managed

- Per investigation: current phase, time entered, phase history.
- Phase-initial engine count and completion counter per investigation —
  incremented only for engines dispatched by Phase Orchestrator at phase
  start, not for chain-dispatched engines. Phase transition fires when
  this counter reaches the expected count.
- Persistence: SQLite (`orchestration.db`, `phase_state` table).

#### Events emitted

- `phase_started` — when a phase begins.
- `phase_completed` — when all completion criteria for a phase are met.
- `phase_failed` — when a phase exceeds its timeout or a fatal error occurs.

#### Events subscribed to

- `engine_completed` from Execution Orchestrator — filtered to phase-initial
  engines only. Each completion increments the phase counter; when the counter
  reaches the expected phase-initial count, the phase transitions. Events from
  chain-dispatched engines are ignored for phase completion purposes.

#### Talks to

- Conductor (status reports via event emission).
- Execution Orchestrator (engine dispatch at phase start; engine tagging so
  phase-initial vs. chain-dispatched runs are distinguishable).

---

### Execution Orchestrator

#### Responsibilities

- Owns engine lifecycle: start, health monitoring, graceful stop, kill.
- Owns concurrency policy enforcement (see Concurrency Policy Matrix).
- Enforces per-investigation resource limits (max concurrent engines).
- Dispatches engines based on current phase and chain triggers from Chain
  Orchestrator.
- Consults Session Orchestrator before firing any engine (rate limit check,
  auth readiness check).
- Forwards engine output to Findings Orchestrator as it streams in.

#### Public interface

```python
class ExecutionOrchestrator:
    async def dispatch(
        self,
        investigation_id: str,
        engine_id: str,
        target: str,
        config: dict,
    ) -> str:
        # Returns run_id. Checks mutex, queues if blocked, fires when safe.
        ...

    async def cancel_all(self, investigation_id: str) -> None:
        # Sends cancel() to every active engine under this investigation.
        ...

    def running_engines(self, investigation_id: str) -> list[dict]:
        # Returns list of {engine_id, run_id, started_at, status}.
        ...

    async def engine_health(self, engine_id: str) -> EngineHealth:
        ...
```

#### What it does NOT do

- Does not read finding content.
- Does not decide which engines to run (Phase Orchestrator + Chain Orchestrator
  drive dispatch decisions).
- Does not store session tokens.
- Does not emit UI events directly (routes engine output through Findings
  Orchestrator).

#### State managed

- Running engine instances — in-memory dict keyed by `run_id`; reconciled from
  SQLite on restart (any "running" rows from last session are marked "unknown"
  and defensively killed). Each record is tagged at dispatch time as either
  `phase_initial` (dispatched by Phase Orchestrator at phase start) or
  `chain_dispatched` (dispatched by Chain Orchestrator via next_actions). This
  tag lets Phase Orchestrator query only the subset it cares about.
- Engine roster — registered engines loaded at startup, held in-memory.

#### Events emitted

- `engine_started` — when a run begins.
- `engine_completed` — when a run exits cleanly.
- `engine_failed` — when a run crashes or times out.
- `engine_killed` — when cancel() was sent and the process exited.

#### Events subscribed to

- None. Driven by dispatch calls from Phase and Chain orchestrators.

#### Talks to

- Session Orchestrator (pre-dispatch: "OK to fire engine X against target Y?").
- Findings Orchestrator (forward engine output).
- Phase Orchestrator (notify on engine_completed so phase transitions can be
  evaluated).

---

### Findings Orchestrator

#### Responsibilities

- Provides the single ingress endpoint for all engine output.
- Translates engine-native output formats into the unified finding schema.
- Deduplicates findings: same `finding_id` from `finding_id.py` generator =
  merge, do not create a second record.
- Correlates findings: populate `related_findings` links where correlation
  criteria are met (same service, same CVE family, overlapping evidence).
- Streams clean, deduplicated findings to the UI event bus.

#### Public interface

```python
class FindingsOrchestrator:
    async def ingest(
        self,
        investigation_id: str,
        engine_id: str,
        raw_output: dict,
    ) -> str | None:
        # Translates, deduplicates, persists, and streams.
        # Returns finding_id if a new or updated finding was emitted; None if
        # the input was a duplicate with no new data.
        ...

    def get_finding(self, finding_id: str) -> dict | None:
        ...

    def list_findings(self, investigation_id: str) -> list[dict]:
        ...
```

#### What it does NOT do

- Does not dispatch engines.
- Does not evaluate next_actions (that is Chain Orchestrator's job).
- Does not hold auth tokens.
- Does not know which phase produced a finding.

#### State managed

- Stateless at runtime. Findings persist via the existing finding storage layer
  (SQLite or in-memory store). The orchestrator is a processing pipeline, not a
  store.

#### Events emitted

- `finding_created` — first time a `finding_id` is seen.
- `finding_updated` — a duplicate `finding_id` arrived with additional evidence.
- `finding_correlated` — a `related_findings` link was established.

#### Events subscribed to

- None. Driven by `ingest()` calls from Execution Orchestrator.

#### Talks to

- Chain Orchestrator (forwards each new/updated finding so next_actions can be
  evaluated).

---

### Chain Orchestrator

#### Responsibilities

- Reads `next_actions` from each new finding forwarded by Findings Orchestrator.
- Classifies each next_action by trigger type: `auto_fire`,
  `operator_arm_required`, or `operator_confirm_required`.
- Dispatches `auto_fire` actions via Execution Orchestrator after checking
  Session Orchestrator (rate limit, auth).
- Surfaces `operator_arm_required` and `operator_confirm_required` actions in
  the UI without firing them.
- Tracks chain depth using two mechanisms and enforces both caps:
  - **Linear chain depth** — counted per branch (keyed by root finding ID),
    capped at 5 by default. Stops forward chains that grow too deep.
  - **Cycle detection** — counted per dispatched engine_id within an
    investigation, capped at 3 by default. Stops self-referential next_actions
    cycles. Cycle findings have unique IDs per emission (to pass dedup), so
    linear depth alone cannot catch cycles — the engine_id counter is the
    correct signal.
- Emits graph edge events for UI mind-map rendering.

#### Public interface

```python
class ChainOrchestrator:
    async def evaluate_finding(
        self,
        investigation_id: str,
        finding: dict,
    ) -> None:
        # Reads next_actions, classifies, dispatches or surfaces.
        ...

    async def operator_arm(
        self,
        investigation_id: str,
        action_id: str,
    ) -> None:
        # Arms an operator_arm_required action; fires it via Execution Orch.
        ...

    async def operator_confirm(
        self,
        investigation_id: str,
        action_id: str,
    ) -> None:
        # Confirms and fires an operator_confirm_required action.
        ...

    def chain_depth(self, investigation_id: str, branch_id: str) -> int:
        ...
```

#### What it does NOT do

- Does not translate or store findings.
- Does not manage auth or sessions.
- Does not render UI directly.
- Does not auto-fire when Session Orchestrator denies the request.

#### State managed

- Chain history — SQLite (`chain_events` table): which action was triggered by
  which finding, when, and with what result.
- Linear chain depth tracker — in-memory counter per `(investigation_id,
  root_finding_id)`, snapshotted to SQLite on each increment. Caps forward
  chain depth at 5 (default, configurable).
- Cycle detection counter — in-memory counter per `(investigation_id,
  engine_id)`, tracking how many times a given engine has been chain-dispatched
  within this investigation. Caps at 3 (default, configurable). This counter
  is the correct cycle gate because cycle findings must have unique IDs per
  emission to survive the FindingsOrchestrator dedup check — meaning linear
  depth alone sees each cycle iteration as a fresh branch at depth 0.

#### Events emitted

- `chain_auto_fired` — an auto_fire action was dispatched.
- `chain_depth_limit_reached` — a branch hit the cap; no further auto-fires on
  that branch.
- `chain_operator_arm_pending` — an action is awaiting operator arming.
- `chain_operator_confirm_pending` — an action is awaiting operator confirmation.
- `chain_edge` — a graph edge between a finding and an action, consumed by the
  UI mind-map renderer.

#### Events subscribed to

- `finding_created` / `finding_updated` from Findings Orchestrator.

#### Talks to

- Execution Orchestrator (dispatch auto-fire actions).
- Session Orchestrator (pre-dispatch check).
- Findings Orchestrator (none; receives from it via event subscription).

---

### Session Orchestrator

#### Responsibilities

- Owns `_API_AUTH_STORE` per investigation — the sole source of auth tokens and
  session cookies for all engines.
- Maintains a per-target rate limiter — tracks request budget and cooldown
  windows; returns "OK" or "wait Ns" to dispatch callers.
- Maintains per-target connection pools for reuse across engines.
- Performs target type detection: local / private-range / external /
  WAF-fronted. Detection result informs concurrency limits and chain depth caps.
- Provides a single decision endpoint: "is it safe to fire engine X against
  target Y right now?" — consulted by both Execution Orchestrator and Chain
  Orchestrator before any dispatch.
- Engines pull auth from this orchestrator via `get_session(target)`. They
  never re-authenticate.

#### Public interface

```python
class SessionOrchestrator:
    async def get_session(self, target: str) -> SessionStore:
        # Returns the current auth store for the target.
        ...

    async def can_dispatch(
        self,
        target: str,
        engine_capabilities: EngineCapabilities,
    ) -> tuple[bool, float]:
        # Returns (allowed, wait_seconds). wait_seconds is 0.0 if allowed.
        ...

    async def record_request(self, target: str) -> None:
        # Called by engines (via OutputChannel) to track request count.
        ...

    async def detect_target_type(self, target: str) -> str:
        # Returns "local" | "private" | "external" | "waf_fronted".
        ...

    def store_auth(self, target: str, auth: dict) -> None:
        # Called once when credentials are captured; updates _API_AUTH_STORE.
        ...
```

#### What it does NOT do

- Does not dispatch engines.
- Does not read finding content.
- Does not decide which phase to run.
- Does not authenticate against targets directly (authentication is done by the
  probe/engine that captures credentials; the result is stored here via
  `store_auth`).

#### State managed

- `_API_AUTH_STORE` — in-memory dict keyed by target; optionally snapshotted to
  SQLite for session persistence across restarts.
- Rate limit budgets — in-memory token-bucket per target; reset on cooldown
  expiry.
- Connection pools — in-memory, per target.
- Target type cache — in-memory, refreshed if target config changes.

#### Events emitted

- `rate_limit_throttled` — dispatch blocked; caller told to wait.
- `target_type_detected` — first time target type is established for an
  investigation.

#### Events subscribed to

- None. Consulted via direct calls.

#### Talks to

- Nobody initiates; all calls are inbound.

---

## Engine interface contract

### The ABC

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class Engine(ABC):
    @abstractmethod
    async def run(
        self,
        target: str,
        config: dict,
        session_store: "SessionStore",
        output_channel: "OutputChannel",
    ) -> "EngineResult":
        ...

    @abstractmethod
    async def cancel(self) -> None:
        ...

    @abstractmethod
    def health_check(self) -> "EngineHealth":
        ...

    @property
    @abstractmethod
    def capabilities(self) -> "EngineCapabilities":
        ...
```

### Supporting dataclasses

```python
@dataclass
class EngineResult:
    run_id: str
    status: str               # "completed" | "cancelled" | "failed"
    finding_count: int
    duration_ms: int
    error: str | None = None


@dataclass
class EngineHealth:
    engine_id: str
    available: bool           # binary is present and responsive
    degraded: bool            # available but capability reduced
    reason: str | None = None # if degraded or unavailable


@dataclass
class EngineCapabilities:
    engine_id: str
    phases: list[str]         # ["recon"] | ["enumeration"] | etc.
    finding_types: list[str]  # finding type strings this engine produces
    resource_cost: str        # "low" | "medium" | "high"
    concurrency_safe: bool    # can run concurrently with same engine type


class SessionStore:
    # Interface only — implemented by Session Orchestrator
    def get_cookies(self, target: str) -> dict: ...
    def get_headers(self, target: str) -> dict: ...
    def get_credentials(self, target: str) -> dict | None: ...


class OutputChannel:
    # Interface only — implemented by Execution Orchestrator
    async def emit_finding(self, raw_output: dict) -> None: ...
    async def emit_stage(self, stage_name: str, detail: dict) -> None: ...
    async def record_request(self) -> None: ...
```

### Conformance rules

- Engines must be stateless across `run()` calls. No instance variables that
  persist between runs.
- Engines must read all auth from `session_store`. Never call a login endpoint
  from within an engine.
- Engines must push findings to `output_channel.emit_finding()` as they emerge.
  Do not buffer and dump at the end — the operator watches findings stream in.
- Engines must respect `cancel()` within 5 seconds. Kill subprocesses; close
  sockets; do not block the event loop.
- Engines must report `capabilities` truthfully. The Execution Orchestrator
  uses `capabilities.concurrency_safe` and `phases` to enforce the concurrency
  matrix and route dispatch decisions.
- Engines must not create asyncio primitives (`Event`, `Queue`, `Lock`,
  `Semaphore`, `Future`, `Task`) in `__init__` or at class definition time.
  Create them inside `run()` so they bind to the correct event loop. Engines
  are registered as singletons at import time; their `__init__` runs in the
  import-time loop, but `run()` executes in the investigation's loop — these
  may differ, and creating primitives in `__init__` raises
  `RuntimeError: bound to a different event loop` at test or restart time.

### Engine registration

```python
from apps.scanner_orchestration.engines.registry import engine_registry

@engine_registry.register
class NmapEngine(Engine):
    ...
```

The `engine_registry` is loaded at application startup; `Execution Orchestrator`
holds a reference to the registry. Adding a new engine requires only the
decorator — no changes to orchestrator code.

---

## Findings flow

```
  Engine 1 ──┐
  Engine 2 ──┼──► output_channel.emit_finding()
  Engine N ──┘           │
                         ▼
              Findings Orchestrator: ingest()
                         │
                         ▼
               Translation layer
               (engine-native dict → unified FindingEvent schema)
                         │
                         ▼
               Dedup check
               (same finding_id from finding_id.py → merge; new id → insert)
                         │
                         ▼
               Correlation pass
               (populate related_findings; emit finding_correlated events)
                         │
                         ▼
               UI event stream
               (finding_created | finding_updated events)
                         │
                         ▼
               Chain Orchestrator: evaluate_finding()
               (next_actions classification and dispatch)
```

**Translation**: each engine registers a translator function alongside its
class. The translator maps from the engine's raw output dict to a `FindingEvent`
with `id`, `confidence`, `type`, `title`, `evidence`, `next_actions`. No
orchestrator code contains engine-specific parsing logic.

**Dedup**: `finding_id.py` generates deterministic IDs from (target, type,
evidence fingerprint). Same ID on re-entry → update existing record, emit
`finding_updated`. Different ID → insert, emit `finding_created`.
Finding IDs (fnd_xxx format from `generate_finding_id`) must be explicitly
passed to `NormalizedFinding` as `finding_id=evt.id` in `_persist`
(routes.py); the `default_factory` fallback is `uuid4()`, which breaks
FilterOrchestrator UPDATEs (all WHERE clauses match 0 rows).

**Correlation**: post-dedup pass checks for shared service, CVE family, or
overlapping payload evidence. Links are stored in `related_findings`; the
operator sees them as graph edges.

---

## Chain flow

```
  Finding emitted with next_actions field
            │
            ▼
  Chain Orchestrator: evaluate_finding()
            │
            ├─► action.trigger == "auto_fire"?
            │        │
            │        ├─► Step 1: linear_depth(root_finding_id) >= 5?
            │        │       └─► emit chain_depth_exceeded; stop branch
            │        │
            │        ├─► Step 2: engine_dispatch_count(engine_id) >= 3?
            │        │       └─► emit chain_depth_exceeded (cycle); stop
            │        │
            │        └─► Step 3: Session Orchestrator: can_dispatch()?
            │                ├─► yes → Execution Orchestrator: dispatch()
            │                │         linear_depth++; engine_count++;
            │                │         emit chain_auto_fired
            │                └─► no  → defer; retry after wait_seconds
            │
            ├─► action.trigger == "operator_arm_required"?
            │        └─► emit chain_operator_arm_pending; surface in UI
            │            (no fire until operator calls operator_arm())
            │
            └─► action.trigger == "operator_confirm_required"?
                     └─► emit chain_operator_confirm_pending; surface in UI
                         (no fire until operator calls operator_confirm())
```

**Linear depth** (Step 1): capped at 5 per branch (a branch is a chain of
auto-fires originating from a single root finding). Counts unique finding
hops forward through the chain.

**Cycle detection** (Step 2): capped at 3 per engine_id per investigation.
Necessary because cycle findings must have unique IDs per emission to pass the
FindingsOrchestrator dedup check — unique IDs mean each cycle iteration looks
like a fresh branch at linear depth 0, making Step 1 blind to cycles. The
engine_id counter is the correct gate.

Operator-triggered arms and confirms do not count against either cap.

---

## Concurrency policy matrix

Enforcement: Execution Orchestrator maintains a per-target mutex table. A
dispatch request that violates a mutex slot is queued (not rejected) and retried
once the blocking engine completes or is cancelled.

| Engine type              | Parallel with                    | Mutex with                          |
|--------------------------|----------------------------------|-------------------------------------|
| HTTP probe (light)       | All read-only engines            | ZAP active scan                     |
| nmap                     | HTTP probes, nuclei, recon       | Metasploit (same target)            |
| nuclei (passive)         | All read-only engines            | ZAP active scan                     |
| nuclei (active)          | nmap                             | HTTP probes, ZAP, Metasploit        |
| ZAP spider               | Read-only operations             | ZAP active scan, Metasploit         |
| ZAP active scan          | nothing                          | everything on target                |
| Metasploit               | nothing on same target           | everything on target                |
| Validation plugins       | each other                       | ZAP active scan, Metasploit (same service) |

Implementation note: `EngineCapabilities.concurrency_safe` handles the
simple case (same-engine parallel). The full matrix is encoded in the
Execution Orchestrator's `_mutex_table` dict keyed by `(engine_id_a,
engine_id_b)`. Adding a new engine requires a new row in the dict.

---

## Failure mode handling

| Failure                              | Conductor/Orchestrator response                                                    |
|--------------------------------------|------------------------------------------------------------------------------------|
| Engine binary missing                | Skip, log, mark engine unavailable in registry. Execution Orch skips dispatch for this engine silently. |
| Engine timeout (no result in window) | Kill process, log, mark capability degraded, continue investigation.               |
| Engine crash mid-run                 | Capture partial findings already pushed to output_channel, log full stderr, continue. |
| Malformed engine output              | Quarantine raw output to a log file, emit no finding, log warning. Do not surface to operator. |
| Engine hang (heartbeat absent)       | Kill after 30s heartbeat threshold, treat as crash.                                |
| Two engines need same mutex slot     | Queue the second; run after first completes or is cancelled.                       |
| Target rate limit (HTTP 429)         | Session Orchestrator enters cooldown for target (configurable window, default 60s). All engines on that target queued until cooldown expires. |
| Operator stops investigation         | Conductor broadcasts cancel to all orchestrators. Each orchestrator calls cancel() on its active engines. Clean exit logged; unclean exits (timeout) logged as warnings. |
| Conductor restart with active investigations | Load from SQLite; mark engines "unknown"; defensively kill stale processes; surface "investigation interrupted" status to operator via admin UI. |

---

## State persistence model

| Orchestrator          | State                     | Storage                                       |
|-----------------------|---------------------------|-----------------------------------------------|
| Conductor             | Active investigations      | SQLite (`data/orchestration.db`, `investigations` table) |
|                       | Lifecycle state            | SQLite                                        |
| Phase Orchestrator    | Current phase              | SQLite (`phase_state` table)                  |
|                       | Phase history              | SQLite                                        |
| Execution Orchestrator| Running engine instances   | In-memory; `engine_runs` table in SQLite for restart reconciliation |
|                       | Engine roster              | In-memory (registered at startup)             |
| Findings Orchestrator | No internal state          | Findings persist via existing finding storage layer |
| Chain Orchestrator    | Chain history              | SQLite (`chain_events` table)                 |
|                       | Chain depth tracker        | In-memory + SQLite snapshot per increment     |
| Session Orchestrator  | `_API_AUTH_STORE`          | In-memory; optional SQLite snapshot for session persistence |
|                       | Rate limit budgets         | In-memory (reset on startup)                  |
|                       | Target type cache          | In-memory                                     |

**Restart reconciliation**: on Conductor startup, load all non-terminal
investigations from SQLite. For each, query `engine_runs` for rows with status
`running` — attempt to kill those PIDs (best-effort), mark rows `unknown`.
Surface affected investigations as "interrupted" in admin UI. Operator can
restart or discard.

---

## Event bus / introspection contract

Every orchestrator implements this interface:

```python
class OrchestratorBase:
    def get_state(self) -> dict:
        # Returns current orchestrator state as a structured dict.
        # Consumed by backend admin UI at /admin/*.
        ...

    def subscribe_events(self, callback) -> "SubscriptionHandle":
        # Registers callback for all structured events this orchestrator emits.
        # Returns a handle the caller can use to unsubscribe.
        ...
```

Event format (all orchestrators, all events):

```json
{
    "orchestrator": "execution",
    "event_type": "engine_started",
    "investigation_id": "inv_abc123",
    "correlation_id": "corr_xyz789",
    "timestamp": "2026-05-24T10:00:00Z",
    "payload": {}
}
```

`correlation_id` is assigned at dispatch time and threads through all
downstream events triggered by the same dispatch. This enables the admin UI to
trace a chain of events (dispatch → engine_started → finding_created →
chain_auto_fired → dispatch) without a distributed tracing library.

Audit log: all events written to an append-only log file at
`data/orchestration_audit.jsonl`. One JSON object per line. Rotated daily by
the application (not by an external tool).

---

## Investigation lifecycle state diagram

```
  CREATED
     │
     ▼
  RECON_RUNNING ──────────────────────────────────────────────► FAILED (terminal)
     │                                                           ▲
     ▼                                                           │
  RECON_COMPLETE ────────────────────────────────────────────────┤
     │                                                           │
     ▼                                                           │
  ENUM_RUNNING ──────────────────────────────────────────────────┤
     │                                                           │
     ▼                                                           │
  ENUM_COMPLETE ─────────────────────────────────────────────────┤
     │                                                           │
     ▼                                                           │
  EXPLOIT_RUNNING ────────────────────────────────────────────────┤
     │                                                           │
     ▼                                                           │
  EXPLOIT_COMPLETE                                               │
     │                                                           │
     ▼                                                           │
  COMPLETED (terminal) ◄──────────────────────────────────────────┘

  Any non-terminal state ──► CANCELLED (terminal, operator-triggered)
```

| State              | Meaning                                                  | Triggered by                                         |
|--------------------|----------------------------------------------------------|------------------------------------------------------|
| `CREATED`          | Investigation context exists; orchestrators not yet booted. | `Conductor.start_investigation()` called.         |
| `RECON_RUNNING`    | Phase Orchestrator has dispatched Recon engines.         | Phase Orchestrator emits `phase_started` (recon).   |
| `RECON_COMPLETE`   | All phase-initial Recon engines done.                    | Phase Orchestrator emits `phase_completed` (recon). |
| `ENUM_RUNNING`     | Enumeration engines dispatched.                          | Phase Orchestrator emits `phase_started` (enum).    |
| `ENUM_COMPLETE`    | All phase-initial Enumeration engines done.              | Phase Orchestrator emits `phase_completed` (enum).  |
| `EXPLOIT_RUNNING`  | Exploitation engines dispatched.                         | Phase Orchestrator emits `phase_started` (exploit). |
| `EXPLOIT_COMPLETE` | All phase-initial Exploitation engines done.             | Phase Orchestrator emits `phase_completed` (exploit).|
| `COMPLETED`        | All phases done; investigation closed.                   | Conductor receives `phase_completed` (exploit).     |
| `FAILED`           | An unrecoverable error terminated the investigation.     | Any orchestrator emitting a fatal error event.      |
| `CANCELLED`        | Operator stopped the investigation.                      | `Conductor.cancel_investigation()` called.          |

Valid transitions: any state may transition to `FAILED` or `CANCELLED`. Forward
phase transitions follow the sequence above; no backward transitions. An
investigation may not skip phases.

**Phase transition and chain-dispatched engines**: phase state advances when
phase-initial engines complete. Chain-dispatched engines spawned during a phase
may still be running when the state transitions (e.g., from RECON_RUNNING to
RECON_COMPLETE). Those engines continue until they finish or the investigation
is cancelled — they do not hold back the phase clock.

---

## What's deliberately out of scope

- Multi-operator support. Single-operator local tool; no auth, no RBAC.
- Distributed orchestrator deployment. All orchestrators run in-process within
  the single FastAPI application.
- Engine sandboxing. Engines are trusted; they run as the same user as the
  application.
- Engine-level retries. An engine that fails is skipped. No retry storms.
- Cross-investigation engine sharing. Each investigation boots its own engine
  instances. No shared mutable state between concurrent investigations.
- Real-time collaboration features.
- Encryption of state at rest. Local tool; SQLite is unencrypted.
- Engine output replay via UI. The audit log captures all output; there is no
  UI feature to replay it.
- Plugin discovery (dynamic loading from disk). Engines are registered at
  startup; no hot-loading.

---

## Implementation sequencing

See `CLAUDE.md` "Delivery sequence" for current PR tracking. This document
defines the architecture; CLAUDE.md tracks delivery status.

| PR    | What ships                                                                 |
|-------|----------------------------------------------------------------------------|
| PR A  | Orchestrator skeletons + Engine ABC + mock engine + Conductor wiring. Verified: Conductor.start_investigation() boots all five orchestrators; mock engine dispatches and emits a finding end-to-end. |
| PR A.1| Backend admin UI at `/admin/*` — one panel per orchestrator showing `get_state()` output and live event stream. No auth (single-operator). |
| PR B  | Wrap existing `investigation_workspace` probes as conforming Engine subclasses dispatched via Execution Orchestrator. No behavior change; architecture realigned. |
| PR C  | nmap Engine — highest leverage per dormant-capabilities audit. Recon phase only. |
| PR D+ | Remaining dormant engines one per PR: CVE chain, validation plugins, nuclei, ZAP, Metasploit. |
| V2    | Exploitation phase: per-technique engines (~8), branch state persistence, three-level mindmap, session pipe. After V1.7 closeout. See `/docs/architecture/exploitation.md`. |
| V2.1  | Qwen single-shot suggester via Ollama. Consumes V2 exhaustion records. See CLAUDE.md V2 roadmap. |
