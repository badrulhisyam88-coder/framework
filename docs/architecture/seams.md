# System Seams

## Why this doc exists

A seam bug is mechanically valid code on each side that silently fails at the layer
boundary. Eight bugs in V1.6–V1.7 had exactly this shape: each layer passed its unit
tests; the mismatch only surfaced during live integration or DB inspection. Wrong ID
type, wrong database, wrong attribution field — all silent, all compounding. This doc
inventories every known seam, its contract, and the regression test protecting it.

**Related:** `tests/conductor/_patterns/README.md` — the 14-pattern seam bug catalog
with one regression test per pattern.

---

## How to use this doc

- Before touching any seam component in a PR, read its entry here.
- After fixing a seam bug, add a `test_seam_*.py` to `tests/conductor/_patterns/`.
- After adding a new seam (V2+ prompt construction, RAG retrieval, exploit execution),
  add an entry here **before** shipping code, not after the first bug surfaces.

---

## Seam inventory

---

### Seam 1: StorageBridge → NormalizedFindingRepository (ID round-trip)

**What crosses:** `FindingEvent.id` (Conductor's `fnd_xxx`) → `NormalizedFinding.finding_id` in `validation.db`

**Writer:** `_persist()` in `apps/investigation_workspace/api/routes.py` (around line 1044)
**Reader:** FilterOrchestrator UPDATE callbacks in `apps/conductor/conductor.py`

**[INVARIANT] Identity contract:** `NormalizedFinding.finding_id` must equal `evt.id` from the
`FindingEvent`. `NormalizedFinding` has `default_factory=lambda: str(uuid4())` — if
`finding_id` is not passed explicitly, it silently defaults to a random UUID4.

Current fix (PR L, line 1045 of routes.py):
```python
finding_id = (evt.id or str(uuid4()))
```

**What breaks if violated:** `FilterOrchestrator UPDATE normalized_findings SET
validation_status=? WHERE finding_id='fnd_xxx'` always matches 0 rows. No error —
just no validation status ever written. This was silent for eight PRs.

**Protected by:** `tests/conductor/_patterns/test_seam_identity_roundtrip.py`

---

### Seam 2: finding_id determinism

**What crosses:** Finding identity across engine dispatch → Findings Orchestrator dedup
→ DB write → FilterOrchestrator UPDATE

**Implementation:** `apps/investigation_workspace/probe/finding_id.py` — `generate_finding_id()`

**Contract (from docstring and code):**
- Inputs: `(probe_id, target, path, finding_type)` — all four required, joined by `|`
- Algorithm: SHA-256 of the joined string, first 12 hex chars, prefixed with `fnd_`
- Output format: `fnd_<12 hex chars>` = 16 chars total
- [INVARIANT] Determinism: same four inputs → same output across process restarts and re-runs

```python
raw = f"{probe_id}|{target}|{path}|{finding_type}"
digest = hashlib.sha256(raw.encode()).hexdigest()
return f"fnd_{digest[:12]}"
```

**Migration note (from module docstring):** Do not change the hash inputs, digest
length, or prefix without a migration that re-IDs all existing findings. Existing
findings in the DB would become orphaned.

**What breaks if violated:** Dedup fails (same finding written twice). FilterOrchestrator
UPDATEs miss their target rows. Cross-finding `related_findings` references break.

**Protected by:** `tests/conductor/_patterns/test_seam_identity_roundtrip.py` —
`test_finding_id_is_deterministic()` and `test_finding_id_format_is_fnd_prefixed()`

---

### Seam 3: FilterOrchestrator DB writer target

**What crosses:** FilterOrchestrator classification results → `normalized_findings` table

**Writer:** `_validation_update()` and `_block_reason_update()` closures in
`apps/conductor/conductor.py` (around lines 101–136)
**Reader:** Workspace UI polling `workspace-data.json` via `NormalizedFindingRepository`

**[INVARIANT] Contract:** Both closures must import and open `DB_PATH` from
`apps.validation.database` — currently `/app/data/validation.db`.
- `normalized_findings` lives **only** in `validation.db`
- Conductor's own DB is `data/orchestration.db`; `normalized_findings` does NOT exist there
- The closures do a lazy import inside the function body to avoid capturing a wrong path
  at closure creation time

Current wiring in conductor.py:
```python
from apps.validation.database import DB_PATH as _VALIDATION_DB
async with _aiosqlite.connect(_VALIDATION_DB) as _db:
    await _FindingRepo(_db).update_validation_status(...)
```

**Bug (PR K):** Before the fix, closures captured `_db_path` from the conductor's
own context, which resolved to `data/orchestration.db`. Every UPDATE silently no-oped.
The entire V1.7 feature set appeared to work (no errors) but wrote nothing.

**Protected by:** `tests/conductor/_patterns/test_seam_db_target_consistency.py`

---

### Seam 4: Source attribution (engine → StorageBridge → NormalizedFinding)

**What crosses:** `probe_id` field on engine-emitted finding dict → `source_scanner`
on `NormalizedFinding`

**Writer:** `StorageBridge.persist()` in `apps/conductor/findings/storage_bridge.py`
**Reader:** Any source-based query against `normalized_findings`

**[INVARIANT] Contract:** `StorageBridge` must read `probe_id` from the finding dict and pass it
as `source_scanner`. Must NOT hardcode a constant.

Current code (storage_bridge.py line 43):
```python
source_scanner=finding.get("probe_id", "unknown"),
```

And in `_persist()` of routes.py (line 1048):
```python
source_scanner = (evt.source_scanner or "passive_probe"),
```

**Bug (PR D-fix-2):** `StorageBridge` originally hardcoded
`source_scanner="passive_probe"` from when only the passive probe existed. nmap,
nuclei, and zap findings were all attributed to `passive_probe`. Source-based
queries silently wrong.

**Protected by:** `tests/conductor/_patterns/test_seam_attribution_preservation.py`

---

### Seam 5: Gate registry (engine registration → dispatch visibility)

**What crosses:** Engine class declaration → gate validation at startup →
`engine_is_visible()` check at dispatch time

**Registry:** `apps/conductor/gates.py` — `engine_is_visible()`, `_REGISTERED_GATES`
**Startup validation:** `apps/conductor/engines/__init__.py` —
`_validate_engine_gate_references()` (runs at import time)

**Contract:**
- Every engine declares exactly **one** of `gate_id: str` (single gate) or
  `gate_ids: tuple[str, ...]` (multi-gate). Declaring both → fail-closed (engine blocked).
- `engine_is_visible(engine)` returns `True` iff: single-gate engine's gate is ON; or
  any gate in a multi-gate engine's `gate_ids` tuple is ON.
- Unknown `gate_id` at startup: engine is **unregistered** (not fatal; app still starts).
  Unknown gate at dispatch: `engine_is_visible()` returns `False` and logs an error.
- Fail-closed is intentional: unknown gate = blocked, not silently visible.

**What breaks if violated:** An engine with a bad `gate_id` runs when it should be
blocked (fail-open), or a working engine is silently skipped because its gate
declaration is wrong.

**Protected by:** `tests/conductor/_patterns/test_seam_adapter_contract.py` (partial —
covers gate_id existence check)

---

### Seam 6: RuleResult protocol (rules → FilterOrchestrator)

**What crosses:** Rule output → FilterOrchestrator classification logic

**Protocol definition:** `apps/conductor/rules/base.py` — `RuleResult` dataclass and
`Rule` Protocol

**Contract:**

```python
@dataclass
class RuleResult:
    matched: bool
    status: str | None = None       # 'validated' | 'dropped' | 'incomplete'
    reason: str | None = None       # human-readable validation_reason
    gaps: list[str] | None = None   # enumeration_gaps (only for 'incomplete')
    is_evidence_gap: bool = False   # when True: matched but classification blocked
```

- `evaluate(finding, all_findings) -> RuleResult` — rules never perform I/O
- First-match-wins applies to the `drop → validate → incomplete` loop for normal rules
- [INVARIANT] `is_evidence_gap=True` (via `RuleResult.evidence_gap(reason)` classmethod) is **not**
  first-match-wins: finding stays `pending`, chain continues, reason stored in
  `enumeration_block_reason`. A later rule can still classify it.
- `ReinvocationRequest` (also in base.py) is returned by reinvocation rules; carries
  `engine_id`, `config`, `source_finding_id`, `rule_id`

**What breaks if violated:** A rule returning `is_evidence_gap=True` that is treated as
first-match-wins will silently drop all findings that lack an evidence field, rather than
surfacing them as blocked for operator review.

**Protected by:** `tests/conductor/_patterns/test_seam_rule_chain_evidence_gap.py` —
`test_chain_continues_after_evidence_gap()` and `test_regression_evidence_gap_not_first_match_wins()`

---

### Seam 7: Wordlist registry (engines → data/wordlists/)

**What crosses:** Engine config wordlist request → file on disk

**Registry:** `apps/conductor/wordlists.py` — `REGISTERED_WORDLISTS`, `load_entries()`,
`get_wordlist()`

**Contract:**
- Engines call `load_entries(wordlist_id)` — never open files directly
- `wordlist_id` must be a key in `REGISTERED_WORDLISTS`; unknown ID raises
  `WordlistNotFoundError` (subclass of `KeyError`)
- Format-aware: `yaml` → `yaml.safe_load` (top-level list), `csv` → `csv.DictReader`
  (list of row dicts), `txt` → list of stripped non-empty non-comment lines
- All paths resolved relative to `REPO_ROOT` so tests run correctly regardless of cwd
- Missing file (registered but not on disk) raises `WordlistFileNotFoundError`

**Currently registered wordlists:**
- `ssh_credentials_default` — `data/wordlists/credentials/ssh-defaults.yaml` (yaml, 12 entries)
- `api_paths_default` — `data/wordlists/paths/api-endpoints.txt` (txt, 269 paths)
- `credentials_extended` — `data/wordlists/credentials/general-defaults.csv` (csv, 2,876 rows)

**What breaks if violated:** Engine accessing wordlist files directly bypasses the
registry, breaks path resolution in test environments, and makes the wordlist inventory
invisible to the admin UI.

---

### Seam 8: OutputChannel (engine → FindingsOrchestrator)

**What crosses:** Engine finding emission → `FindingsOrchestrator.ingest()`

**Implementation:** `apps/conductor/engines/base.py` — `OutputChannel` class (lines 69–99)

**Contract:**
- `OutputChannel` is constructed by `ExecutionOrchestrator` before each `engine.run()`
  call, with refs to both `FindingsOrchestrator` and `SessionOrchestrator`
- `await output_channel.emit_finding(finding_dict)` → calls
  `findings_orch.ingest(finding, engine_id)`; never writes to DB directly
- `finding_dict` must carry: `id` (fnd_xxx from `generate_finding_id()`), `category`,
  `title`, `severity`, `evidence`, `probe_id`, `phase`
- `output_channel.record_request(target)` and `record_response(target, status_code)` go
  directly to `SessionOrchestrator` (no event bus) to keep the rate-limiting hot path lean
- Engines read auth via `session_store.get_auth(investigation_id)` and
  `session_store.has_auth(investigation_id)` — **never** re-authenticate

**What breaks if violated:** An engine writing to DB directly bypasses dedup in
`FindingsOrchestrator` and the `finding_id` round-trip seam (Seam 1), creating the
two-parallel-ID-systems bug pattern.

---

### Seam 9: Engine watchdog (engine run() duration → Execution Orchestrator threshold)

**What crosses:** Long-running engine subprocess → watchdog kill decision

**Implementation:** `apps/conductor/orchestrators/execution.py` — `_HUNG_THRESHOLD_LIGHT`
and `_HUNG_THRESHOLD_HEAVY` constants (lines 30–31), threshold selection at dispatch

**Contract:**
- Engines that run blocking subprocesses (nmap, nuclei, zap) declare
  `resource_cost='heavy'` in `EngineCapabilities`
- `_HUNG_THRESHOLD_HEAVY = 600.0` seconds for heavy engines
- `_HUNG_THRESHOLD_LIGHT = 30.0` seconds for light/medium engines
- Threshold is read from `engine.capabilities.resource_cost` at dispatch time:
  ```python
  threshold = _HUNG_THRESHOLD_HEAVY if engine.capabilities.resource_cost == "heavy" else _HUNG_THRESHOLD_LIGHT
  ```
- Heartbeat is updated before and after the subprocess call — during a long scan the
  heartbeat goes stale; the heavy threshold is what keeps the watchdog from killing it

**Bug (PR G):** Flat 30s threshold killed nuclei mid-scan while the subprocess was still
running. nuclei scans take 60–300s. Fix differentiated threshold by `resource_cost`.

**Protected by:** `tests/conductor/_patterns/test_seam_resource_policy.py`

---

### Seam 10: Event bus (orchestrators → frontend polling)

**What crosses:** Orchestrator events → frontend `workspace.js` SSE / polling

**Implementation:** `apps/conductor/events/bus.py` — `EventBus` class, module-level
`bus` singleton

**Contract:**
- Event shape: `{ orchestrator, event_type, investigation_id, correlation_id, timestamp, payload }`
- `bus.subscribe(callback)` returns a `SubscriptionHandle`; call `.cancel()` to stop
- `await bus.emit(orchestrator, event_type, investigation_id, payload, correlation_id=None)` —
  broadcasts to all current subscribers; subscriber exceptions are caught and logged,
  they do not propagate
- No persistence (events are ephemeral). No external broker.
- Correlation IDs are auto-generated (uuid4) if not provided — all orchestrator events
  should propagate the same correlation_id for a given chain dispatch

**What breaks if violated:** A subscriber that raises will be logged but the event bus
continues; a subscriber that is never cancelled leaks memory. Dropped subscription
handles after investigation completion are a known leak vector.

**No dedicated seam test yet.** Covered indirectly by integration tests.

---

### Seam 11: Audit log (orchestration events → durable record)

**What crosses:** Orchestrator events → `orchestration_audit.jsonl`

**Current status:** The audit log described in `docs/architecture/orchestration.md`
(append-only JSONL, rotated daily) is **not yet implemented** in the codebase. No
`orchestration_audit` writer was found in `apps/conductor/`. The `EventBus` has no
audit subscriber wired at startup.

**Why this matters:** The audit log is the planned RAG source of truth for V2.7
knowledge accumulation. The correlation_id discipline already in the event bus is
designed to trace "this finding led to this exploit which solved this lab." If an
audit writer is added, it must subscribe to the shared `bus` singleton and write the
full event envelope (including `correlation_id`) to a durable file.

**No seam test exists.** When this seam is wired for V2.7, add a
`test_seam_audit_log.py` to `tests/conductor/_patterns/`.

---

## V2 Seams (Seams 12–18)

Seam tests for each V2 seam ship with the V2.2 PR that introduces the seam, not here.
Reserve slots in `tests/conductor/_patterns/` as `test_seam_v2_*.py`.

---

### Seam 12: FilterOrchestrator output → exploitation engine input

**What crosses:** `NormalizedFinding` rows (`validated` / `incomplete` status) in
`validation.db` → exploitation engine `run()` call with evidence dict

**Producer:** `FilterOrchestrator` writing `validation_status` to `normalized_findings`
**Consumer:** `ExploitationPhaseDispatcher` (V2.1) reading findings and dispatching engines

**[INVARIANT] Contract:**
- Only `validated` and `incomplete` findings are dispatched to exploitation engines.
  `pending` and `dropped` findings must never reach an exploitation engine.
- Engine `run()` receives the full `evidence` dict as-is from `normalized_findings`. Engines
  do not re-run classification logic.
- Required evidence fields per `finding_type` are defined in
  `/docs/architecture/exploitation.md` §2. If a required field is absent, the engine
  emits `evidence_gap` and terminates — it does NOT attempt enumeration recovery.
- `finding_id` passed to the engine must match the `normalized_findings.finding_id` value
  (same round-trip identity requirement as Seam 1).

**What breaks if violated:**
- Dispatching `pending` findings to exploitation engines: engines run against unclassified
  data, producing artifacts with no FilterOrchestrator backing.
- Dropping required evidence fields during dispatch: engine crashes or silently produces
  wrong results; no signal to operator.

**Pattern test slot:** `tests/conductor/_patterns/test_seam_v2_enum_to_exploit_input.py`

---

### Seam 13: Exploitation engine → branch state persistence

**What crosses:** Engine execution output (`artifact` or `ExhaustionRecord`) → `exploitation_branches` table in `validation.db`

**Producer:** Exploitation engines writing via `OutputChannel` extension
**Consumer:** Mindmap polling endpoint (`/exploitation-data.json`), right-side panel

**[INVARIANT] Contract:**
- `branch_id` must be deterministic: `sha256(investigation_id|finding_id|engine_id)[:12]`
  prefixed `"exb_"`. Same formula as `generate_finding_id()` in
  `apps/investigation_workspace/probe/finding_id.py` — same inputs → same ID across
  restarts, enabling idempotent re-dispatch.
- DB writer must target `validation.db` (same invariant as Seam 3). Using `orchestration.db`
  silently no-ops all branch reads in the UI.
- `state` column transitions: `pending → armed → running → succeeded | exhausted | failed | cancelled`.
  No backward transitions. Any code that writes `state` must use the enum values exactly.
- `artifact` and `exhaustion_record` are mutually exclusive per branch: only one is non-null.
  An engine that produces both indicates a logic error.

**What breaks if violated:**
- Non-deterministic `branch_id`: re-dispatch creates duplicate rows; mindmap renders duplicate
  nodes; V2.1 Qwen reads stale exhaustion records.
- Wrong DB target: all `exploitation_branches` reads return empty; mindmap renders no nodes.
- Backward `state` transition: already-succeeded branch can be overwritten; artifact lost.

**Pattern test slot:** `tests/conductor/_patterns/test_seam_v2_branch_persistence.py`

---

### Seam 14: V2 → Qwen exhaustion handoff

**What crosses:** `ExhaustionRecord` written to `exploitation_branches.exhaustion_record` → V2.1 Qwen single-shot suggester reads it

**Producer:** `exploit_exhaustion.py` — `ExhaustionRecord` emitter (V2 ships schema)
**Consumer:** V2.1 Qwen suggester (reads `exhaustion_record` from `exploitation_branches`)

**[INVARIANT] Contract — `ExhaustionRecord` schema (locked in V2, must not change in V2.1):**

```python
@dataclass
class ExhaustionRecord:
    technique_class: str          # e.g. "injection.sql"
    engine_id: str                # e.g. "sqli_auth_bypass"
    target: str                   # normalized target URL
    finding_id: str               # source finding fnd_xxx
    payloads_tried: list[dict]    # [{payload, source, result}]
    detection_method: str         # "tautology_bypass" | "timing" | "boolean_diff" | etc.
    negative_evidence: dict       # best attempt's response shape
    finding_context: dict         # evidence fields from normalized_findings
    operator_params: dict         # template fields the operator supplied
    exhausted_at: str             # ISO8601
```

The schema is write-once in V2. V2.1 must not require additional fields — it must
work with exactly this shape. Any V2.1 additions require a V2 schema patch PR.

**What breaks if violated:**
- Schema drift: V2.1 Qwen fails to read exhaustion records from V2-produced branches;
  all exhausted branches appear unrecognized.
- Missing `finding_context`: Qwen has no evidence to reason from; suggestions are generic
  rather than evidence-grounded.

**Pattern test slot:** `tests/conductor/_patterns/test_seam_v2_exhaustion_record.py`

---

### Seam 15: Session pipe (SessionOrchestrator → exploitation engines)

**What crosses:** Investigation-scoped auth state → exploitation engine `run()` auth reads

**Producer:** `SessionOrchestrator` on `_InvestigationContext` (`apps/conductor/orchestrators/session.py`)
**Consumer:** All exploitation engines; ACTIVE-LEGACY probe layer via `INVESTIGATION_ID_CTX`; future Qwen prompts

**[INVARIANT] Contract:**
- Exploitation engines call `session_store.get_auth(investigation_id)` — same interface
  as enumeration engines (Seam 8). They NEVER re-authenticate.
- One `SessionOrchestrator` per investigation on `_InvestigationContext`. No process-level
  store on `Conductor`. The module-level `_API_AUTH_STORE` and `Conductor.session_orch`
  were both removed in V2.1 Steps 2 and 2b.
- ACTIVE-LEGACY probes (fixed `target: str` signatures) access the investigation-scoped
  store via `INVESTIGATION_ID_CTX` set in `_runner_from_probe` before the probe is called.
- Session refresh: operator-driven only. Engines emit `auth_expired` stage event and
  transition branch to `failed` if auth is stale. No autonomous re-auth.
- If `session_store.get_auth(investigation_id)` returns `None`, the engine treats the
  session as unauthenticated and documents this in the template spec's auth state field.

**What breaks if violated:**
- A second `SessionOrchestrator` instance (process-level or module-level): auth writes
  land in the wrong scope; concurrent investigations corrupt each other's sessions.
- `INVESTIGATION_ID_CTX` not set before probe call: probe's `_get_session_orch()` falls
  back to an ephemeral instance; auth writes are silently discarded.
- Engine re-authenticates autonomously: violates the session inheritance invariant;
  creates parallel auth sessions; rate limit coordination fails.

**Pattern test slot:** `tests/conductor/_patterns/test_seam_session_pipe.py`

---

### Seam 16: Re-invocation entry hook (stubbed in V2)

**What crosses:** V2.5 Qwen loop extended payload/wordlist injection → exploitation engine re-dispatch

**Producer:** V2.5 Qwen loop (not yet built; V2 ships the stub)
**Consumer:** Exploitation engines via `config["extended_payloads"]` and `config["extended_wordlists"]`

**Contract (stub, locked in V2):**
- Every exploitation engine's `run()` accepts `config["extended_payloads"]` and
  `config["extended_wordlists"]` as optional kwargs with empty-list defaults.
- In V2, engines ignore these keys beyond documenting them in the `ExhaustionRecord`.
- In V2.5, the Qwen loop populates these keys and re-dispatches the engine. The engine
  must union `extended_payloads` with its preset, not replace it.
- The re-invocation goes through `REINVOCATION_RULES` → `ReinvocationRequest` →
  `ExecutionOrchestrator.dispatch()` — same path as FilterOrchestrator re-invocation
  (Seam 3 pattern).

**What breaks if violated:**
- Engine raises `TypeError` on unknown `config` keys: V2.5 re-dispatch fails silently.
- Engine replaces preset with extended payloads: preset payloads are re-tried, wasting
  operator capacity; exhaustion record is invalidated.

**Pattern test slot:** `tests/conductor/_patterns/test_seam_v2_reinvocation_hook.py` (shipped V2.3 Step 2 — was incorrectly listed as V2.2; stub kwargs added to all 9 engines in same PR)

---

### Seam 17: Feedback capture hook (wired V2.5 Step 4)

**What crosses:** Engine terminal-state transition → Qwen auto-feedback message → next ACTION recommendation

**Producer:** `_checkTerminalTransitions()` in exploitation-mindmap.js — fires when `_pollBranches()` detects a branch entering succeeded/exhausted/failed while the chat window is open
**Consumer:** `_chatAutoFeedback()` — sends context message to `/qwen/chat`, renders response + optional approval card

**Contract (stub, locked in V2):**
- Every exploitation engine's `capabilities.template_spec` includes a `feedback_hook` field
  of type `stub`. V2 renders the field as a no-op placeholder; the UI does not display it.
- In V2.1, the feedback hook becomes `thumbs_up_down`; the UI renders the control;
  a click POSTs to `/api/exploitation/feedback` which writes to `template_feedback`.
- `template_feedback` schema (defined now, created by V2.1 migration):
  `(feedback_id, branch_id, engine_id, technique_class, verdict TEXT CHECK(verdict IN ('up','down')), created_at)`
- V2 must not create this table (avoid premature schema). V2.1 creates it idempotently.

**What breaks if violated:**
- V2 creates `template_feedback` table: V2.1 migration fails idempotency check; or
  table schema diverges from V2.1's expectation.

**Pattern test slot:** `tests/conductor/_patterns/test_seam_v2_feedback_hook.py` (ships with V2.1)

---

### Seam 18: RAG injection point (partially wired V2.5)

**What crosses:** Retrieved context chunks (V2.8) / Qwen recommendation (V2.5) → payload load context

**Producer:** V2.8 ChromaDB retrieval (not yet built); V2.5 partially wires Qwen recommendation
  as `rag_context["qwen_recommendation"]` passed to `load_payloads()`.
**Consumer:** Layer 1 payload loading — `load_payloads(technique_id, rag_context=...)` in each engine.

**Contract (stub, locked in V2):**
- Template build flow calls `_inject_rag_context(finding, template_spec) -> template_spec`
  at the start of Layer 1 form construction.
- In V2, this function returns `template_spec` unchanged (no-op pass-through).
- In V2.8, this function receives top-K similar past chains from ChromaDB and merges
  them into `template_spec` as a `rag_context` field.
- The function signature is: `(finding: NormalizedFinding, template_spec: dict) -> dict`.
  V2 and V2.8 share this signature — V2.8 must not change it.
- The function must be pure (no side effects); it may not write to DB or emit events.

**What breaks if violated:**
- Signature changes in V2.8: every exploitation engine that calls `_inject_rag_context`
  breaks at dispatch time.
- Side effects in the stub: V2 template builds acquire hidden dependencies; testing
  becomes non-deterministic.

**Pattern test slot:** `tests/conductor/_patterns/test_seam_v2_rag_injection.py` (ships with V2.8)

---

### Seam 19: Bootstrap ↔ Conductor Phase State

**What crosses:** `PhaseOrchestrator._PHASE_SEQUENCE` (Conductor) → `PhasedRun` + `_current_phase()` (workspace bootstrap layer)

**Producer:** `PhaseOrchestrator` emitting `phase_started` events on the `EventBus`
**Consumer:** `_run_all_probes_via_conductor` in `apps/investigation_workspace/bootstrap/runtime.py`,
which owns the `PhasedRun` for the running investigation

**[INVARIANT] Contract:**
- `PhasedRun` must have a field for every phase in `_PHASE_SEQUENCE`. If a new phase is activated
  in `_PHASE_SEQUENCE` without a matching `PhasedRun` field, `_current_phase()` skips it silently
  and the operator UI shows the wrong phase (or "complete" prematurely).
- `_current_phase()` must return the phase string while its `PhaseRun.completed_at is None`,
  and `"complete"` only after all `PhaseRun.completed_at` values are set.
- `is_exploitation_active(investigation_id)` is the canonical predicate for querying exploitation
  phase liveness. Must be importable from `apps.investigation_workspace.bootstrap.runtime`.
- `_OPERATOR_DRIVEN_PHASES` in `apps/conductor/orchestrators/phase.py` and `PhasedRun.exploitation_run`
  are co-present: if one exists, the other must too. A new operator-driven phase requires both.
- `_apply_phase_event(run, event_type, phase)` in `runtime.py` is the module-level function that
  applies phase bus events to `PhasedRun` state. `_on_event` delegates all `phase_started` and
  `phase_completed` events to it. All phase state changes go through this function.
- Full subscriber set (post V2.1 Step 3 Fix-2):
  - `phase_started(enumeration)` → creates `enumeration_run` with `completed_at=None`
  - `phase_started(exploitation)` → creates `exploitation_run` with `completed_at=None`
  - `phase_completed(recon)` → writes `recon_run.completed_at` (idempotent)
  - `phase_completed(enumeration)` → writes `enumeration_run.completed_at` (idempotent)
  - `phase_completed(exploitation)` → writes `exploitation_run.completed_at` (idempotent)
  - `investigation_completed` / `investigation_cancelled` → close any open phase run, set `done`
- Teardown block is idempotent: it only writes timestamps that were not already set by bus-event
  subscribers.

Current wiring (`_apply_phase_event` in runtime.py):
```python
if event_type == "phase_started":
    if phase == "enumeration":
        run.enumeration_run = PhaseRun(run_id=..., phase="enumeration", started_at=now, completed_at=None)
    elif phase == "exploitation":
        run.exploitation_run = PhaseRun(run_id=..., phase="exploitation", started_at=now, completed_at=None)
elif event_type == "phase_completed":
    if phase == "recon" and run.recon_run.completed_at is None:
        run.recon_run.completed_at = now
    elif phase == "enumeration" and run.enumeration_run.completed_at is None:
        run.enumeration_run.completed_at = now
    elif phase == "exploitation" and run.exploitation_run.completed_at is None:
        run.exploitation_run.completed_at = now
```

**Bug (V2.1 Step 3 gap):** `_PHASE_SEQUENCE` was updated to include "exploitation" but `PhasedRun`
had no `exploitation_run` field and `_current_phase()` had no exploitation case. The workspace
showed "complete" the instant enumeration ended, making the Exploitation tab inaccessible even
though the Conductor was correctly running exploitation.

**What breaks if violated:**
- Missing `PhasedRun` field: `_current_phase()` returns "complete" during exploitation; Exploitation
  tab inaccessible from operator UI; `is_exploitation_active()` always False.
- Missing `_on_event` listener: `exploitation_run` never set; same symptom as missing field.
- Early `done.set()` or short timeout in `_run_all_probes_via_conductor`: investigation context
  exits before exploitation phase completes; operator loses the active investigation window.

**Protected by:** `tests/conductor/_patterns/test_seam_bootstrap_phase_state.py` (Pattern 13)

---

### Seam 20: Engine auth write-back (OutputChannel → SessionOrchestrator)

**What crosses:** Captured credentials from exploitation engine → `SessionOrchestrator._api_auth_store` → downstream engine `session_store.get_auth()`

**Producer:** Credential-producing exploitation engines (e.g., DefaultCredsEngine)
**Consumer:** All downstream engines calling `session_store.get_auth(investigation_id)` in subsequent run() calls

**[INVARIANT] Contract:**
- Engines that produce auth state as their exploitation outcome call
  `output_channel.store_auth(investigation_id, auth)` — NOT `session_store.store_target_auth()`.
- `OutputChannel.store_auth(investigation_id, auth)` delegates to
  `SessionOrchestrator.store_auth(investigation_id, auth)`.
- After the engine's `run()` returns, `session_store.get_auth(investigation_id)` on the
  investigation-scoped `SessionOrchestrator` returns the captured auth dict.

**What breaks if violated:**
- Engine calls only `emit_finding()` but not `store_auth()`: finding record is correct but
  the session store remains None. Downstream engines run unauthenticated and produce false
  exhaustion records. The operator sees a "successful" credential capture but all follow-on
  authenticated actions fail silently — no error, no signal, no re-run triggered.

**Protected by:** `tests/conductor/_patterns/test_seam_engine_auth_write.py` (Pattern 16)

---

---

### Seam 21: MSF recipe lookup (service_name → RECIPES key)

**What crosses:** nmap `service_name` string (from `normalized_findings.raw_data["service"]`) → `msf_service_map.lookup_recipe_key()` → RECIPES dict key → recipe modules list for `MetasploitRecipeEngine`

**Producer:** nmap engine (emits `service_detected` findings with `evidence["service"]` set to the nmap-normalised service name)
**Consumer:** `MetasploitRecipeEngine._run_recipe_for_finding()` — depends on `lookup_recipe_key()` returning a valid `RECIPES` key

**[INVARIANT] Contract:**
- `lookup_recipe_key(service_name)` returns a non-None key only for service names in `_NMAP_TO_RECIPE`.
- For any `None` return (unknown service), the engine **must** emit an `ExhaustionRecord` with `detection_method="unknown_service"` — NOT skip the finding silently.
- Every key in `RECIPES` must have at least one entry in `_NMAP_TO_RECIPE` — adding a new recipe without a map entry produces permanent exhaustion records against that service.
- The lookup is pure and side-effect-free — safe to call from tests without MSF, DB, or network.

**What breaks if violated:**
- `lookup_recipe_key` returns `None` silently → engine skips finding → operator sees engine "complete" with zero signal — no exhaustion record, no indication that a service was unhandled.
- New service added to `RECIPES` without `_NMAP_TO_RECIPE` entry → all `service_detected` findings for that service permanently exhaust → operator never sees the recipe for that service via the engine.

**Protected by:** `tests/conductor/_patterns/test_seam_msf_recipe_lookup.py` (Pattern 17)

---

---

## V2.2 seam arc (Seams 16–21)

Seams 16–21 were added across V2.2 to guard the new engine substrate surfaces:

| Seam | Surface guarded | Pattern test |
|---|---|---|
| Seam 16 | `CredentialBruteEngine` — per-request CSRF token refresh | `test_seam_brute_force_csrf_refresh.py` (Pattern 15) |
| Seam 17 | XssReflectedEngine probe retirement atomicity | `test_seam_xss_exploit_engine.py` (Pattern 12, updated for C6) |
| Seam 18 | CSRF invariant extension (Pattern 15 formalized) | `test_seam_brute_force_csrf_refresh.py` |
| Seam 19 | `OutputChannel.store_auth()` write-through round-trip | `test_seam_engine_auth_write.py` (Pattern 16) |
| Seam 20 | (see seams.md body — previously numbered entry) | — |
| Seam 21 | MSF recipe lookup: unknown service → ExhaustionRecord | `test_seam_msf_recipe_lookup.py` (Pattern 17) |

All V2.2 seams have passing tests as of V2.2 closeout (2026-05-27).

## V2.3 seam arc (Step 2 defect closures + Step 4 graph wiring)

Three V2.2 production defects identified during live verification (PortSwigger lab, 2026-05-27)
were closed atomically in V2.3 Step 2:

| Defect | Seam fixed | Pattern test |
|---|---|---|
| BranchWriter not wired in ExecutionOrchestrator (all emit_stage() → silent no-op) | ExecutionOrchestrator.__init__ + _launch() wiring | `test_seam_branch_writer_wired.py` (Pattern 18) |
| Seam 16 stub keys absent from all 9 engine run() signatures | Seam 16 re-invocation stub + log no-op added | `test_seam_v2_reinvocation_hook.py` (Seam 16 closure) |
| SqliAuthBypassEngine missing store_auth() after bypass confirmation | Pattern 16 write-through added to _probe_target() | `test_sqli_auth_bypass_engine.py` (existing suite) |

V2.3 Step 3 added `/exploitation-data.json` (BranchReader first consumer). V2.3 Step 4
added the three-level mindmap (`exploitation-mindmap.js`) and Seam 22 (panel data source):

### Seam 22: exploitation-mindmap.js panel → branch data (Pattern 19)

**What crosses:** `_branchMap` (in-memory cache, polled from `/exploitation-data.json`) → panel
rendering functions (`_panelForAction`, `_panelForProgress`, `_panelForResult`) → `#ws-panel-body`
HTML injection

**Producer:** `_pollBranches()` in `exploitation-mindmap.js` — fetches `/exploitation-data.json` at 1.1s
**Consumer:** `_onNodeClick()` → panel rendering functions — reads `node.data._branch` from cached map

**[INVARIANT] Contract:**
- Panel rendering functions read from `node.data._branch` (set during graph construction via `_buildGraph()`).
- No secondary server fetch inside panel rendering — all branch state comes from the polling cache.
- The context-panel endpoint (capture-bundle, ACTIVE-LEGACY) must not be called from `exploitation-mindmap.js`.
- `workspace-data.json` is passed in via mount/refresh API — never fetched from within the mindmap.

**What breaks if violated:**
- Panel fetch inside rendering function → panel silently returns nothing on stale-token or session expiry,
  exactly when the operator is inspecting exploitation results.
- Context-panel fetch → old capture-bundle HTML injected into the branch state panel — renders garbage.

**Protected by:** `tests/conductor/_patterns/test_seam_panel_data_source.py` (Pattern 19)

---

### Seam 23: SUGGESTIONS catalog ↔ engine_registry registration (Pattern 21)

**What crosses:** `SuggestionSpec.engine_id` in `catalog.py` → `engine_registry._engines` in
`apps/conductor/engines/base.py` → `exec_orch.dispatch_engine(engine_id)` in `routes.py`

**Producer:** `SuggestionSpec` entries in `SUGGESTIONS` dict — action_kind + engine_id fields
**Consumer:** `execute_suggestion()` route in `routes.py` — calls `ctx.exec_orch.dispatch_engine(spec.engine_id)`

**[INVARIANT] Contract:**
- Every exploitation-phase engine registered in `engine_registry` must have at least one
  `SuggestionSpec` in `SUGGESTIONS` with `engine_id` matching the engine's `engine_id` class attribute.
  If absent, Phase 2 ghost emission never produces an action card for the engine — operators cannot arm it.
- Every `SuggestionSpec.engine_id` must reference an engine present in `engine_registry`. A dangling
  engine_id causes `dispatch_engine` to log an error and return without firing the engine — silent failure.
- `probe_runner` and `engine_id` are mutually exclusive. Dual-mode specs create ambiguous dispatch.

**What breaks if violated:**
- Engine not catalogued → Phase 2 ghost emission produces no action cards → engine invisible to operators.
- Dangling `engine_id` → execute route calls `dispatch_engine` with unknown id → silent no-op, no error
  surfaced to operator.
- Both fields set → execute route takes engine path, probe_runner silently ignored → potential silent skip.

**Protected by:** `tests/conductor/_patterns/test_seam_v2_engine_topology_registration.py` (Pattern 21)

---

### Seam 24: Conductor _active ↔ workspace investigation_id alignment (Pattern 22)

**What crosses:** `run.investigation_id` (workspace UUID, from `kick_off()` in `runtime.py`) →
`conductor.start_investigation(investigation_id=...)` → `_active[investigation_id]` in `conductor.py` →
`get_context(investigation_id)` called by `execute_suggestion` in `routes.py`

**Producer:** `runtime.py:kick_off()` — creates PhasedRun with workspace UUID; passes it to
`conductor.start_investigation(investigation_id=run.investigation_id)`

**Consumer:** `routes.py:execute_suggestion()` — calls `get_shared_conductor().get_context(investigation_id)`
where `investigation_id` is the workspace UUID from the URL path

**[INVARIANT] Contract:**
- `conductor._active` must be keyed by the workspace investigation_id. `start_investigation` must store
  the provided investigation_id (not a conductor-generated UUID) in `_active`.
- `runtime.py` must pass `run.investigation_id` as `investigation_id=` to `start_investigation`.
  If omitted, the conductor generates its own UUID and `get_context(workspace_uuid)` always returns None.

**What breaks if violated:**
- `get_context(workspace_uuid)` returns None → `execute_suggestion` returns 409 on every V2 engine Execute
  click — not just after server restart, but permanently for every investigation ever started.

**Root cause of ghost-execute 409:** Prior to this fix, `start_investigation()` had no `investigation_id`
parameter. It always called `str(uuid4())`. `runtime.py` never passed the workspace UUID. Every V2
engine Execute click returned 409 unconditionally, regardless of server state or phase.

**Protected by:** `tests/conductor/_patterns/test_seam_conductor_workspace_id_alignment.py` (Pattern 22)

---

---

## Adding new seams (V2.2+)

V2.1 is complete. Seams 12–19 are documented and enforced (Patterns 9–14).

V2.2 adds Seam 20 (engine auth write-back, Pattern 16) and Seam 21 (MSF recipe lookup, Pattern 17). Engine lifts extend existing
Seam 12 (probe-to-engine lift) and Seam 15 (session pipe). Patterns 10, 12, 16, and 17
cover them.

V2.3 adds Seam 22 (panel data source, Pattern 19) and Seam 23 (engine topology registration, Pattern 21). Seams 12–23 are documented and enforced (Patterns 9–21).

V2.3 (post-closeout) adds Seam 24 (conductor–workspace ID alignment, Pattern 22). Seams 12–24 are documented and enforced (Patterns 9–22).

The following seams are deferred and must be documented here before shipping the code:

**Qwen prompt construction (V2.1 Qwen):**
- `ExhaustionRecord` → Qwen prompt template → Ollama API call → structured suggestion output
- Contract questions: what format does Qwen return? Who validates it? What happens on
  malformed output? Where does `correlation_id` survive the prompt boundary?

**RAG retrieval (V2.7–V2.8):**
- Query → ChromaDB → returned context chunks → `_inject_rag_context()` (Seam 18)
- Contract questions: chunk ID stability (must survive reindex), retrieval schema,
  how chunks are deduplicated before injection, what happens when ChromaDB is empty.

Rule: add the seam entry here before writing the code, not after the first bug.
