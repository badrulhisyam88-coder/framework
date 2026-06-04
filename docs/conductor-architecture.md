# Conductor Architecture

Read this before `system.md`, `orchestration.md`, or `seams.md`. Those documents are reference material — this one is the mental model.

---

## What the Conductor does

The Conductor is the backbone of the investigation runtime. It answers one question for every security investigation: *given a target URL, what should run next, and what do the results mean?*

It does this in three distinct loops that fire in sequence:

1. **Recon + enumeration** — automated scanning. Nmap, nuclei, passive probes, and service plugins run without operator interaction. They produce a ranked pool of findings. FilterOrchestrator classifies each finding as validated, incomplete, or dropped.

2. **Exploitation** — operator-driven, planner-sequenced. The planner selects the next technique based on what the system knows (the agent STATE). Engines run one at a time per operator approval. Every result updates STATE; the next planner pick reflects that update.

3. **Failure interrogation** — recovery. When the planner would otherwise say "stuck," the interrogator inspects the most recent exhaustion records, emits a typed failure-reason fact, re-seeds the candidate pool, and lets the planner try again. Bounded by an attempt cap to prevent loops.

These three loops share one codebase, one database, and one agent STATE per investigation. They do not share a selection mechanism — the planner is the sole selector on paths 2 and 3.

---

## The three-level hierarchy

```
LEVEL 3 — CONDUCTOR
  Knows nothing about individual engines.
  Boots orchestrators; emits investigation-level events (started/completed/failed).

LEVEL 2 — ORCHESTRATORS  (apps/conductor/orchestrators/)
  Six of them, each owns one concern:
  PhaseOrchestrator    — state machine (recon → enumeration → exploitation)
  ExecutionOrchestrator — engine lifecycle, dispatch, concurrency, watchdog
  FindingsOrchestrator  — single ingress for all engine output; dedup by finding_id
  ChainOrchestrator    — next_actions chains; auto-fires enumeration follow-ons
  SessionOrchestrator  — auth store, rate limiting, target classification
  FilterOrchestrator   — post-enumeration two-pass rule evaluation

LEVEL 1 — ENGINES  (apps/conductor/engines/)
  Stateless execution units.
  Each implements the Engine ABC: run(), cancel(), health_check(), capabilities.
  Registered via @engine_registry.register — no orchestrator code changes needed.
  Never talk to each other. All coordination flows upward through orchestrators.
```

Adding a fourth level is not permitted. Two levels would collapse orchestrator concerns into a god object. The boundary between L3 and L2 is intent vs. mechanism; the boundary between L2 and L1 is coordination vs. execution.

---

## The engine contract

Every engine — recon, enumeration, exploitation, recovery — conforms to the same ABC. No exceptions.

**What an engine must do:**

- Implement `run(target, config, session_store, output_channel)` as an async coroutine.
- Return `EngineResult(status=..., findings_count=N)` on every exit path. Every path. No silent returns.
- Respond to `cancel()` within 5 seconds.
- Report a truthful `health_check()`.
- Declare `capabilities` accurately (phases, finding_types, resource_cost, mutex_with).
- Emit findings via `output_channel`, never via direct DB writes.
- Read auth via `session_store.get_auth(investigation_id)`, never by re-authenticating.

**What an engine may never do:**

- Store state across `run()` calls (beyond cancellation flag and heartbeat).
- Call another engine directly.
- Select the next technique. The planner selects; the engine executes what it is told.
- Contain hardcoded lab values, target-specific checks, or conditional logic keyed to specific hostnames.
- Persist `self_pass` or any operator-supplied password to STATE, DB, or logs.
- Emit `negative_evidence.reason` values from raw response body text. Reasons are structured tags (`"ip_blocked_or_account_locked"`, `"csrf_extraction_failed"`), never page-title strings. Matchers match on these tags; if they match on response content, they reproduce the false-positive bug from the live counter-reset lab run.

**Registration:** the `@engine_registry.register` decorator on the engine class is the only wiring needed. Nothing in the orchestrator layer needs to change when an engine is added or removed.

---

## The planner-as-sole-selector invariant

**One thing picks engines: `plan_next_step()` in `apps/conductor/planner.py`.** No other code selects engines on any operator-facing path.

This was not always true. The history of deviations and their consequences:

- The autonomous loop used `generate_work_order()` (Qwen/Ollama) to select engines. Qwen picked based on narrative reasoning, not vault-calibrated priorities. On a brute-force-protection lab, it picked `sqli_auth_bypass` first because the context mentioned SQL injection — the wrong technique entirely.
- The context panel used `generate_work_order()` to propose the top technique card. Same problem.
- The chat box (`qwen_chat_stream`) used the Qwen LLM to pick `engine_id` from a menu. This gave Qwen selection authority on the operator's most-used path.

All three are now wired to `plan_next_step()`. The only thing Qwen does on these paths is provide a conversational acknowledgment; it does not pick engines.

**Why this matters:** the vault encodes 11+ years of security research about which technique to try first given a set of facts (`ip_block_detected`, `login_form_detected`, `requires_session_first`). An LLM has no access to that calibration at inference time. The planner does — it reads `agent_state.pending`, sorts by priority, respects preconditions, and pops the top reachable concept. That selection is reproducible, auditable, and explainable.

**The invariant in code:** `planner.py:plan_next_step()` is a pure function that reads `agent_state` and returns a `PlannerDecision`. It never calls Qwen, never reads the DB, never has side effects. It is tested independently of every path that calls it.

---

## The vault as routing table

The knowledge vault (`/home/unctad/projects/knowledge-vault/concepts/`) is not documentation. It is executable routing logic. Every `.md` file is a row in the routing table.

**Two connection mechanisms:**

`grows_from` (body text, `## Relationships` section) — maps a finding_type or failure-fact to this concept. Parsed by `graph_resolver._section_body()`. Drives `init_agent_state_async` (initial seeding from DB findings) and the Phase 3 interrogation re-seed (seeding from failure facts like `mid_run_blocked`).

`unlocks` (frontmatter YAML) — maps this concept's success to the set of concepts that should now enter `pending`. Applied by `_apply_verdict_in_place()` in `agent_state.py` after a branch succeeds.

**Adding a new technique class requires vault edits, not code edits.** A new concept `.md` with the correct `grows_from` and `unlocks` edges, combined with a `CONCEPT_ENGINE_MAP` entry in `constants.py`, is sufficient for the planner to route to it. No orchestrator code changes.

**The grows_from seeding path:**

1. `init_agent_state_async` queries `normalized_findings` for validated findings.
2. For each finding_type, calls `graph_resolver.resolve_branches(finding_type)`.
3. Each resolved `BranchSpec` becomes a `{concept_id, priority}` entry in `agent_state.pending`.
4. `pending` is sorted by priority descending. The planner pops the top.

Phase 3 facts (`mid_run_blocked`, `wordlist_exhausted_no_signal`, etc.) use the same machinery but via a different entry point — `autonomous_orchestrator.py` calls `resolve_branches(emitted_fact)` directly after the interrogator emits a fact.

**The vault and the planner together enforce probe-first ordering without code logic.** CONCEPT-LOGIN-PROTECTION-PROBE has priority 99, grows from `login_form_detected`. When a login form finding is validated, the probe concept enters `pending` at priority 99. Every other login-form concept (brute at 85, counter-reset at 78, username-enum at 80) enters at lower priority. The planner pops the highest. Probe runs first. This is not hardcoded anywhere in planner.py — it is vault configuration.

---

## The agent STATE model

`agent_state` is a JSON dict persisted in the `exploitation_branches` table under a synthetic row with `branch_id = state_{investigation_id}`. It is the memory of the exploitation phase.

```python
{
  "goal": {
    "objective":           str,   # from operator chat or planner/run call
    "success_conditions":  list,  # ["valid_credentials_found", ...]
    "provided_self_user":  str | None,  # operator's own account (never the target)
    "target_user":         str | None,  # account to compromise
  },
  "facts":            list[str],  # ["ip_block_detected", "protection_probed", ...]
  "artifacts":        {           # typed buckets
    "credentials": [...],
    "sessions":    [...],
    "tokens":      [...],
    "files":       [...],
  },
  "pending":          list[{concept, priority}],  # sorted desc, planner pops top
  "completed":        list[str],  # concept_ids already dispatched
  "ruled_out":        list[str],  # concept_ids eliminated by ruleset
  "current_position": {
    "authentication": "none" | "authenticated" | "admin",
    "privilege":      "none" | "user" | "admin",
    "access_scope":   list[str],
    "execution":      "none" | "rce",
  },
  "planner_log":         list[str],  # decision trace, surfaced in Zone C
  "interrogation_attempts": int,     # Phase 3 attempt counter
  "interrogation_log":   list[...],  # Phase 3 event log
  "solved":              bool,
  "solved_reason":       str | None,
}
```

**Key invariants on STATE:**

- `self_pass` is NEVER a field in STATE. It cannot be stored. The counter-reset engine requires it at dispatch time via `operator_params`; the planner parks counter-reset with an explicit reason if `self_pass` is absent.
- `provided_self_user` distinguishes the operator's known account from the target account. `check_success()` will not fire SOLVED when `provided_self_user` captures credentials — only `discovered` origin credentials solve the investigation.
- STATE is updated under `_get_state_lock(investigation_id)` (an asyncio Lock keyed by investigation_id). Concurrent verdict writes are serialised; the lock is not held across `await` calls that do network I/O.
- The verdict wire (`apply_verdict_to_state_async`) fires as a fire-and-forget task after each branch completes. It writes `state_changes` facts and `artifacts_captured` objects from the vault concept to STATE, then updates `pending` (removes the completed concept, adds any unlocked concepts).

---

## The verdict wire

When a branch reaches a terminal state (succeeded / exhausted / failed), the verdict wire fires:

```
branch terminal
     ↓
evaluate_verdict(engine_id, concept_id, artifact, exec_state)
     ↓ reads vault concept: state_changes, artifacts_captured, unlocks, rules_out
     ↓
Verdict(match_kind, goal_advanced, state_changes, artifacts_captured, unlocks, rules_out)
     ↓
apply_verdict_to_state_async(investigation_id, verdict, ...)
     ↓
STATE: facts += verdict.state_changes (if artifact present — Fix 3)
STATE: artifacts[bucket] += objects
STATE: pending += verdict.unlocks (not already present, not ruled_out)
STATE: pending -= completed concept
STATE: ruled_out += verdict.rules_out
check_success(STATE) → solved=True if success_condition met
```

**Fix 3 (credential facts coupled to artifact landing):** `credential_obtained` and `session_authenticated` are filtered from `state_changes` when no artifact was captured. This closes the false-positive path where the fact lands in STATE without a credential object to back it — which would cause `check_success` to false-fire SOLVED on the operator's own credentials even when no target credential was found.

**`match_kind`:**
- `"known"` — the concept is in the vault; apply the verdict.
- `"no_concept_match"` — no vault concept for this engine_id; park as an Unknown Artifact in `agent_loop_unknowns` for operator review.

The verdict wire fires on both the planner path (explicit dispatch) and the manual execution path (operator clicks Execute on a mindmap node). Manual executions update STATE the same way as planner-driven ones.

---

## The inquiry layer (Phases 1–3)

The inquiry layer is the probe-interrogation-routing loop that governs what runs and when during exploitation. It has three phases:

**Phase 1 — Pre-flight detection (priority 99)**

`login_protection_probe` runs first. It makes ≤5 HTTP requests, using XFF-spoofed source IPs on any POST that might consume the target's failure counter. It emits a `protection_profile` artifact: which defenses are present (IP block, CSRF per-request, XFF supported). Based on the profile, it directly manipulates `agent_state.pending` — elevating `CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET` to priority 95 when IP block is detected. The probe itself is counter-neutral: the failure budget for the real IP is preserved for the technique that comes next.

*Why counter-neutral matters:* in a live run, probe POSTs that are not spoofed consumed the lab's failure budget before counter-reset started, causing an immediate block. XFF spoofing on probe POSTs resolves this. The probe must not sabotage the technique it routes to.

**Phase 2 — Success precision**

`check_success()` is called after every verdict write. It returns `True` only when:
- A credential with `origin="discovered"` is in `artifacts.credentials`, AND
- That credential's username is not the `provided_self_user`.

Three false-positive paths were closed in V2.3:
- Path A: `provided_self_user` was engine-scoped (only counter-reset set it). Fixed: set at objective level via `operator_params` before any engine runs.
- Path B: bare `credential_obtained` fact fired SOLVED when the artifacts bucket was empty. Fixed: `_has_discovered_credential()` returns False when the bucket is empty.
- Path C: async timing — the fact landed in STATE before the artifact bucket. Fixed: credential facts filtered from `state_changes` when `artifacts_captured` is empty.

**Phase 3 — Failure interrogation (when STUCK)**

When `plan_next_step()` would return `action="stuck"` and the investigation has not exceeded its interrogation budget (default: 5 attempts), interrogation fires:

1. Load recent exhausted branch records for the investigation.
2. Run four pattern-matching matchers in order. Each returns a typed fact or None:
   - `_match_mid_run_blocked` — 429/lockout body detected during a run (not pre-flight).
   - `_match_wordlist_exhausted` — full wordlist consumed with no signal and no block.
   - `_match_missing_csrf_token` — "csrf" in `exhaustion_record.negative_evidence.reason`.
   - `_match_requires_session_first` — "requires_auth" / "session_required" in reason, or session-requiring engine without a captured session.
3. First non-None fact wins.
4. If a fact is emitted and is not already in STATE: write it to `facts`, call `resolve_branches(fact)` to re-seed `pending` from the vault, continue the planner loop.
5. If no fact: write "no actionable reason" to `planner_log`, return `action="stuck"`.

**The interrogator is not a selector.** It emits facts. The vault determines which concepts grow from those facts. The planner selects among the resulting candidates. Three-step separation, clean roles.

**Matcher keyword discipline:** matchers match on `exhaustion_record.negative_evidence.reason` which is an engine-assigned structured tag (`"ip_blocked_or_account_locked"`, `"csrf_extraction_failed"`) — never raw response body text. This is the lesson from the RC2 false positive, where the regex `ip.{0,10}block` matched "IP block" in the PortSwigger lab page title on every response.

---

## Fail-closed everywhere

The system is designed to fail visibly and conservatively, never silently and optimistically.

**Gate registry:** an engine with an unknown `gate_id` is BLOCKED at startup with an explicit log. It does not dispatch silently. An engine declaring both `gate_id` and `gate_ids` is fail-closed.

**Planner without agent STATE:** if `plan_next_step()` is called before agent STATE is initialized, the autonomous loop returns `reason="park"` with an operator-facing message. It does not fall back to an alternative selector.

**Verdict wire on unknown concept:** `match_kind="no_concept_match"` parks the artifact as an Unknown in `agent_loop_unknowns`. It does not silently discard the result.

**Interrogator error:** if the interrogator raises, the caller catches the exception, logs it, and returns `action="stuck"`. It does not retry or silently continue.

**Counter-reset without `self_pass`:** the planner returns `action="park"` with reason "self_pass required, not supplied." It does not attempt a self-login with an empty password.

**Phase 3 attempt cap:** after 5 interrogation attempts, the loop returns `action="stuck"` without calling the interrogator. This prevents a pathological loop where a fact unlocks a concept that exhausts and produces the same fact.

---

## The branch model

An exploitation branch is one technique class applied to one finding with one parameter set. It has a deterministic ID: `exb_` + 12 hex chars of SHA-256 over `(investigation_id, finding_id, engine_id, technique_class)`.

**Branch lifecycle:**

```
pending → armed → running → succeeded
                         → exhausted
                         → failed
                         → cancelled
```

- `pending`: created, not yet started.
- `armed`: operator clicked Arm but has not confirmed execution.
- `running`: engine is executing.
- `succeeded`: engine produced an artifact. One branch per success.
- `exhausted`: engine tried every payload with no success. An `ExhaustionRecord` is written.
- `failed`: engine crashed or was killed by the watchdog.
- `cancelled`: operator or system stopped mid-run.

**Branches are the unit of observation.** The mindmap (the exploitation UI) shows branches as Layer 1 (arm/execute nodes), Layer 2 (running progress), and Layer 3 (artifact or exhaustion record). The right-side panel shows the per-branch detail. Zone B shows Unknown Artifacts (branches that produced no_concept_match).

**Branch persistence:** `exploitation_branches` table in `validation.db`. The STATE synthetic row lives in the same table with `branch_id = state_{investigation_id}`, `engine_id = "investigation_state"`.

**Zombie recovery:** on container restart, any branch stuck in `running` or `armed` with no live asyncio task is transitioned to `failed` by `zombie_recovery.py` during the lifespan startup hook. This prevents phantom branches from blocking future runs.

---

## The operator-approval gate (C6)

Exploitation engines never auto-dispatch. The operator approves every step. This is not a UI preference — it is the architectural boundary that keeps automated discovery separate from active exploitation.

**The gate in practice:**

- The planner proposes (`action="execute"`) and logs the decision to `planner_log`.
- `run_planner_loop` calls `planner_execute_step()` which dispatches the engine.
- From the operator's perspective: the chat box shows a `[Planner]` approval card. The operator clicks Approve. The card routes to `POST /autonomous/seed` with `operator_params`. The loop then executes.

**What the gate does not mean:** operators can supply `max_iterations > 1` to `/planner/run` and let multiple planner iterations run automatically. This is still C6-compliant — the operator confirmed the run at the `/planner/run` call boundary. The gate is at the *run* level, not the *iteration* level.

**Engine names are never visible to operators.** The UI shows findings, techniques, and results — not `credential_brute_counter_reset`. This is the "operator drives car" invariant. Engine names appearing in the operator UI is an architecture violation.

---

## The filtering layer

After enumeration completes, `FilterOrchestrator` runs two passes over all findings in `validation.db`:

**Pass 1:** 19 rules in a first-match-wins chain. Rule categories evaluated in order: drop → validate → incomplete. A finding classified as `dropped` is retained in the DB for audit; it is hidden in the UI by default. `evidence_gap()` results are not first-match-wins — the rule chain continues and the gap reason is written to `enumeration_block_reason`.

**Pass 2:** Reinvocation rules collect `ReinvocationRequest` objects, deduplicate by `(engine_id, config)`, and dispatch additional engine runs via `ExecutionOrchestrator`. New findings from those runs are passed through Pass 1 again.

**The timing invariant:** FilterOrchestrator runs after enumeration, not after recon. Chain-dispatched engines (`auth_recon`, `api_recon`, `sqli_recon`) emit during enumeration; running FilterOrchestrator after recon misses them entirely. This was PR K's bug — `FilterOrchestrator.run()` was wired at the wrong phase boundary.

**DB target:** FilterOrchestrator callbacks must write to `validation.db`, not `orchestration.db`. Pre-PR K, all FilterOrchestrator UPDATEs silently no-oped because the closure captured the wrong DB path. The test `test_seam_db_target_consistency.py` enforces this.

---

## The finding_id contract

Every finding has a deterministic ID: `fnd_` + 12 hex chars of some stable hash over `(investigation_id, finding_type, target, ...)`. Same inputs, same ID, across process restarts.

**Why determinism matters:** FilterOrchestrator writes `UPDATE WHERE finding_id='fnd_xxx'`. If the finding was stored under a different ID (the two-parallel-ID bug — using `uuid4()` instead of `evt.id` at the `NormalizedFinding` construction site), the UPDATE matches zero rows, silently. The finding never gets classified. This was PR L's bug. The fix is one line: pass `finding_id=evt.id` explicitly to `NormalizedFinding` at the storage bridge.

**The `source_scanner` field** on `NormalizedFinding` must be populated from `evt.probe_id`, not hardcoded. Pre-PR D-fix-2, `StorageBridge` hardcoded `"passive_probe"` for all engines. This broke source-based filtering rules.

---

## The seam catalog

A seam is the interface between two independently-correct pieces of code where the contract can be violated silently. The pattern catalog (`tests/conductor/_patterns/README.md`) documents every known seam and its regression test. As of Phase 3 v1 close-out: 25 seams, each with a `test_seam_*.py`.

Before touching any cross-layer interface in a PR:
1. Read its seam entry in `seams.md`.
2. Run the relevant `test_seam_*.py` before and after the change.
3. If the PR introduces a new cross-layer interface, add a `test_seam_*.py` before shipping.

Seam bugs evade unit tests because each side is individually correct. The seam test is the enforcement layer.

---

## What to read next

- `docs/architecture/system.md` — component reference: exact file locations, class names, constructor signatures, DB tables, gate registry.
- `docs/architecture/orchestration.md` — the orchestration spec: all five orchestrators, their event contracts, their internal state machines.
- `docs/architecture/seams.md` — the cross-layer contract inventory: what each seam requires, what breaks if it's violated, which test protects it.
- `docs/architecture/exploitation.md` — the exploitation phase design: the mindmap, branch lifecycle, Layer 1/2/3 semantics, C6 gate.
- `docs/unknown-resolution-playbook.md` — what to do when the system surfaces an Unknown Artifact.
- `tests/conductor/_patterns/README.md` — the seam bug catalog with pattern descriptions and regression tests.
