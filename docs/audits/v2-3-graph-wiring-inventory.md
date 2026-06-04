# V2.3 Graph Wiring Pre-Implementation Inventory

**Date:** 2026-05-27
**Method:** 5 parallel read-only subagents. Every claim cited by file:line.
**Purpose:** Establish concrete starting state before V2.3 implementation PRs begin.

---

## 1. ChainOrchestrator — current state

**Location:** `apps/conductor/orchestrators/chain.py` (201 lines)

**Public API:**
- `__init__(investigation_id, bus, max_depth=5)` — `chain.py:27-43`
- `wire_execution(exec_orch)` — stores reference, no callback (`chain.py:44-45`)
- `wire_session(session_orch)` — stores reference, no callback (`chain.py:47-48`)
- `evaluate_finding(finding: dict)` — entry point; iterates `finding["next_actions"]` (`chain.py:52-94`)
- `operator_arm(action_id)`, `operator_confirm(action_id)` — dispatch from pending store (`chain.py:176-188`)
- `chain_depth(branch_id)`, `get_state()` — read-only (`chain.py:190-200`)

**How findings reach ChainOrchestrator:** direct synchronous call from `FindingsOrchestrator.ingest()` at `apps/conductor/orchestrators/findings.py:103-104`. Not a bus subscriber. No `on_finding()` method — entry point is `evaluate_finding()`.

**`next_actions` dispatch:**
- `trigger="auto_fire"` → gate visibility check → depth limit → rate limit → `exec_orch.dispatch_engine(engine_id)` (`chain.py:139-170`)
- `trigger="operator_arm_required"` / `trigger="operator_confirm_required"` → stored in `self._pending_actions`, bus event emitted; dispatch via `operator_arm()`/`operator_confirm()` (`chain.py:176-188`)

**V2.1 stubs in ChainOrchestrator:** none. All three stubs (Seam 16, 17, 18) live elsewhere (see §4 and §5).

**`get_state()` output** (`chain.py:193-200`):
```python
{"orchestrator": "chain", "investigation_id": str,
 "chain_depths": dict[str, int], "pending_actions": int, "max_depth": int}
```
**Gap:** `pending_actions` is a count only. Full action details (engine_id, trigger, description) are not exposed. V2.3 right-side panel will need these if it renders pending-arm state.

---

## 2. Artifact emission path

**`OutputChannel.emit_stage()`** (`apps/conductor/engines/base.py:135-144`): delegates to `BranchWriter.transition()`. No bus event. Write is a no-op if `_branch_writer is None`.

**`BranchWriter.transition()`** (`apps/conductor/exploitation/branch_store.py:95-123`):
- `state="succeeded"`: `UPDATE exploitation_branches SET state=?, artifact=json(payload)`
- Other states: appends `{state, at, **payload}` to `stage_log` JSON array

**CRITICAL GAP — BranchWriter not wired in production:** `apps/investigation_workspace/execution/runtime.py:190-195` constructs `OutputChannel` with no `branch_writer` argument. Default is `None` (`base.py:84`). **All `emit_stage()` calls are silent no-ops.** `exploitation_branches` is never written during live investigations.

**`BranchReader` callers:** zero outside `branch_store.py` itself. No API route reads from the table. Table is effectively write-only from the UI/API perspective (and actually not even written — see above).

**Bus events on artifact emission:** none. `stage_emitted` event does not exist. `/exploitation-data.json` polling endpoint (V2.3 target) must query `exploitation_branches` directly.

**`SqliAuthBypassEngine` Layer 3 artifact** (`sqli_auth_bypass_engine.py:472-483`):
- `artifact_type="bookmarklet_href"`, fields: `bookmarklet`, `token_preview`, `discovered_email`, `login_url`, `bypass_payload_email`, `response_status`, `session_cookies`, `indicators`, `references`
- **Missing `store_auth()` call** — captured JWT/cookies are not written to `SessionOrchestrator`. Downstream engines cannot read the captured session. This is a behavioral gap introduced in V2.2 (the equivalent probe did not have this issue; probe legacy called `store_target_auth()`).

**`DefaultCredsEngine` Layer 3 artifact + `store_auth()`** (`default_creds_engine.py:249-258`):
- Calls `output_channel.store_auth(investigation_id, auth_result)` ✓ — writes to `session_orch._api_auth_store[investigation_id]`
- `artifact_type="captured_session"`, fields: `username`, `login_path`, `method`, `session_cookies`, `references`

**Cross-pollination hook:** does not exist. When `DefaultCredsEngine` captures auth, no event fires to promote `AccessControlEngine` branch eligibility. Auth is available in the session store for engines that run later in the same session, but the promotion is implicit (no UI update, no branch state change).

---

## 3. Branch eligibility model

**`exploitation_branches` schema** (`apps/validation/database.py:299-312`): columns: `branch_id PK`, `investigation_id`, `finding_id`, `engine_id`, `technique_class`, `operator_params JSON`, `state TEXT DEFAULT 'pending'`, `artifact JSON`, `exhaustion_record JSON`, `stage_log JSON`, `created_at`, `updated_at`. **No `eligible` column.**

**Valid states** (`apps/conductor/exploitation/branch_store.py:23-25`): `pending | armed | running | succeeded | exhausted | failed | cancelled`

**State machine** (`apps/conductor/exploitation/approval.py:30-38`): `pending → {armed, cancelled}`, `armed → {running, cancelled}`, `running → {succeeded, exhausted, failed, cancelled}`, terminal states have no transitions.

**Eligibility computation:** purely on-read from in-memory runtime. `apps/investigation_workspace/branch/topology_v2.py` does not query `exploitation_branches` at all — it reads `apps.investigation_workspace.execution.runtime.active_runs()` (in-memory). Arm affordance (`execute_url`) is assembled in `apps/investigation_workspace/api/routes.py:856-945` from the in-memory execution runtime, not from branch DB state.

**Finding-type → exploit-path eligibility:** static dict at `apps/investigation_workspace/exploitation_paths/bindings.py:22-66`. Compile-time lookup, not DB-driven.

**Arm/execute route:** `POST /investigations/{id}/finding/{fid}/suggest/{action_kind}/execute` at `routes.py:1366-1499`. Does **not** touch `exploitation_branches`. Calls `exec_kick_off()` from in-memory runtime. The `armed` state is written mid-engine by the engine itself via `emit_stage(branch_id, "armed")` — but this is currently a no-op (see §2 gap).

**Rows on re-run:** `Conductor.start_investigation()` allocates a new `investigation_id` (UUID4), never DELETEs `exploitation_branches`. Rows accumulate across investigations, scoped by `investigation_id`.

---

## 4. Re-invocation seam

**Seam 16 contract** (`docs/architecture/seams.md:463-485`): engines must accept `config["extended_payloads"]` and `config["extended_wordlists"]` as optional list kwargs (empty-list default); in V2 engines ignore them; V2.5 Qwen populates them and re-dispatches; engines must union, not replace, presets.

**`_reinvoke_dispatch` closure** (`apps/conductor/conductor.py:92-95`): live today for FilterOrchestrator → ExecutionOrchestrator two-pass. `async def _reinvoke_dispatch(engine_id: str, config: dict): await _exec.dispatch_engine(engine_id, extra_config=config)`. This is the existing filter-driven re-invocation path (REINVOCATION_RULES), not the V2.5 Qwen path.

**`wire_reinvocation_dispatcher(fn)`** (`apps/conductor/orchestrators/filter.py:61-68`): accepts `async fn(engine_id: str, config: dict)`. Called from filter orchestrator after first pass; `_collect_reinvocations()` runs `REINVOCATION_RULES`, dedupes by `(engine_id, config)`, calls fn per unique `ReinvocationRequest`. Two-pass runs after filter.

**Actual V2.5 stub:** `apps/conductor/exploitation/approval.py:95-100` — `_reinvocation_hook(branch_id: str, context: dict) -> None`, body is `logger.debug("reinvocation_hook: not wired (V2.5 consumer)")`. Zero callers in engine files.

**Duplicate-run guard:** none in `ExecutionOrchestrator.dispatch_engine()` (`execution.py:150-179`). Guards are mutex, rate limit, and `_cancelled`. Engine can re-run on same branch freely.

**Config shape sufficiency:** `extra_config: dict` shallow-merged over `self._config` at `execution.py:188`. The `config["extended_payloads"]` / `config["extended_wordlists"]` keys fit this shape. Union-not-replace logic must live inside each engine's `run()`, not in the dispatcher.

**UNFULFILLED V2.2 COMMITMENT:** `seams.md:485` states `test_seam_v2_reinvocation_hook.py` "ships with V2.2". This file does not exist in `tests/conductor/_patterns/`. The `extended_payloads`/`extended_wordlists` keys are also absent from all 9 engine files — the stub keys were documented but not implemented. This must be addressed before V2.3 graph wiring ships seam tests.

---

## 5. Qwen loop hook stubs

**Seam 17 — feedback hook** (`docs/architecture/seams.md:489-509`):
- Contract: `template_spec` carries `feedback_hook: stub` field (V2); V2.1 promotes to `thumbs_up_down`; POSTs to `/api/exploitation/feedback` → `template_feedback` table (must NOT be pre-created in V2).
- Actual stub: `apps/conductor/exploitation/approval.py:87-92` — `_feedback_hook(branch_id, context, outcome) -> None`, body is `logger.debug("feedback_hook: not wired (V2.1 consumer)")`. Zero callers.

**Seam 18 — RAG injection point** (`docs/architecture/seams.md:513-536`):
- Contract: `_inject_rag_context(finding, template_spec) -> template_spec` — called at Layer 1 form construction; pure; in V2 returns unchanged; V2.8 merges ChromaDB top-K chunks into `rag_context` field.
- Actual stub: `apps/conductor/exploitation/payload_registry.py:119` — `load_payloads(technique_id, rag_context: dict | None = None)` accepts param, logs `"rag_context injection not yet wired (V2.8)"` if non-None, ignores it. **No standalone `_inject_rag_context()` function exists.** The seams.md contract names a function that has not been written.

**Vault-ingestion-ready branch shape:** `BranchRecord` fields for V2.5/V2.7 (`branch_store.py:35-48`): `artifact` (Layer 3 payload), `engine_id`, `technique_class`, `operator_params`, `exhaustion_record`, `stage_log`. V2.3 must expose `BranchReader.get(branch_id)` through `/exploitation-data.json` for the right-side panel — this is `BranchReader`'s first production call site.

**`exporters/` dormancy:** confirmed dormant — zero callers in `apps/` or `core/`.

**`apps/investigation_core/exports/` is LIVE (not dormant):** `ExportService` imported at `apps/investigation_core/api/export_routes.py:10`; router included at `apps/investigation_core/api/__init__.py:5`; `investigation_core_router` mounted at `apps/validation/api/__init__.py:22`. Export routes reachable via HTTP. CLAUDE.md's "dormant V2.7 ingestion target" refers to the vault-ingestion path (reading branch artifacts into a knowledge base), not the export routes themselves.

---

## 6. Synthesis

### 6.1 Implementation order recommendation

**First lift: BranchWriter wiring + `/exploitation-data.json` endpoint.**

Rationale: `BranchWriter` not being wired in production is the highest-impact gap — it silently breaks all stage tracking for all 9 engines. This is not a V2.3 feature addition; it is a production defect that must be fixed before any graph-wiring UI work can be meaningfully tested. The fix is contained: wire `BranchWriter` into `OutputChannel` construction in `execution.py`, then add `BranchReader` as the backing store for `/exploitation-data.json`. The polling endpoint is V2.3 scope and the BranchWriter fix is its prerequisite.

**Second lift: `test_seam_v2_reinvocation_hook.py` + engine stub keys.** The unfulfilled V2.2 seam commitment (Seam 16) must be closed before the pattern catalog reaches V2.3. Add the missing seam test and add `extended_payloads`/`extended_wordlists` to each engine's `run()` signature as documented no-ops.

**Third lift: right-side panel + three-level mindmap UI wiring.** Once BranchWriter is live and `/exploitation-data.json` returns real data, the React Flow graph wiring can proceed.

**Cross-pollination and re-invocation:** defer to V2.4+. Neither has a concrete operator workflow request yet, and the substrate gaps (no eligibility promotion hook, no `_reinvocation_hook` callers) are large enough that they warrant their own PR design.

### 6.2 Substrate gaps

| Gap | Location | Required by V2.3? |
|-----|----------|-------------------|
| BranchWriter not wired in `OutputChannel` construction | `execution.py:190-195` | **Yes — blocks all stage tracking** |
| BranchReader has no route caller | `branch_store.py:137` | Yes — `/exploitation-data.json` is its first consumer |
| `test_seam_v2_reinvocation_hook.py` missing | `tests/conductor/_patterns/` | Yes — unfulfilled V2.2 commitment |
| `extended_payloads`/`extended_wordlists` not in engine `run()` signatures | all 9 engine files | Yes — Seam 16 stub contract |
| `SqliAuthBypassEngine` missing `store_auth()` call | `sqli_auth_bypass_engine.py` | Likely — captured session not in session pipe |
| `_inject_rag_context()` function does not exist | `apps/conductor/exploitation/` | No — V2.8 |
| No cross-pollination hook (auth capture → branch eligibility) | `session.py` / `execution.py` | No — V2.4+ |
| `ChainOrchestrator.get_state()` returns count-only for pending_actions | `chain.py:193-200` | Depends on right-side panel design |
| `_feedback_hook` has zero engine callers | `approval.py:87-92` | No — V2.1 Qwen |

### 6.3 Cross-piece concerns

- **BranchWriter wiring + `SqliAuthBypassEngine` `store_auth()` fix** should ship in the same PR. Both are production defects in the artifact path, not V2.3 features. Fixing BranchWriter alone will expose the missing `store_auth()` call when stage logs become visible.
- **Seam 16 stub keys + seam test** must ship before any other V2.3 seam tests, since pattern catalog numbering will advance from 17 → 18 with V2.3's first new seam. Shipping the missing V2.2 commitment first keeps the catalog clean.
- **`/exploitation-data.json` shape** must be designed before the right-side panel is wired — the panel needs `artifact` content inline at Layer 3, which means `BranchRecord.artifact` must be in the endpoint response. Decide field set before implementation.

### 6.4 Operator decisions required before V2.3 implementation

1. **`SqliAuthBypassEngine` `store_auth()` fix scope.** The captured JWT/session from a successful SQLi bypass is not currently written to the session pipe. This means downstream engines (e.g., `AccessControlEngine`) cannot use it. Fix it in V2.3 Step 1 alongside BranchWriter, or treat it as a separate PR? The fix is 3 lines but the behavioral impact is significant (changes cross-engine auth flow).

2. **`/exploitation-data.json` field shape.** What fields does the right-side panel need from `BranchRecord`? Minimum is `state`, `artifact`, `exhaustion_record`, `stage_log`. Should `operator_params` be included (for operator re-review of what they configured)? Decision affects the endpoint contract.

3. **`ChainOrchestrator.get_state()` pending_actions detail.** If the right-side panel shows pending-arm state for chained findings, `get_state()` must expose full action details (engine_id, trigger, description), not just a count. Does V2.3 need this, or is the count sufficient for the mindmap?

4. **Cross-pollination model.** Does V2.3 need visual indication that "DefaultCredsEngine succeeded → AccessControlEngine is now more likely to produce results"? If yes, this requires new wiring (a re-render trigger on `store_auth()` completion, or eligibility annotation in the topology). If no, the implicit session-pipe dependency (silent, no UI) is the V2.3 model. No implementation exists either way.

5. **Re-invocation UX.** Does the operator need a "re-run with extended payloads" button at Layer 1 for V2.3? If yes, the Seam 16 stub keys + `_reinvocation_hook` callers need to ship in V2.3. If V2.3 is graph-wiring-only (read the mindmap, arm, execute, observe Layer 3), then re-invocation stays deferred to V2.5.
