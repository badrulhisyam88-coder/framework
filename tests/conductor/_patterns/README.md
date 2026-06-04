# Seam Bug Pattern Catalog

This directory contains *seam tests* — tests that verify data crossing between
architectural layers preserves the identity, shape, and semantics that downstream
layers depend on.

## Why these tests exist

Multiple bugs and design risks across V1.6–V2.1 shared the same root shape: **mechanically valid code at
each layer, but a silent mismatch at the seam between layers.** Each bug was
mock-tested and verified before live integration revealed the gap. Pure unit tests
missed them because they tested each layer in isolation — never that data crossing
layers actually survived the crossing.

The `_patterns/` tests fill that gap. They are seam tests, not unit tests.

---

## Patterns and their test files

### Pattern 1 — Two-Parallel-ID-Systems (`test_seam_identity_roundtrip.py`)
**Bug:** Since PR B, findings had two IDs: Conductor's deterministic `fnd_xxx` in
memory and a random UUID4 in the DB. FilterOrchestrator `UPDATE WHERE finding_id='fnd_xxx'`
always hit 0 rows. Eight PRs of work built on top of the silent failure. **PR L fix:**
one line in `_persist` — `finding_id=(evt.id or str(uuid4()))`.

**Lesson:** When data crosses between layers with their own ID generation, write an
explicit round-trip test that proves the ID survives the crossing.

### Pattern 2 — Attribution Loss at Seam (`test_seam_attribution_preservation.py`)
**Bug (PR D-fix-2):** StorageBridge hardcoded `source_scanner="passive_probe"` from
when only one consumer existed. nmap, nuclei, zap findings all attributed to
`passive_probe`. Source-based queries silently wrong.

**Lesson:** Attribution metadata must survive all layer transitions. Test it explicitly.

### Pattern 3 — Silently-Disabling Default (`test_seam_default_safety.py`)
**Bug (PR D-fix-2):** `max_chain_depth=0` was the "safe" default. Depth 0 means "do not
dispatch." Chain Orchestrator evaluated next_actions but dispatched nothing. Also: the
FilterOrchestrator timing fix (PR K) belongs here — running after recon instead of
enumeration silently excluded all chain-dispatched findings.

**Lesson:** Defaults intended to be conservative-safe must be reviewed when downstream
consumers are added. Test that a default configuration executes a non-trivial code path.

### Pattern 4 — Adapter Shape Mismatch (`test_seam_adapter_contract.py`)
**Bugs:** (a) nuclei adapter used `-json` flag (v2); nuclei v3.3.5 removed it; adapter
didn't check returncode; 0 findings returned as success. (b) ZAP spider adapter returned
int count when caller expected URL list. Both are caller/callee contract violations.

**Lesson:** Every adapter must check subprocess returncode. Output shapes must be tested
against what engines actually consume.

### Pattern 5 — Dangling Reference (`test_seam_consumer_existence.py`)
**Bug (PR G):** nmap emitted `cve_lookup` next_actions after the CVE chain was dropped.
No engine with `engine_id='cve_lookup'` existed. Dead next_actions wasted Chain
Orchestrator cycles and polluted finding records.

**Lesson:** Every `next_action.engine_id` must reference a registered engine. Every
`gate_id` must exist in the registry. Test statically.

### Pattern 6 — Resource-Class-Blind Policy (`test_seam_resource_policy.py`)
**Bug (PR G):** Flat 30s watchdog threshold killed nuclei mid-scan. nuclei runs a blocking
subprocess that takes 60-300s. The fix differentiated thresholds by `resource_cost`.

**Lesson:** Policies that use `resource_cost` for differentiated limits must actually
apply different limits. Test that heavy engines declare `resource_cost='heavy'`.

### Pattern 7 — Wrong DB Target (`test_seam_db_target_consistency.py`)
**Bug (PR K):** `_validation_update` and `_block_reason_update` captured the conductor's
`_db_path = data/orchestration.db`. `normalized_findings` lives in `validation.db`. Every
UPDATE silently no-oped for the entire V1.7 feature set.

**Lesson:** Any DB writer callback must connect to the DB the reader queries. Test that
writer and reader path sources agree.

### Pattern 8 — Rule Chain Evidence Gap (`test_seam_rule_chain_evidence_gap.py`)
**Invariant (Seam 6):** `RuleResult.evidence_gap()` signals a missing evidence field but
does **not** terminate the rule chain. Subsequent rules must still evaluate. A gap-blocked
finding can still be classified by a later rule — if evidence_gap were first-match-wins,
such findings would silently stay `pending` forever.

**Lesson:** The chain-continue behavior for evidence_gap is a correctness invariant of
`FilterOrchestrator._evaluate()`. Any refactor that adds an early return on
`is_evidence_gap=True` silently breaks all gap-blocked findings. Test explicitly.

### Pattern 10 — Session Pipe Seam (`test_seam_session_pipe.py`)
**Risk (V2.1 auth store merge + V2.1 Step 2b unification):** Two bugs with the same
root shape — wrong scope for auth state. (a) Duplicate `_API_AUTH_STORE` module-level
dict in `suggestions/probes.py` was invisible to `SessionOrchestrator` (removed V2.1
Step 2). (b) Process-level `Conductor.session_orch` created a second `SessionOrchestrator`
instance; probe writes landed in the process-scope store while V2 engines read from the
per-investigation `_InvestigationContext.session_orch` (removed V2.1 Step 2b).

**Invariant (post-Step-2b):** One `SessionOrchestrator` per investigation on
`_InvestigationContext`. `Conductor` has no `session_orch`. ACTIVE-LEGACY probe functions
(fixed `target: str` signatures) reach the correct investigation-scoped store via
`INVESTIGATION_ID_CTX` set in `_runner_from_probe`.

**Lesson:** Auth scope must be investigation-scoped end to end. A process-level
singleton is a silent corruption path for concurrent investigations. Any second
`SessionOrchestrator` instance — whether module-level dict, class singleton, or
process-level attribute — breaks the invariant. Test statically that `Conductor` has
no `session_orch`, that `INVESTIGATION_ID_CTX` is exported and set before probes are
called, and that the expired→refresh state machine is operator-gated.

### Pattern 9 — Output Channel Stage Seam (`test_seam_output_channel_stage.py`)
**Risk (V2.1):** Adding `emit_stage()` to `OutputChannel` could silently break the
existing `emit_finding()` → `FindingsOrchestrator` contract if the constructor signature
changes, or break V1 phase engines if `emit_stage()` raises when no `branch_writer` is
wired. `branch_writer=None` is the default — all V1 engines construct `OutputChannel`
without it.

**Lesson:** When extending an interface used by multiple callers (all existing engines),
the extension must be backward-compatible. `None`-guarded no-op is the correct pattern
for optional downstream collaborators. Test: (a) `emit_finding` still exists, (b)
`emit_stage` is a no-op on `None` writer, (c) it routes correctly when wired.

### Pattern 11 — Operator-Driven Phase Completion (`test_seam_exploitation_phase_completion.py`)
**Risk (V2.1 Step 3):** If any auto-complete path remains for the exploitation phase —
the zero-engine guard in `start_next_phase`, the engine-count guard in `on_engine_completed`,
or a timeout in `_run_phases` — the operator loses control of phase completion. A silent
auto-complete closes the investigation before the operator is done, discarding any
in-flight Qwen proposals (V2.5) or operator-initiated branches.

**Invariant (post-Step-3):** "exploitation" is in `_OPERATOR_DRIVEN_PHASES`. `start_next_phase`
and `on_engine_completed` check the set before calling `_complete_phase`. `operator_complete_exploitation()`
is the ONLY path to `phase_completed` for exploitation. `reenter_exploitation()` exists as a
V2.5 re-entry pipe. `Conductor.operator_complete_exploitation()` delegates to `phase_orch`.

**Lesson:** Any phase that requires human judgement before closing must be explicitly declared
operator-driven. Guard sets (`_OPERATOR_DRIVEN_PHASES`) with static seam tests are the
enforcement layer — without them, any refactor touching the phase completion logic can silently
reintroduce an auto-complete path.

### Pattern 15 — CSRF Refresh Invariant (`test_seam_brute_force_csrf_refresh.py`)
**Risk (V2.2 Step 3):** `CredentialBruteEngine` must issue a fresh GET to the form URL
immediately before each credential POST when `csrf_field` is non-None. Silent failure mode:
a stale token causes the server to reject every attempt after the first with a CSRF error
(often indistinguishable from a wrong-password rejection), producing a false exhaustion
record — the engine reports "no credentials accepted" when it never submitted a valid token.

**Invariant:** Request sequence is `(GET, POST, GET, POST, ...)` for every credential pair.
Each POST uses the token extracted from the immediately-preceding GET. A cached single-token
approach fails as soon as the server rotates CSRF tokens between requests.

**Lesson:** Per-request state (CSRF tokens, nonces, one-time fields) cannot be fetched once
and reused. Any refactor that caches the token outside the per-iteration loop silently
produces false exhaustion records for CSRF-protected targets.

### Pattern 16 — Engine Auth Write Seam (`test_seam_engine_auth_write.py`)
**Risk (V2.2 Step 8):** Engines that produce auth state as their exploitation outcome
(e.g., DefaultCredsEngine) must write credentials through `OutputChannel.store_auth()`.
Silent failure mode: engine records a successful credential capture and emits a finding,
but never writes the credentials to `SessionOrchestrator._api_auth_store`. Downstream
engines call `session_store.get_auth()` and receive `None`; they run unauthenticated
and produce false exhaustion records. The operator sees a "successful" credential capture
but all follow-on authenticated actions fail silently.

**Invariant:** `OutputChannel.store_auth(investigation_id, auth)` exists and delegates
to `SessionOrchestrator.store_auth()`. After a call to `store_auth()`, a subsequent call
to `session_store.get_auth(investigation_id)` on the same `SessionOrchestrator` instance
returns the stored dict. Empty auth dicts write through — the engine controls success
semantics, not the channel.

**Lesson:** Engine-to-session write paths require the same seam discipline as engine-to-
finding write paths. An engine that only calls `emit_finding()` but omits `store_auth()`
leaves the session store in a stale state even though the finding record looks correct.
The write path must be tested end-to-end (channel → orchestrator → readable back via
the session_store interface), not just checked for method existence.

### Pattern 12 — Probe-to-Engine Lift Seam (`test_seam_xss_exploit_engine.py`)
**Risk (V2.2 Step 1):** Lifting `probe_csp_xss_reflected` into `XssReflectedEngine` creates
four co-dependent retirement obligations. If any one is missed: the V2 engine and legacy
probe run in parallel (double-executing against the target); or the catalog entry renders an
Execute button that 404s (probe function no longer exists); or the route-layer confirm gate
checks for a probe action_kind that can never be reached.

**Invariants (post-Step-1, post-C6):** `engine_id='xss_reflect'` registered. Engine declares
`exploitation` phase. Engine is UNGATED — per-action Arm→Execute flow (C6) is the operator
control. `probe_xss_reflected` ABSENT from `suggestions.probes`. `csp_xss_reflected` ABSENT from
catalog `_CSP_SUGGESTIONS`. `csp_xss_reflected` ABSENT from `routes._EXPLOITATION_ACTIONS`.

**Lesson:** Engine-lift PRs are atomic: retire the probe, catalog entry, and route gate in
the same PR that adds the engine. Static seam tests enforce all four obligations together.

### Pattern 13 — Bootstrap ↔ Conductor Phase State Seam (`test_seam_bootstrap_phase_state.py`)
**Risk (V2.1 Step 3 gap):** Activating EXPLOITATION phase in `PhaseOrchestrator._PHASE_SEQUENCE`
without updating `PhasedRun` + `_current_phase()` left the workspace bootstrap permanently
returning "complete" after enumeration. The Exploitation tab was inaccessible from the
operator UI even though the Conductor was correctly running exploitation.

**Invariants (post-fix):** `PhasedRun` has `exploitation_run` field. `_current_phase()` returns
"exploitation" while `exploitation_run.completed_at is None`. `is_exploitation_active()` exported.
`_OPERATOR_DRIVEN_PHASES` and `_PHASE_SEQUENCE` both contain "exploitation". `csp_xss_reflected`
absent from `exploit-tree.js` CRITICAL_KINDS.

**Lesson:** Activating a new phase in the Conductor requires updating the workspace bootstrap
layer in the same PR. Any future new phase must add: (a) a field to `PhasedRun`, (b) a case in
`_current_phase()`, (c) an `is_<phase>_active()` helper, (d) a bus listener in
`_run_all_probes_via_conductor`. Pattern 13 tests enforce all four obligations statically.

### Pattern 14 — Import-time Reachability Seam (`test_seam_import_time_reachability.py`)
**Bug (PR VESTIGE-1):** Deleted modules in `scanner_orchestration/` had zero call-site usages —
pre-deletion grep confirmed no runtime caller invoked them. Two retained ACTIVE-LEGACY modules
(`api/routes.py`, `services/orchestration_service.py`) still imported the deleted modules at the
top of the file. Container crashed with `ModuleNotFoundError` on startup before any request could
be served. The audit's call-site grep view missed module-level import statements.

**Invariant (post-Pattern-14):** Pre-deletion grep must verify **both** views before any deletion:
(1) No call-site reference invokes the deleted code at runtime.
(2) No module-level `import` or `from X import Y` in any retained module references the deleted code.
After any deletion PR, the app's primary entry-point modules must import without `ImportError`.

**Lesson:** Call-site reachability (grep for function calls, class instantiations, attribute access)
is necessary but not sufficient. A second grep pass for bare `import <module>` and
`from <module> import` in all retained files is required before declaring a module safe to delete.
Both greps must pass before the deletion is committed.

### Pattern 19 — Panel Data Source Seam (`test_seam_panel_data_source.py`)
**Risk (V2.3 Step 4):** The three-level exploitation mindmap right-side panel shows artifact and
exhaustion data from exploitation-data.json branch records. If a developer adds a secondary `fetch()`
call inside the panel rendering function (e.g., to a `/context-panel` endpoint), the panel silently
stops working in stale-token or offline cases — exactly when the operator most needs artifact
visibility after a successful exploitation run.

**Invariants (Pattern 19):**
- `exploitation-mindmap.js` polls `/exploitation-data.json` and caches results in `_branchMap`.
- Panel rendering functions (`_panelForAction`, `_panelForProgress`, `_panelForResult`) read from
  `node.data._branch` — no secondary server fetch.
- The `/context-panel` endpoint (capture-bundle panel) is never called from `exploitation-mindmap.js`.
- `workspace-data.json` is passed in via `window.mountExploitationMindmap()`, never fetched internally.
- `investigation_workspace.html` loads `exploitation-mindmap.js`, not the retired `exploit-tree.js`.

**Lesson:** When a UI panel's data source is determined by the polling contract rather than on-demand
fetch, that contract must be enforced statically. A secondary fetch inside panel rendering creates a
race between two sources and breaks the offline/stale-token case silently.

### Pattern 18 — BranchWriter Wiring Seam (`test_seam_branch_writer_wired.py`)
**Risk (V2.3 Step 2 closure of V2.2 production defect):** `ExecutionOrchestrator` constructed
`OutputChannel` without a `branch_writer=` argument since V2.1 Step 1. All `emit_stage()` calls
were silent no-ops: `exploitation_branches` was never written during live investigations. Silent
failure mode: engine runs, operator sees "complete" in the UI, but no audit trail or artifact is
written to disk. Re-running the investigation produces no branch history.

**Invariants (Pattern 18):**
- `ExecutionOrchestrator.__init__` assigns `self._branch_writer` via `BranchWriter()` (verified
  by source inspection to avoid aiosqlite in host environment).
- `ExecutionOrchestrator._launch()` passes `branch_writer=self._branch_writer` to `OutputChannel`
  (verified by source inspection).
- `emit_stage("running", ...)` appends to `stage_log` in `exploitation_branches` (integration test,
  skipped on host — requires aiosqlite/Docker).
- `emit_stage("succeeded", {"artifact": ...})` writes the `artifact` JSON column (integration test,
  skipped on host).
- `BranchWriter.create()` → `BranchReader.get()` round-trips all fields (integration test, skipped on
  host).
- Wiring `BranchWriter` does not break the `emit_finding()` → `FindingsOrchestrator` contract (P18-F,
  runs on host via fake writer).

**Lesson:** Silent no-ops at seam boundaries are undetectable without explicit wiring tests. When an
output channel method is added (emit_stage), immediately verify that the underlying writer is wired
at construction time — not just that the method exists.

### Pattern 17 — MSF Recipe Lookup Seam (`test_seam_msf_recipe_lookup.py`)
**Risk (V2.2 Step 12):** `MetasploitRecipeEngine` receives a `service_detected` finding with
a `service_name` that `lookup_recipe_key()` cannot map to a RECIPES key. Silent failure mode:
engine skips the finding entirely — no ExhaustionRecord, no operator signal, no indication
that a service was unhandled. The operator sees the engine "complete" with zero findings, which
is indistinguishable from a case where every recipe module was run and failed to match.

Additionally: adding a new service to RECIPES without updating `_NMAP_TO_RECIPE` in
`msf_service_map.py` produces permanent exhaustion records against that service — the engine
always exhausts because `lookup_recipe_key()` always returns None.

**Invariants (Pattern 17):**
- Unknown `service_name` → ExhaustionRecord with `detection_method="unknown_service"` emitted
  via `emit_stage("exhausted", ...)` — never a silent no-op.
- All RECIPES keys must be reachable from at least one `_NMAP_TO_RECIPE` entry (coverage guard).
- `lookup_recipe_key()` is case-insensitive and edge-safe (empty string and None return None).
- Engine engine_id="metasploit_recipe" registered. Engine declares "exploitation" phase.
  Engine carries no `gate_id` (C6).

**Lesson:** For engines that dispatch behaviour based on a lookup (service → recipe, CVE → module,
finding_type → technique), the lookup failure path must be an explicit ExhaustionRecord, not a
silent continue. Engines that silently skip unrecognised inputs produce phantom completions — the
operator gets no signal that a finding class had no handler. Write the failure path as an invariant
and test it before the first production exercise.

### Pattern 20 — Finding-Type Registry Seam (`test_seam_finding_type_registry.py`)
**Risk (V2.3 finding-type rename sprint):** Probes and normalizers emit `finding_type` strings that
may not match the keys in `FINDING_TYPE_TO_CATEGORY` (the workspace category map). Silent failure
mode: the sidebar shows "Uncategorized: N" with no label and no exploitation path — the operator
gets no signal that the count represents real findings. Before the rename sprint, 14 findings from a
live PortSwigger lab investigation appeared under "Uncategorized" because `verbose_banner_disclosed`,
`stack_trace_disclosed`, `service_exposure`, and `open_port` had no matching entries in the category
map (canonical names: `server_version_leaked`, `stack_trace_leaked`, `service_banner_disclosed`,
`http_service_detected`, `open_port_detected`).

**Invariants (Pattern 20):**
- Every `finding_type` keyword argument in probe files (`apps/investigation_workspace/probe/`) must
  be either a key in `FINDING_TYPE_TO_CATEGORY` or explicitly listed in `_KNOWN_UNCATEGORIZED`.
- Every `finding_type` value emitted by scanner normalizers (`apps/scanner_orchestration/normalization/`)
  must satisfy the same constraint.
- `_KNOWN_UNCATEGORIZED` is the explicit allowlist for domain-valid types with no exploitation path
  yet (informational recon findings, protocol-level observations). New entries require a comment.

**Lesson:** When a multi-layer naming contract (probe emits → category map receives) is maintained
across multiple files, drift is undetectable until a live investigation surfaces a count mismatch.
Static source inspection of probe emit strings against the category map catches the gap immediately.
Don't wait for "Uncategorized: 14" in a live session — enforce the seam in the test suite.

### Pattern 23 — V1 Probe Retirement Seam (`test_seam_v1_probe_retirement.py`)
**Risk (V2.4 Step 1):** Re-introducing a V1 probe-backed `SuggestionSpec` into SUGGESTIONS would
cause V1 probes to reappear as Execute buttons in the exploitation mindmap. V1 probes write only to
in-memory `_RUNS`, never to `exploitation_branches` — the Execute click would produce no branch
record; the operator would see "Executed" but no mindmap branch would appear.

Also: the `_has_v2_engine` filter in `topology_v2._emit_ghost_actions` Phase 2 must correctly
identify finding_types with V2 engine specs. A false negative (reporting False when engine_id specs
exist) would suppress valid exploitation mindmap nodes; a false positive (reporting True when only
V1 probe specs exist) would let probe ghost nodes leak into the mindmap.

**Invariants (Pattern 23):**
- The 6 retired V2.4 Step 1 action_kinds (`api_browser_recon`, `api_method_enum`, `api_endpoint_enum`,
  `api_authed_recon`, `api_full_discovery`, `purchase_flow`) are absent from SUGGESTIONS.
- No actionable `SuggestionSpec` in SUGGESTIONS has both `probe_runner=None` and `engine_id=None`
  without `guidance_only=True` (no orphaned specs with no dispatch mechanism).
- `_has_v2_engine` returns True for all finding_types that have engine_id-backed specs in SUGGESTIONS.
- `_has_v2_engine` returns False for finding_types with only guidance-only or probe_runner specs.

**Lesson:** Catalog and topology filter invariants must be co-maintained. Retiring specs from the
catalog without enforcing the filter (or vice versa) leaves a partial defence — a new V1 probe spec
could slip in and bypass the filter if the filter tests are absent.

### Pattern 21 — V2 Engine Topology Registration Seam (`test_seam_v2_engine_topology_registration.py`)
**Risk (V2.3 engine topology registration fix):** V2 exploitation engines registered in
`engine_registry` are invisible to the operator if they lack a `SuggestionSpec` entry in
`SUGGESTIONS` (catalog.py). The Phase 2 ghost emission loop reads only from `SUGGESTIONS`; engines
not catalogued there produce no action cards. Before this fix, 8 of 9 V2 exploitation engines
(all except XssReflectedEngine) had empty or absent SUGGESTIONS entries — operators could never arm
them from the mindmap UI. Root cause: V2.2 retirement PRs removed probe_runner entries but left
empty tuples rather than adding engine_id-backed specs.

**Invariants (Pattern 21):**
- Every exploitation-phase engine in `engine_registry` must have at least one `SuggestionSpec` in
  `SUGGESTIONS` with `engine_id` matching the engine's `engine_id` field.
- Every `SuggestionSpec` with `engine_id` set must reference an engine present in `engine_registry`
  (no dangling engine_ids).
- No `SuggestionSpec` may have both `probe_runner` and `engine_id` set simultaneously (ambiguous
  dispatch).

**Lesson:** Engine registration and catalog registration are two independent steps — one can be done
without the other. Add a seam test that proves the pair is always in sync; otherwise silent topology
gaps are only visible to operators who notice missing action cards during live investigation.

---

---

## V2.1 pattern arc (Patterns 9–14)

Patterns 9–14 were introduced across V2.1 to enforce the seams that exploitation
infrastructure added. Together they form a complete guard ring around the V2.1
surface area:

| Pattern | Seam enforced | Risk blocked |
|---|---|---|
| 9 | OutputChannel.emit_stage() extension | Backward incompatibility with V1 engines |
| 10 | Session pipe — investigation-scoped auth | Duplicate SessionOrchestrator; process-level auth scope |
| 11 | Operator-driven phase completion | Silent auto-complete of exploitation phase |
| 12 | Probe-to-engine lift atomicity | Parallel execution of retired probe + new engine |
| 13 | Bootstrap ↔ Conductor phase state | `_current_phase()` returning "complete" during exploitation |
| 14 | Import-time reachability | Container startup crash after module deletion |
| 15 | CSRF refresh invariant | False exhaustion record from stale CSRF token |
| 16 | Engine auth write seam | Successful credential capture that no downstream engine can use |
| 17 | MSF recipe lookup seam | Unknown service_name silently skipped with no operator signal |

All 14 V2.1 patterns have passing tests as of V2.1 closeout (2026-05-26). Pattern 15
added for V2.2 Step 3 (CredentialBruteEngine). Pattern 16 added for V2.2 Step 8
(OutputChannel.store_auth substrate). Pattern 17 added for V2.2 Step 12
(MetasploitRecipeEngine — MSF recipe lookup seam).

## V2.2 pattern arc (Patterns 15–17)

Patterns 15–17 were introduced across V2.2 to enforce the seams that the engine
substrate additions exposed. Together they guard the new substrate write paths and
recipe dispatch paths:

| Pattern | Seam enforced | Risk blocked |
|---|---|---|
| 15 | CSRF token refresh per credential pair (CredentialBruteEngine) | False exhaustion from stale CSRF token |
| 16 | Engine auth write: `OutputChannel.store_auth()` write-through | Credential capture with no downstream auth visibility |
| 17 | MSF recipe lookup: unknown service → ExhaustionRecord | Silent engine no-op on unrecognized service_name |
| 18 | BranchWriter wiring in ExecutionOrchestrator | All emit_stage() calls are silent no-ops; exploitation_branches never written |
| 19 | Panel data source: panel reads from _branchMap only | Panel silently fails on stale-token or offline; secondary fetch competes with poll |

## V2.3 pattern arc (Patterns 18–21)

Pattern 18 and the Seam 16 stub test were added in V2.3 Step 2 to close three V2.2 production
defects identified during live verification (PortSwigger lab, 2026-05-27):

| Defect | Fix | Test |
|---|---|---|
| BranchWriter not wired in ExecutionOrchestrator | Wire in `__init__`; pass to OutputChannel in `_launch()` | Pattern 18 (P18-A to P18-F) |
| SqliAuthBypassEngine missing `store_auth()` | Add Pattern 16 write after bypass confirmation | `test_sqli_auth_bypass_engine.py` (existing suite) |
| Seam 16 stub keys absent from all 9 engine `run()` signatures | Add `extended_payloads`/`extended_wordlists` kwargs + no-op log | `test_seam_v2_reinvocation_hook.py` (Seam 16) |

Pattern 19 added in V2.3 Step 4 (three-level mindmap + right-side panel) to enforce the
panel data source seam:

| Defect class | Invariant | Test |
|---|---|---|
| Panel fetches from context-panel instead of cached branch data | Panel must read from _branchMap only — no secondary server fetch | P19-B |
| Polling URL changed/removed silently | exploitation-data.json URL must be present in source | P19-A |
| Panel open functions lost or aliased to wrong data source | _panelForAction/Progress/Result must use node.data._branch | P19-C |
| Second fetch URL for branch data added (competing source of truth) | Only exploitation-data.json is fetched; workspace-data.json is passed in | P19-D |
| Script tag reverted to exploit-tree.js | Template must reference exploitation-mindmap.js | P19-E |

Pattern 20 added for the V2.3 finding-type rename sprint: probes and normalizers enforced against
FINDING_TYPE_TO_CATEGORY. All 5 rename pairs (verbose_banner_disclosed, stack_trace_disclosed,
service_exposure, open_port, and http service detection split) resolved before adding the test.

Pattern 21 added for the V2.3 engine topology registration fix: all 9 V2 exploitation engines
registered in `engine_registry` enforced to have a `SuggestionSpec` entry with matching `engine_id`
in `SUGGESTIONS`. Closed a bootstrap deadlock where 8 of 9 V2 engines were invisible to operators.

Pattern 22 added for the conductor–workspace ID alignment fix: `conductor._active` must be keyed by
the workspace investigation_id, not a conductor-generated UUID. Closed a permanent 409 on every V2
engine Execute click — `get_context(workspace_uuid)` always returned None because `start_investigation`
generated its own UUID and `runtime.py` never passed `run.investigation_id`.

Pattern 23 added for the V2.4 Step 1 V1 probe retirement: the 6 retired V1 probe action_kinds
(`api_browser_recon`, `api_method_enum`, `api_endpoint_enum`, `api_authed_recon`, `api_full_discovery`,
`purchase_flow`) must not re-appear in SUGGESTIONS. The `_has_v2_engine` filter in topology_v2 correctly
identifies exploitable vs non-exploitable finding_types for Phase 2 ghost emission.

All 23 patterns have passing tests as of V2.4 Step 1 (2026-05-28).

## V2.4 pattern arc (Pattern 23)

| Pattern | Seam enforced | Risk blocked |
|---|---|---|
| 23 | V1 probe retirement: retired action_kinds absent from SUGGESTIONS; `_has_v2_engine` filter correct | V1 probe ghost nodes leak into exploitation mindmap; non-exploitable findings rendered as actionable |

---

## Adding new patterns

As V2+ introduces new architectural seams (Qwen prompt construction, RAG retrieval,
exploitation execution), add new `test_seam_*.py` files here.

Each file should follow the pattern:
1. Header comment: pattern name, bug example, assertion property
2. At least one positive test (current code is correct)
3. At least one regression test (would catch the original bug if re-introduced)
