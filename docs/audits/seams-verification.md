# Seams Verification

Audit date: 2026-05-25. Verified against seams.md (11 documented seams) and
tests/conductor/_patterns/ (7 pattern test files). Code is ground truth; where
code disagrees with seams.md, code wins.

---

## Verification results (11 documented seams)

| Seam | Contract matches code? | Pattern test exists? | Notes |
|---|---|---|---|
| 1 — StorageBridge ID round-trip | YES | YES | `finding_id=(evt.id or str(uuid4()))` in routes.py line 1045 |
| 2 — finding_id determinism | YES | YES | SHA-256, fnd_ prefix, 16-char, 4 inputs — matches doc exactly |
| 3 — DB writer target | YES | YES | Closures in conductor.py import `DB_PATH` from `apps.validation.database` |
| 4 — Source attribution | YES | YES | `storage_bridge.py:43`: `source_scanner=finding.get("probe_id", "unknown")` |
| 5 — Gate registry | PARTIAL DISCREPANCY | YES (partial) | Startup removes unknown-gate engines from registry; doc says "unregistered, app still starts" — code matches. But seams.md says "unknown gate at dispatch: returns False and logs error"; actual code in `engines/__init__.py` deletes from `_registered_engines` at startup — they never reach dispatch. Minor doc/code gap. |
| 6 — RuleResult protocol | YES | NO dedicated test | Dataclass fields match exactly; evidence_gap() classmethod confirmed; 4-tuple `_evaluate()` return confirmed in filter.py |
| 7 — Wordlist registry | YES | NO dedicated test | REGISTERED_WORDLISTS, load_entries(), WordlistNotFoundError, WordlistFileNotFoundError all confirmed |
| 8 — OutputChannel | YES | NO dedicated test | `emit_finding()` → `findings_orch.ingest()`; `record_request()`/`record_response()` → SessionOrchestrator direct (no bus) |
| 9 — Engine watchdog | YES | YES | `_HUNG_THRESHOLD_LIGHT=30.0`, `_HUNG_THRESHOLD_HEAVY=600.0` at execution.py:30–31; threshold selected by `resource_cost` at _check_health |
| 10 — Event bus | YES | NO dedicated test | EventBus shape matches doc exactly: `{orchestrator, event_type, investigation_id, correlation_id, timestamp, payload}` |
| 11 — Audit log | CONFIRMED NOT IMPLEMENTED | NO test (doc says N/A) | Zero `orchestration_audit` references anywhere in apps/; EventBus has no audit subscriber at startup |

---

## Per-seam detail

### Seam 1 — StorageBridge → NormalizedFindingRepository (ID round-trip)

Verified at routes.py line 1045: `finding_id = (evt.id or str(uuid4()))`. The
`NormalizedFinding` model in `apps/scanner_orchestration/normalization/models.py`
line 13 still has `default_factory=lambda: str(uuid4())` — this default only fires
if the caller omits `finding_id`, which routes.py no longer does.

Contract: confirmed. No discrepancy.

### Seam 2 — finding_id determinism

`apps/investigation_workspace/probe/finding_id.py`: algorithm is
`f"{probe_id}|{target}|{path}|{finding_type}"` → SHA-256 → `fnd_{digest[:12]}`.
All engine wrappers that call `translate_finding_event()` pass this through; engines
that generate their own IDs (nuclei_engine.py, zap_engine.py) also call
`generate_finding_id()` directly. `FindingsOrchestrator.ingest()` generates an ID
as fallback if `finding.get("id")` is absent, using `(engine_id, endpoint, phase,
category)` as inputs. Seams.md documents `(probe_id, target, path, finding_type)` —
the fallback in `FindingsOrchestrator` uses `endpoint` in place of `target` and
`phase` in place of `path`. This is a minor input-substitution discrepancy from the
canonical contract, but only fires when an engine emits a finding without a
pre-generated `id` field — a contract violation by that engine, not a regression.

### Seam 3 — FilterOrchestrator DB writer target

Confirmed at conductor.py lines 113–115 (`_validation_update`) and 130–132
(`_block_reason_update`): both closures do `from apps.validation.database import
DB_PATH as _VALIDATION_DB` inside the function body, then
`async with _aiosqlite.connect(_VALIDATION_DB)`. The old pattern
(`aiosqlite.connect(_db_path)`) is absent. `test_seam_db_target_consistency.py`
tests this via source-code inspection — would catch a regression.

### Seam 4 — Source attribution

`storage_bridge.py` line 43: `source_scanner=finding.get("probe_id", "unknown")`.
`translate_finding_event()` in `apps/conductor/engines/translation.py` sets
`"probe_id": engine_id` in the returned dict. Both sides confirmed; the seam test
exercises the bridge live with a mock persist_fn and asserts `source_scanner == "nmap"`.

### Seam 5 — Gate registry

Startup validation in `apps/conductor/engines/__init__.py` (`_validate_engine_gate_references()`)
iterates `_registered_engines` and deletes any engine whose `gate_id` or any member
of `gate_ids` is not in `_REGISTERED_GATES`. Engines with bad gate references are
removed from the runtime registry entirely.

Minor doc/code gap: seams.md says "App still starts — misconfigured engines are
blocked, not fatal. Unknown gate at dispatch: `engine_is_visible()` returns False
and logs an error." In practice, engines with bad gates are deleted at startup, so
they cannot reach the dispatch-time check. The fail-closed guarantee is stronger
than documented: bad-gate engines are not merely invisible, they are deregistered.
No practical impact but seams.md overstates the dispatch-time gate check's role.

### Seam 6 — RuleResult protocol

`apps/conductor/rules/base.py`: `RuleResult` dataclass matches the documented
schema exactly (matched, status, reason, gaps, is_evidence_gap). `evidence_gap()`
classmethod confirmed. `FilterOrchestrator._evaluate()` returns a 4-tuple
`(status, reason, gaps, block_reason)` as documented. Evidence-gap findings leave
`status=None` (chain continues) while `block_reason` is set. No dedicated seam
test. Covered only by integration-level FilterOrchestrator tests in
`tests/conductor/`.

### Seam 7 — Wordlist registry

`apps/conductor/wordlists.py` matches docs completely: three registered wordlists,
`load_entries()` dispatches by format (`yaml`/`csv`/`txt`), `WordlistNotFoundError`
and `WordlistFileNotFoundError` both defined. Paths relative to `REPO_ROOT`
confirmed. No seam test exists; failure mode is a `KeyError` or
`FileNotFoundError` raised at engine dispatch time — visible but not tested
contractually.

### Seam 8 — OutputChannel

`apps/conductor/engines/base.py` lines 69–99: `OutputChannel` matches docs exactly.
`emit_finding()` → `findings_orch.ingest(finding, self.engine_id)`. `record_request()`
and `record_response()` → `session_orch` directly (no event bus). Constructed by
`ExecutionOrchestrator._launch()` before each `engine.run()` call. No dedicated seam
test; the "direct to SessionOrchestrator" shortcut for rate-limiting is
undocumented in the test layer.

### Seam 9 — Engine watchdog

`apps/conductor/orchestrators/execution.py` lines 30–31: `_HUNG_THRESHOLD_LIGHT=30.0`,
`_HUNG_THRESHOLD_HEAVY=600.0`. Threshold selection in `_check_health()` (lines
360–364): `threshold = _HUNG_THRESHOLD_HEAVY if engine.capabilities.resource_cost == "heavy" else _HUNG_THRESHOLD_LIGHT`. All three seam test cases in
`test_seam_resource_policy.py` pass: constant values, branching logic, and
`resource_cost='heavy'` declarations for nmap/nuclei/zap.

### Seam 10 — Event bus

`apps/conductor/events/bus.py`: `EventBus.emit()` produces exactly
`{orchestrator, event_type, investigation_id, correlation_id, timestamp, payload}`.
`SubscriptionHandle.cancel()` removes the callback. Subscriber exceptions are
caught and logged, not propagated — confirmed at lines 74–76. No dedicated seam test.
The subscription-handle leak vector (handles not cancelled after investigation
completion) is documented in seams.md but untested.

### Seam 11 — Audit log

`grep -rn "orchestration_audit"` across all of `apps/` returns zero results. No JSONL
writer, no audit subscriber wired to the EventBus. Status confirmed: not implemented.
Consistent with seams.md which explicitly marks this as deferred for V2.7.

---

## Pattern test coverage map

| Test file | Seam(s) protected | Coverage gap |
|---|---|---|
| `test_seam_identity_roundtrip.py` | Seam 1 (ID round-trip), Seam 2 (determinism) | Full coverage of both seams |
| `test_seam_attribution_preservation.py` | Seam 4 (source attribution) | Covers StorageBridge and translate_finding_event sides |
| `test_seam_default_safety.py` | Seam 3 (timing: filter runs after enumeration), Seam 9 (max_chain_depth) | Covers timing of FilterOrchestrator invocation and chain depth default |
| `test_seam_db_target_consistency.py` | Seam 3 (DB writer target) | Covers DB path mismatch; also checks absolute path requirement |
| `test_seam_adapter_contract.py` | Seam 8 (OutputChannel adapter shape indirectly), Seam 5 (gate indirectly) | Tests nuclei v3 flag, returncode check, ZAP spider return type |
| `test_seam_consumer_existence.py` | Seam 5 (gate registry), dangling-reference pattern | Every engine's gate_id in registry; every next_action engine_id registered |
| `test_seam_resource_policy.py` | Seam 9 (watchdog threshold) | Heavy/light threshold differentiation; heavy engine declarations |

**Documented seams with NO pattern test:**
- Seam 6 (RuleResult protocol)
- Seam 7 (Wordlist registry)
- Seam 8 (OutputChannel)
- Seam 10 (Event bus)
- Seam 11 (Audit log — documented as not-yet-wired; test deferred intentionally)

---

## Undocumented seams found

### US-1: scan_id UUID4 → NormalizedFinding (FK orphan risk)

**What:** `ScanExecution.scan_id` is `default_factory=lambda: str(uuid4())` in
`apps/scanner_orchestration/execution/models.py:22`. `_persist()` in routes.py
creates a new `ScanExecution` on the first finding per investigation and
inserts it. The `NormalizedFinding` is linked to this `scan_id`. There is no
referential-integrity check between `scan_id` on a finding and any existing
`scan_executions` row. If two concurrent calls to `_persist()` for the same
`investigation_id` both check `list_for_investigation()` before either inserts
the `ScanExecution`, both will insert a new scan, and findings from the second
race leg will carry a different `scan_id`.

**Silent failure mode:** Queries using `list_for_scan(scan_id)` to group findings
by scan return partial results. No error — just missing findings under the "wrong"
scan. Currently low-severity (single-process uvicorn, rare in practice) but
structurally a race.

**Priority:** Low — single-process deployment makes the race unlikely; no V1.x
report of this surfacing.

### US-2: ContextVar probe-evidence bridge (runtime.py → suggestions/probes.py)

**What:** `FINDING_EVIDENCE_CTX`, `ACTION_ID_CTX`, and `OPERATOR_INPUTS_CTX` are
`ContextVar` instances defined in
`apps/investigation_workspace/execution/runtime.py`. The setter path is
`_runner_from_probe()` (via `FINDING_EVIDENCE_CTX.set(evidence_hints)` and
`ACTION_ID_CTX.set(run.action_id)`) and the execute route (via
`_OPERATOR_INPUTS_CTX.set(dict(_form))`). The reader path is
`apps/investigation_workspace/suggestions/probes.py` — at least 10 call sites
read these vars. `_load_finding_evidence()` in execution/runtime.py reads
`raw_data` from `normalized_findings` via `NormalizedFindingRepository(db).get_by_id(finding_id)` using `validation.db` via `get_db()`.

**Contract:** The ContextVar value must be set on the same asyncio Task (or a
descendent) as the probe consumer. If a probe is called from a different task
context (e.g., via `asyncio.create_task()`), the ContextVar is not inherited.
Readers use `(FINDING_EVIDENCE_CTX.get() or {})` as a safe fallback, so failure
is graceful (empty dict) rather than fatal — but the probe re-enumerates rather
than using recon hints.

**Silent failure mode:** Probe silently re-discovers paths instead of using
parent finding's evidence. No error. Functional regression in Qwen/V2 collaboration
scenarios where evidence-hint passing is expected.

**Priority:** Medium — current probes fall back gracefully; V2.5 Qwen collaboration
depends on this seam working correctly.

### US-3: disc-{finding_id} node ID convention (topology → evidence load)

**What:** The topology layer (routes.py, topology_v2.py) creates graph node IDs
as `disc-{finding_id}` for discovery nodes. The execution runtime's
`_load_finding_evidence(parent_node_id)` strips the `disc-` prefix to recover
`finding_id` for a DB lookup. This string-prefix convention is not documented as
a seam. Any change to the node ID format (e.g., adding a namespace prefix or
changing the disc- sentinel) silently breaks evidence lookup without error —
`_load_finding_evidence()` returns `{}` for any non-`disc-` node.

**Silent failure mode:** Evidence hints not loaded; probe re-enumerates. Same
graceful fallback as US-2. The string-stripping logic appears in at least 5
places in routes.py and topology_v2.py.

**Priority:** Medium — no test covering the prefix convention; renaming it is a
multi-file change with a silent failure mode.

### US-4: findings table vs. normalized_findings table (two finding schemas in validation.db)

**What:** `apps/validation/database.py` initializes `validation.db` with both a
`findings` table (used by `apps/validation/repositories/__init__.py` — the older
Metasploit/scanner findings pipeline) and a `normalized_findings` table (used by
`NormalizedFindingRepository` — the Conductor pipeline). Both are in the same DB
file (`/app/data/validation.db`). The `findings` table has a `validation_status`
column (queried in `repositories/__init__.py:673`) that is a different field from
`normalized_findings.validation_status` (the V1.7 FilterOrchestrator output).

**Silent failure mode:** Code that queries `validation_status` on the `findings`
table (old pipeline) and code that queries it on `normalized_findings` (new
pipeline) are not interchangeable. A reader that opens validation.db but queries
the wrong table gets an empty result set or stale data without error. Currently
the two codepaths are separate, but the name collision increases the risk of
confusion in V2 when exploitation results may need to bridge both schemas.

**Priority:** Medium — no known active bug; risk materializes when V2 joins data
across both tables.

### US-5: sdk.Logger import (load-bearing vestigial dependency)

**What:** `from sdk import Logger` appears in at least 15 production files across
`apps/validation/`, `apps/scanner_orchestration/`, `apps/investigation_core/`,
and `apps/investigation_workspace/`. The `sdk/` directory is vestigial factory
scaffolding. CLAUDE.md documents this as load-bearing: sdk/ cannot be removed
until all consumers are migrated to `stdlib logging`. `bootstrap/runtime.py:374`
also has a live `from sdk import Logger` inside an async function. If sdk.Logger
is ever removed or breaks (e.g., the sdk/ module is accidentally deleted by a
subagent), all 15+ import sites raise `ImportError` at function call time —
mostly deferred imports, so startup may succeed but the affected code paths fail
silently at runtime.

**Silent failure mode:** Deferred `from sdk import Logger` inside functions means
startup succeeds; failures only surface when those code paths are exercised.
`bootstrap/runtime.py` would silently fall through the `except Exception` and log
nothing, while returning from the timeout branch.

**Priority:** Medium — known tech debt, documented in CLAUDE.md, but no test
guards against accidental sdk/ deletion.

---

## Seam gap summary (ordered by priority)

| Seam | Pattern test? | Priority | Silent failure mode |
|---|---|---|---|
| Seam 6 — RuleResult protocol | NO | Critical | evidence_gap treated as first-match-wins → all findings lacking evidence field silently dropped rather than surfaced as blocked |
| US-2 — ContextVar evidence bridge | NO | Medium | Probe re-enumerates instead of using recon hints; V2.5 Qwen collaboration depends on correct hints |
| US-3 — disc- node ID convention | NO | Medium | Evidence hints silently empty; multi-site string-stripping has no contractual test |
| US-4 — findings vs. normalized_findings table collision | NO | Medium | Wrong-table query returns empty result; risk materializes in V2 cross-table joins |
| US-5 — sdk.Logger vestigial imports | NO | Medium | 15+ deferred ImportError paths; startup succeeds, failures only at runtime |
| Seam 7 — Wordlist registry | NO | Low | KeyError or FileNotFoundError at dispatch time — visible but untested contractually |
| Seam 8 — OutputChannel | NO | Low | Engine writing DB directly bypasses dedup (detectable), but no test for the no-direct-write contract |
| Seam 10 — Event bus | NO | Low | Subscription handle leak after investigation completion; no test for cancel discipline |
| US-1 — scan_id UUID4 race | NO | Low | Partial findings under scan-grouped queries; single-process deployment makes race rare |
| Seam 11 — Audit log | NO | N/A | Not yet wired; test explicitly deferred to V2.7 per seams.md |
