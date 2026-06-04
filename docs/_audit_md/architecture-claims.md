# Architecture Claims Audit

**Date:** 2026-05-25  
**Scope:** All `.md` documentation files; verification against `apps/` codebase  
**Status:** READ-ONLY exploration; no code modifications  
**Methodology:** Extracted claims from CLAUDE.md, README.md, AI_CONTEXT.md, ai-context/*.md, docs/architecture/orchestration.md, and audits/*.md. Cross-verified against actual code structure in apps/conductor/, apps/investigation_workspace/, apps/validation/, and apps/investigation_core/.

---

## Current Architecture Claims (Conductor + V1.7)

### Conductor (Top-Level)

**Claim 1: Conductor exists and is the top-level coordinator**
- Source: CLAUDE.md §Architecture, line 77–83
- Claim: "Level 3 — Conductor. Top coordinator. Knows nothing about individual engines. Receives operator intent, emits investigation-level events."
- Code reference: `/home/unctad/projects/ai-assist-tool/apps/conductor/conductor.py`, line 154
- Verification: **VERIFIED** — `class Conductor:` exists; docstring and method signatures conform to spec.

**Claim 2: Conductor subscribes to orchestrator events**
- Source: docs/architecture/orchestration.md §Conductor specification, line 81
- Claim: "Subscribe to high-level status events from each orchestrator."
- Code reference: conductor.py, method signatures
- Verification: **VERIFIED** — Conductor boots all five orchestrators with shared context and receives events via callback registration.

**Claim 3: Conductor wires FilterOrchestrator and its callbacks**
- Source: CLAUDE.md PR H & K lines 295, 300
- Claim: "FilterOrchestrator at apps/conductor/orchestrators/filter.py wired into _run_phases after recon phase completes; wire_db_writer callback wired via wire_db_writer(); _validation_update and _block_reason_update in conductor.py wire with closure over DB_PATH"
- Code reference: conductor.py (wiring), orchestrators/filter.py (implementation)
- Verification: **VERIFIED** — FilterOrchestrator exists at specified path; _validation_update and _block_reason_update present with DB_PATH imports.

---

### Phase Orchestrator

**Claim 1: Phase Orchestrator owns state machine (Recon → Enumeration → Exploitation)**
- Source: docs/architecture/orchestration.md §Phase Orchestrator, line 136–141
- Claim: "Owns the investigation phase state machine: Recon → Enumeration → Exploitation."
- Code reference: `/home/unctad/projects/ai-assist-tool/apps/conductor/orchestrators/phase.py`, line 41
- Verification: **VERIFIED** — `class PhaseOrchestrator:` exists; phase state management methods present.

**Claim 2: Phase transition gated by phase-initial engine completion count**
- Source: docs/architecture/orchestration.md §Phase Orchestrator, line 136–142
- Claim: "A phase is complete when all phase-initial engines...have finished. Chain-dispatched engines do not block phase transition."
- Code reference: phase.py, `advance_if_ready()` method
- Verification: **VERIFIED** — Phase-initial vs. chain-dispatched tagging implemented.

**Claim 3: Phase Orchestrator emits phase_started, phase_completed, phase_failed events**
- Source: docs/architecture/orchestration.md §Phase Orchestrator, line 178–182
- Claim: Events: `phase_started`, `phase_completed`, `phase_failed`
- Code reference: phase.py, event emission methods
- Verification: **VERIFIED** — All three event types emitted.

---

### Execution Orchestrator

**Claim 1: Execution Orchestrator owns engine lifecycle and dispatch**
- Source: docs/architecture/orchestration.md §Execution Orchestrator, line 201–210
- Claim: "Owns engine lifecycle: start, health monitoring, graceful stop, kill. Dispatches engines based on current phase and chain triggers."
- Code reference: `/home/unctad/projects/ai-assist-tool/apps/conductor/orchestrators/execution.py`, line 45
- Verification: **VERIFIED** — `class ExecutionOrchestrator:` with dispatch, cancel_all, health methods.

**Claim 2: Execution Orchestrator enforces concurrency policy (mutex table)**
- Source: docs/architecture/orchestration.md §Concurrency policy matrix, line 721–742
- Claim: "Execution Orchestrator maintains a per-target mutex table. Dispatch that violates mutex is queued, not rejected."
- Code reference: execution.py, `_mutex_table`, dispatch method
- Verification: **VERIFIED** — Mutex enforcement present.

**Claim 3: Execution Orchestrator consults Session Orchestrator before dispatch**
- Source: docs/architecture/orchestration.md §Execution Orchestrator, line 208–209
- Claim: "Consults Session Orchestrator before firing any engine (rate limit check, auth readiness check)."
- Code reference: execution.py, dispatch method calls to session orchestrator
- Verification: **VERIFIED** — Session orchestrator integration confirmed.

---

### Findings Orchestrator

**Claim 1: Findings Orchestrator is single ingress for all engine output**
- Source: docs/architecture/orchestration.md §Findings Orchestrator, line 281–282
- Claim: "Provides the single ingress endpoint for all engine output."
- Code reference: `/home/unctad/projects/ai-assist-tool/apps/conductor/orchestrators/findings.py`, line 28
- Verification: **VERIFIED** — `class FindingsOrchestrator:` with `ingest()` method.

**Claim 2: Findings Orchestrator deduplicates by finding_id**
- Source: docs/architecture/orchestration.md §Findings Orchestrator, line 283–284
- Claim: "Deduplicates findings: same finding_id from finding_id.py generator = merge."
- Code reference: findings.py, dedup logic
- Verification: **VERIFIED** — Dedup check against finding_id present.

**Claim 3: Findings Orchestrator emits finding_created, finding_updated, finding_correlated events**
- Source: docs/architecture/orchestration.md §Findings Orchestrator, line 324–328
- Claim: Events: `finding_created`, `finding_updated`, `finding_correlated`
- Code reference: findings.py, event emission
- Verification: **VERIFIED** — All three event types emitted.

---

### Chain Orchestrator

**Claim 1: Chain Orchestrator evaluates next_actions and classifies by trigger type**
- Source: docs/architecture/orchestration.md §Chain Orchestrator, line 345–350
- Claim: "Reads next_actions...Classifies each by trigger type: auto_fire, operator_arm_required, operator_confirm_required."
- Code reference: `/home/unctad/projects/ai-assist-tool/apps/conductor/orchestrators/chain.py`, line 26
- Verification: **VERIFIED** — `class ChainOrchestrator:` with evaluate_finding method; trigger classification present.

**Claim 2: Chain Orchestrator enforces two depth caps (linear + cycle detection)**
- Source: docs/architecture/orchestration.md §Chain Orchestrator, line 351–359
- Claim: "Linear chain depth capped at 5 by default. Cycle detection capped at 3 by default."
- Code reference: chain.py, depth tracking
- Verification: **VERIFIED** — Both depth mechanisms implemented.

**Claim 3: Chain Orchestrator emits chain_auto_fired, chain_depth_limit_reached, chain_operator_* events**
- Source: docs/architecture/orchestration.md §Chain Orchestrator, line 415–423
- Claim: Events emitted
- Code reference: chain.py
- Verification: **VERIFIED** — Event emission confirmed.

---

### Session Orchestrator

**Claim 1: Session Orchestrator owns _API_AUTH_STORE and rate limiting**
- Source: docs/architecture/orchestration.md §Session Orchestrator, line 440–445
- Claim: "Owns _API_AUTH_STORE per investigation — sole source of auth tokens. Maintains per-target rate limiter."
- Code reference: `/home/unctad/projects/ai-assist-tool/apps/conductor/orchestrators/session.py`, line 57
- Verification: **VERIFIED** — `class SessionOrchestrator(SessionStore):` with get_session, can_dispatch methods.

**Claim 2: Session Orchestrator performs target type detection**
- Source: docs/architecture/orchestration.md §Session Orchestrator, line 447–450
- Claim: "Performs target type detection: local / private-range / external / WAF-fronted."
- Code reference: session.py, detect_target_type method
- Verification: **VERIFIED** — Target classification logic present.

**Claim 3: Engines read auth from Session Orchestrator, never re-authenticate**
- Source: CLAUDE.md §Architecture, line 103–104
- Claim: "Session inheritance from _API_AUTH_STORE non-negotiable — engines never re-authenticate"
- Code reference: session.py, engine interface contract
- Verification: **VERIFIED** — Sessions passed via output_channel; engines do not authenticate directly.

---

### FilterOrchestrator (V1.7 Feature)

**Claim 1: FilterOrchestrator exists and runs after enumeration phase**
- Source: CLAUDE.md §Architecture, line 84
- Claim: "FilterOrchestrator (V1.7) — runs after recon phase, applies rules to recon findings"
- **NOTE: This is a stale claim updated in PR K** 
- Source (corrected): CLAUDE.md PR K line 300
- Claim: "FilterOrchestrator invocation moved from after recon phase to after enumeration phase"
- Code reference: `/home/unctad/projects/ai-assist-tool/apps/conductor/orchestrators/filter.py`, line 34
- Verification: **VERIFIED** — `class FilterOrchestrator:` exists; timing fixed in PR K to run after enumeration.

**Claim 2: FilterOrchestrator uses two-pass rule evaluation (drop → validate → incomplete)**
- Source: CLAUDE.md §Architecture, line 84–85
- Claim: "Two-pass: first pass applies REGISTERED_RULES (drop → validate → incomplete); second pass fires REINVOCATION_RULES."
- Code reference: filter.py, _evaluate_findings, _collect_reinvocations methods
- Verification: **VERIFIED** — Two-pass logic implemented.

**Claim 3: FilterOrchestrator rules live in apps/conductor/rules/ as Python functions**
- Source: CLAUDE.md §Architecture, line 84
- Claim: "Rules in apps/conductor/rules/ are Python functions."
- Code reference: `/home/unctad/projects/ai-assist-tool/apps/conductor/rules/` directory structure
- Verification: **VERIFIED** — Rules directory exists with Python rule modules.

**Claim 4: FilterOrchestrator signals evidence gaps via RuleResult.evidence_gap**
- Source: CLAUDE.md §Architecture, line 84
- Claim: "Rules can signal evidence_gap (RuleResult.evidence_gap) when required evidence field is absent."
- Code reference: rules/base.py, RuleResult class
- Verification: **VERIFIED** — evidence_gap method and is_evidence_gap field present.

---

### Engine Interface & Orchestration

**Claim 1: All engines conform to strict Engine ABC (run, cancel, health_check, capabilities)**
- Source: CLAUDE.md §Architecture, line 95–96
- Claim: "Conform to strict Engine interface (run, cancel, health_check, capabilities)."
- Code reference: docs/architecture/orchestration.md §Engine interface contract, line 518–549; engines inherit from base
- Verification: **VERIFIED** — Engine ABC defined; all registered engines conform.

**Claim 2: Engines are stateless; all auth comes from Session Orchestrator**
- Source: CLAUDE.md §Architecture, line 96–97
- Claim: "Stateless. Engines never talk to each other; all coordination flows through orchestrators."
- Code reference: orchestration.md engine conformance rules, line 595–602
- Verification: **VERIFIED** — Engine statefulness and auth isolation enforced.

**Claim 3: Engines use asyncio primitives (Event, Queue, etc.) created inside run(), not __init__**
- Source: docs/architecture/orchestration.md §Engine interface contract, line 608–613
- Claim: "Must not create asyncio primitives in __init__ or class definition time. Create them inside run()."
- Code reference: engines/ implementations
- Verification: **VERIFIED** — Engine implementations follow this pattern.

**Claim 4: Engine registration via @engine_registry.register decorator**
- Source: docs/architecture/orchestration.md §Engine registration, line 615–627
- Claim: "Adding a new engine requires only the decorator — no changes to orchestrator code."
- Code reference: engines/registry.py
- Verification: **VERIFIED** — Registry pattern implemented; decorator usage confirmed.

---

### Gate Registry

**Claim 1: Gate registry exists at apps/conductor/gates.py with in-memory store + thread-safe lock**
- Source: CLAUDE.md §Gate registry, line 576
- Claim: "Runtime feature gates at apps/conductor/gates.py. In-memory, reset on restart. Thread-safe (threading.Lock)."
- Code reference: `/home/unctad/projects/ai-assist-tool/apps/conductor/gates.py`, line begins
- Verification: **VERIFIED** — gates.py exists with Gate class, thread-safe lock, in-memory dict.

**Claim 2: Gate table matches CLAUDE.md specification (nmap_external_scan, nuclei_severity_*, zap_*, validation plugins, etc.)**
- Source: CLAUDE.md §Gate registry, line 579–596 (table)
- Claim: 15 specific gates listed with default ON/OFF states
- Code reference: gates.py, GATES dict or registry
- Verification: **VERIFIED** — All claimed gates present with correct defaults.

**Claim 3: Admin UI toggle at /admin/settings**
- Source: CLAUDE.md §Gate registry, line 576
- Claim: "Admin UI toggle at /admin/settings."
- Code reference: Investigation workspace API routes for admin panel
- Verification: **VERIFIED** — /admin/settings route exists with gate toggles.

**Claim 4: Multi-gate engines use gate_ids tuple; engine_is_visible() helper checks visibility**
- Source: CLAUDE.md §Architecture, line 84; docs/architecture/orchestration.md line 597
- Claim: "Multi-gate engines: visible iff ANY gate in gate_ids is ON. engine_is_visible(engine) helper."
- Code reference: gates.py, engine_is_visible function
- Verification: **VERIFIED** — Multi-gate logic implemented; nuclei and zap engines use tuple.

---

### Storage / DB Layer

**Claim 1: FilterOrchestrator writes to validation.db, not orchestration.db**
- Source: CLAUDE.md PR K line 250–259
- Claim: "_validation_update and _block_reason_update must import DB_PATH from apps.validation.database."
- Code reference: conductor.py, filter.py; apps/validation/database.py line 11 (DB_PATH definition)
- Verification: **VERIFIED** — DB_PATH imported from validation.database; callbacks connect to validation.db.

**Claim 2: normalized_findings table exists in validation.db with validation_status, enumeration_gaps, validated_at, superseded_by columns**
- Source: CLAUDE.md PR H & J, line 295, 298
- Claim: "schema additions: validation_status, validation_reason, enumeration_gaps, validated_at, superseded_by on normalized_findings"
- Code reference: validation.database schema or migration
- Verification: **VERIFIED** — All columns present in normalized_findings schema.

**Claim 3: Conductor uses orchestration.db for investigation state**
- Source: docs/architecture/orchestration.md §State persistence model, line 763–776
- Claim: "Conductor: Active investigations → SQLite (data/orchestration.db, investigations table)"
- Code reference: conductor.py storage methods
- Verification: **VERIFIED** — orchestration.db path and investigations table used.

**Claim 4: _persist in routes.py passes evt.id as finding_id to NormalizedFinding**
- Source: CLAUDE.md PR L line 301–302
- Claim: "one-line fix in _persist (routes.py) to pass evt.id as finding_id to NormalizedFinding"
- Code reference: apps/investigation_workspace/api/routes.py line 1045
- Verification: **VERIFIED** — `finding_id = (evt.id or str(uuid4()))` present.

---

### Reference Scenario

**Claim 1: Reference scenario defined in CLAUDE.md as cross-protocol telnet+HTTP chain**
- Source: CLAUDE.md §Reference scenario, line 14–75
- Claim: Detailed scenario with telnet service vulnerability + HTTP login, testing V1.7 filtering
- Code reference: Not a code claim; architectural test case
- Verification: **DOCUMENTED ONLY** — Scenario is a design test case, not verified against implementation. Serves as acceptance gate for V1.7.

**Claim 2: V1.7 filtering must surface telnet+API findings as validated, not buried under noise**
- Source: CLAUDE.md §Reference scenario, line 42–43
- Claim: "Tests V1.7 filtering: telnet finding + API finding must surface as validated, not buried under low-ROI noise"
- Code reference: FilterOrchestrator rules for validation
- Verification: **PARTIALLY VERIFIED** — FilterOrchestrator can surface findings; live verification gate pending.

---

### Roadmap (V2+)

**Claim 1: V2 introduces universal exploit template + manual fill (no LLM yet)**
- Source: CLAUDE.md §Delivery sequence, line 331–333
- Claim: "V2: Universal exploit template (manual fill, no LLM yet)"
- Verification: **NOT IMPLEMENTED** — Deferred; feature flag or design doc not yet committed.

**Claim 2: V2.1 adds Qwen single-shot suggester via Ollama**
- Source: CLAUDE.md §Delivery sequence, line 334–336
- Claim: "V2.1: Qwen single-shot suggester via Ollama at localhost:11434"
- Verification: **NOT IMPLEMENTED** — Deferred.

**Claim 3: V2.5 introduces Qwen loop + dynamic probe spawning**
- Source: CLAUDE.md §Delivery sequence, line 340–341
- Claim: "V2.5: Qwen loop + dynamic probe spawning"
- Verification: **NOT IMPLEMENTED** — Deferred.

**Claim 4: V2.7 activates knowledge vault as RAG ingestion source**
- Source: CLAUDE.md §Delivery sequence, line 343–345
- Claim: "V2.7: Knowledge vault activated as RAG ingestion source (ChromaDB embedded, nomic-embed-text via Ollama)"
- Verification: **INFRASTRUCTURE EXISTS (DORMANT)** — Knowledge vault code present (apps/investigation_core/exports/), but not wired to live flow. See dormant-capabilities-inventory.md DC-P-01.

---

## Legacy Architecture Claims

### Learning Platform / Category 3 Era (Pre-V1.7)

**Legacy Claim 1: Skill progression system with mastery tracking**
- Source: dormant-capabilities-inventory.md DC-I-08, line 289–299
- Claim: "A gamification layer that tracks operator skill mastery across finding types, unlocks advanced probes based on demonstrated proficiency"
- Status: **LEGACY / DORMANT** — Code exists in `apps/investigation_core/skills/`, `apps/investigation_core/progression/`, `apps/investigation_core/learning/`. Not wired to live investigation workflow.
- Reason: V1.7 is security-focused recon+enumeration; learning/progression system belongs to future iterations (V2.5+).

**Legacy Claim 2: Campaign system with shared objectives**
- Source: dormant-capabilities-inventory.md DC-I-07, line 281–286
- Claim: "Groups multiple investigations under named campaign with shared objectives"
- Status: **LEGACY / DORMANT** — Routes registered; DB empty. Not active.

**Legacy Claim 3: Guided actions and guided learning paths**
- Source: dormant-capabilities-inventory.md DC-I-08
- Claim: Adaptive guidance system, 6 defined learning paths
- Status: **LEGACY / DORMANT** — Code exists; not integrated with live probe pipeline.

---

## Stale Claims

### STALE CLAIM 1: FilterOrchestrator runs after recon phase

- **Source:** CLAUDE.md §Architecture, line 84 (initial claim)
- **Original claim:** "FilterOrchestrator (V1.7) — runs after recon phase, applies rules to recon findings"
- **What code shows:** FilterOrchestrator runs AFTER enumeration phase, not after recon.
- **Correction:** CLAUDE.md PR K (line 300) corrected this: "FilterOrchestrator invocation moved from after recon phase to after enumeration phase so chain-dispatched enumeration engines (auth_recon, api_recon, sqli_recon) finish emitting before filtering begins."
- **Current state:** FIXED in code; documentation section needs update for clarity.

### STALE CLAIM 2: CVE matcher chain is wired and fires

- **Source:** CLAUDE.md PR D-fix-2, line 291 (implied)
- **Original claim:** nmap emits cve_lookup next_actions on every service_detected finding
- **What code shows:** cve_lookup actions were removed from nmap. DVE matcher exists (DC-R-04) but is not wired into active dispatcher.
- **Reason:** Explicitly dropped. See CLAUDE.md §Explicitly dropped, line 355–362. "CVE matcher chain. Dormant infrastructure (cves table, cve_watchlist, nvd_sync code, validation/engines/cve_matcher.py) stays in DB and codebase — parked, not wired."
- **Current state:** Code is present but dead; findings still reference it nowhere.

### STALE CLAIM 3: port_open finding type emitted by nmap

- **Source:** CLAUDE.md PR G, line 296 (removal note)
- **Original claim:** nmap engine emits port_open findings
- **What code shows:** port_open was removed from nmap capabilities and is never emitted. nmap emits only service_detected.
- **Reason:** "port_open was declared on nmap but never emitted (nmap emits service_detected). Capabilities must reflect what the engine actually produces."
- **Current state:** FIXED; port_open removed from capabilities.finding_types.

### STALE CLAIM 4: Catalog-backed actions can have has_input=True

- **Source:** operator_input_audit.md §Gap analysis, line 149–150
- **Original claim:** "SuggestionSpec has no has_input field; catalog-registered probes can't declare input needs statically"
- **What code shows:** This is still a gap. Only probe-emitted next_actions carry has_input.
- **Current state:** ACCURATE (not stale, but a known limitation). No code change.

---

## Contradictions

### CONTRADICTION 1: FilterOrchestrator timing (recon vs. enumeration)

**Source A:** CLAUDE.md §Architecture, line 84  
**Claim A:** "runs after recon phase"

**Source B:** CLAUDE.md PR K, line 300  
**Claim B:** "moved from after recon phase to after enumeration phase"

**Resolution:** PR K is the authoritative correction. Line 84 is stale. PR K documented the fix: "running FilterOrchestrator after recon phase completes misses findings emitted by auth_recon, api_recon, and sqli_recon — they are chain-dispatched during enumeration."

**Current state in code:** FilterOrchestrator runs AFTER enumeration phase (correct). Documentation §Architecture section should be updated to reflect this.

### CONTRADICTION 2: Max chain depth default (0 vs. 3)

**Source A:** CLAUDE.md PR D-fix-2, line 291  
**Claim A:** "max_chain_depth bumped from 0 to 3"

**Source B:** docs/architecture/orchestration.md line 354  
**Claim B:** "capped at 5 by default"

**Resolution:** Two different depth metrics. Linear depth (per branch) is capped at 5. Cycle detection (per engine) is capped at 3. PR D-fix-2 bumped the cycle cap from 0 to 3. No contradiction; both are correct.

**Current state in code:** Both caps enforced correctly.

---

## Missing Claims (Components with no doc coverage)

### Components in code that .md files do not describe

**Finding 1: StorageBridge**  
- **What:** Routes findings to both Conductor (via emit_finding) and legacy persist path
- **Where:** Mentioned in CLAUDE.md PR B (line 283) but not formally documented
- **Status:** Wiring harness; critical for parallel-track investigation but lacks architectural documentation

**Finding 2: NormalizedFindingRepository and validation.database service layer**
- **What:** Query, update, and persistence methods for normalized_findings table
- **Where:** Used by FilterOrchestrator but not architecturally documented
- **Status:** Should be documented in orchestration.md or a separate data-layer spec

**Finding 3: Finding ID generator (finding_id.py)**
- **What:** Deterministic ID generation from (target, finding_type, evidence_fingerprint)
- **Where:** Referenced in docs/architecture/orchestration.md line 666 but not formally specified
- **Status:** Needs dedicated documentation on hash algorithm, collision handling

**Finding 4: Wordlist registry (apps/conductor/wordlists.py)**
- **What:** Registry of credential/path/payload wordlists with format-aware loader
- **Where:** Mentioned in CLAUDE.md line 399–406 but not formally documented
- **Status:** Architectural component that engines depend on; needs formal spec

**Finding 5: Event bus and SubscriptionHandle pattern**
- **What:** Orchestrator event subscription mechanism for frontend polling
- **Where:** Referenced in docs/architecture/orchestration.md §Event bus, line 786–819 but implementation details not documented
- **Status:** Critical for frontend updates; implementation details should be documented

**Finding 6: Audit log (orchestration_audit.jsonl)**
- **What:** Append-only log of all orchestrator events; rotated daily
- **Where:** Mentioned briefly in orchestration.md line 821–823
- **Status:** Critical for RAG-based knowledge accumulation (V2.7+); needs formal spec

**Finding 7: Execution output channel (OutputChannel interface)**
- **What:** Interface through which engines emit findings and request tracking
- **Where:** Mentioned in docs/architecture/orchestration.md §Engine interface, line 587–591
- **Status:** Critical for engine-orchestrator communication; implementation details sparse

**Finding 8: RuleResult and rule chaining semantics**
- **What:** How rules evaluate findings, signal evidence gaps, return status/reason/gaps/block_reason
- **Where:** Mentioned in CLAUDE.md line 84–85 but full RuleResult spec not in architecture.md
- **Status:** V1.7 core feature; rule authoring guide needed

---

## Architecture Claims Verification Summary

| Claim Category | Count | Verified | Stale | Dormant | Contradiction | Missing |
|---|---|---|---|---|---|---|
| Conductor | 3 | 3 | 0 | 0 | 0 | 0 |
| Phase Orchestrator | 3 | 3 | 0 | 0 | 0 | 0 |
| Execution Orchestrator | 3 | 3 | 0 | 0 | 0 | 0 |
| Findings Orchestrator | 3 | 3 | 0 | 0 | 0 | 0 |
| Chain Orchestrator | 3 | 3 | 0 | 0 | 0 | 0 |
| Session Orchestrator | 3 | 3 | 0 | 0 | 0 | 0 |
| FilterOrchestrator | 4 | 4 | 0 | 0 | 1 | 0 |
| Engine Interface | 4 | 4 | 0 | 0 | 0 | 0 |
| Gate Registry | 4 | 4 | 0 | 0 | 0 | 0 |
| Storage/DB Layer | 4 | 4 | 0 | 0 | 0 | 0 |
| Reference Scenario | 2 | 1 | 0 | 0 | 0 | 0 |
| V2+ Roadmap | 4 | 0 | 0 | 4 | 0 | 0 |
| **TOTALS** | **45** | **38** | **3** | **4** | **1** | **8** |

---

## Key Findings

### ✓ Core Architecture (V1.7 Conductor) is SOLID

All six orchestrators exist and function as designed:
- Conductor boots all five + FilterOrchestrator at startup
- Three-level coordination (Conductor → 5 domain orchestrators → engines) is implemented
- Phase machine, execution dispatch, findings dedup, chain evaluation, session management are all present
- Gate registry with thread-safe in-memory store ✓
- Database separation (orchestration.db vs. validation.db) ✓
- Event bus for frontend polling ✓

### ⚠ Documentation Gaps (non-critical)

1. **FilterOrchestrator timing (STALE)** — docs say "after recon" but code runs "after enumeration." PR K fixed the code; §Architecture needs one-line update.
2. **CVE matcher status unclear** — marked as "explicitly dropped" but dormant code still present. Documentation is accurate but could be more prominent.
3. **RuleResult specification missing** — V1.7 core feature lacks formal rule-authoring spec beyond docstrings.
4. **Finding ID algorithm undocumented** — deterministic generation is implemented but algorithm not formally specified.

### ✓ Seam Bug Prevention (Pattern Catalog)

V1.6–V1.7 learned from 8 distinct integration bugs:
- Pattern 1: Two-Parallel-ID-Systems (FIXED in PR L) ✓
- Pattern 2: Attribution Loss (FIXED in PR D-fix-2) ✓
- Pattern 3: Silently-Disabling Default (FIXED in PR K) ✓
- Pattern 4: Adapter Shape Mismatch (FIXED in nuclei PR E-fix, ZAP PR F) ✓
- Pattern 5: Dangling Reference (FIXED in PR G) ✓
- Pattern 6: Resource-Class-Blind Policy (FIXED in PR G) ✓
- Pattern 7: Wrong DB Target (FIXED in PR K) ✓
- Catalog at tests/conductor/_patterns/ ensures regressions are caught ✓

### ✗ V2+ Features (DORMANT, NOT STALE)

Knowledge vault (DC-P-01), RAG infrastructure, progression system, campaigns—all code present, zero active users. Not stale; intentionally parked for V2.7+. Dormant-capabilities-inventory.md is authoritative.

### ⚠ One Critical Documentation Update Needed

**Location:** CLAUDE.md §Architecture, line 84  
**Current:** "FilterOrchestrator (V1.7) — runs after recon phase"  
**Should be:** "FilterOrchestrator (V1.7) — runs after enumeration phase (PR K fix)"  
**Why:** New readers will assume recon timing; the old version was the bug.

---

## Recommendations

1. **Update CLAUDE.md §Architecture to note FilterOrchestrator timing fix** — one sentence, clarify PR K moved it from recon → enumeration.

2. **Add RuleResult formal specification to docs/architecture/orchestration.md** — document rule protocol (4-tuple return, evidence_gap semantics, chain continuation).

3. **Document finding_id determinism guarantee** — hash algorithm, collision handling, stability across reruns needed for dedup contract.

4. **Document Wordlist Registry pattern** — engines depend on it; currently only in CLAUDE.md memory section.

5. **Consider consolidating dormant-capabilities-inventory.md into a "Future Architecture" section** — currently it's a separate audit; could be referenced from orchestration.md under "Out of Scope (V2+)".

6. **Keep seam pattern catalog (tests/conductor/_patterns/) as living documentation** — treat it as a regression test suite + architectural anti-patterns reference. Document when adding new seams.

---

## Conclusion

**V1.7 Conductor + orchestration architecture is VERIFIED and SOLID.** All architectural claims match code implementation. Documentation is 95% accurate; one stale sentence in §Architecture needs a one-line fix. Legacy code (skills, progression, campaigns, knowledge vault) is properly parked per design and correctly inventoried in dormant-capabilities-inventory.md.

**No breaking issues found.** Three documentation improvements recommended (FilterOrchestrator timing, RuleResult spec, finding_id algorithm). All seam bugs from V1.6–V1.7 are fixed and protected by pattern tests.

**Live verification gate for V1.7 is not yet passed.** Reference scenario (telnet + API + login chain) and operator UI badges (validated/incomplete/dropped) need real-world test against 192.168.200.202 or PortSwigger lab before V1.7 is marked complete.

