# CLAUDE.md

Security investigation workbench. FastAPI + Jinja + htmx + Preact + React Flow.
Operator profile: IT specialist running a data center. No git. Operator accepts catastrophic-loss risk.

---

## Always read first

Before any PR or diagnostic work, read these canonical docs:

- `/docs/glossary.md` — canonical terminology + code formatting conventions
- `/docs/architecture/system.md` — components, data flow, gate registry, reference scenario
- `/docs/architecture/seams.md` — cross-layer contracts + what breaks if violated
- `/docs/architecture/orchestration.md` — orchestrator-level specification (definitive)
- `/tests/conductor/_patterns/README.md` — seam bug catalog (23 patterns, each with regression test)

Audit reports (Stage 1A/1B, 2026-05-25): `/docs/_audit_md/`

---

## Operational rules

1. Before using any domain term in prompts or code, consult `/docs/glossary.md`. If the term is absent, ask operator before proceeding.
2. Before declaring a fix complete, check `/tests/conductor/_patterns/README.md` for a matching pattern. If the bug matches a new pattern, add `test_seam_*.py` to the catalog.
3. Live verification gates are operator-driven. Do not skip, simulate, or claim verification on operator's behalf.
4. Reconstruction must use verifiable sources: file mtimes, transcripts at `/mnt/transcripts/`, grep output, build logs. Session memory is not a valid source.
5. When sources conflict: code wins over docs, docs win over session memory.
6. When operator uses a non-canonical term, map to canonical via `/docs/glossary.md` and confirm before proceeding.
7. For PR prompts: reference canonical docs by path rather than restating content. Target prompt length 50–150 lines.
8. After any session involving subagents or broad file writes, verify the 4 build files (deployment/docker/Dockerfile, docker-compose.yml, pyproject.toml, core/api/app.py) have not been silently replaced — compare against `/files/` backups before running docker compose build.
9. `/files/` directory is the canonical protected backup. Never delete or modify `/files/Dockerfile`, `/files/docker-compose.yml`, `/files/pyproject.toml`, `/files/app.py` without operator direction.
10. When unsure, ask operator. Do not guess to fill gaps.
11. When CLAUDE.md grows past 250 lines, split PR delivery history to `/docs/history/` before continuing other work.
12. To resolve a flagged unknown artifact (Zone B / "process unknown `<id>`"): read `/docs/unknown-resolution-playbook.md` before authoring any vault concept or engine. The playbook is the single source of truth for the operator command flow, authoring procedure, invariants, and worked example.

---

## Project

Transcripts: `/mnt/transcripts/`
Active DB: `/app/data/validation.db` (findings) and `data/orchestration.db` (investigation state)
Entrypoint: `core/api/app.py` → `apps/investigation_workspace/bootstrap/runtime.py`

---

## Current status

**V2.2 FULLY CLOSED. V2.3 ACTIVE.**

V2.2 delivered: 9 exploitation engines (8 probe-replacement + 1 net-new MetasploitRecipeEngine), api_discovery.py + msf_service_map.py substrates, OutputChannel.store_auth() seam, Pattern catalog 15–17, Playwright milestone gate infrastructure, conductor state machine fix (EXPLOIT_RUNNING state now set in _run_phases), V2.2 closeout docs.

**V2.2 LIVE VERIFICATION GATE CLOSED (2026-05-27):** Operator-driven verification against PortSwigger lab confirmed phase progression (Recon → Enum → Exploitation end-to-end), enumeration findings populated (API surface, login form, login endpoint), multiple engines executed (api_browser_recon, api_method_enum, api_endpoint_enum, api_authed_recon, api_full_discovery, purchase_flow legacy probe), Layer 3 artifact rendering with execution status persistence confirmed. Defects B/C (frontend filter pass-through) and MetasploitRecipeEngine (requires msfrpcd) deferred; substrate confirmed working. Full closure notes in `/docs/history/pr-delivery-history.md`.

---

## Active delivery sequence

**V1.7 closeout (after live verification):**
- [ ] Run investigation, confirm validated/dropped/incomplete/pending mix in UI
- [ ] V1.7 comprehensive audit: `docs/audits/v1.7-enumeration-output-inventory.md`

**Block C cleanup — COMPLETE.** See `/docs/_cleanup/block-c-closeout.md`.

**V2.1 — COMPLETE.** EXPLOITATION phase, investigation-scoped auth, branch state, utility modules, phase UI, Pattern catalog 9–14, verification infrastructure.

**V2.2 — COMPLETE.** All 9 engine lifts + 2 substrates + consolidated cleanup + Playwright milestone gate. See `/docs/history/pr-delivery-history.md` for full step-by-step record.
- [x] XssReflectedEngine — probe_csp_xss_reflected retired
- [x] CredentialBruteEngine — probe_brute_force_login retired; Pattern 15
- [x] CmdiReflectedEngine — probe_cmdi_reflected retired
- [x] CmdiBlindTimeEngine — probe_cmdi_blind_time retired; 3 correctness invariants
- [x] CmdiBlindBooleanEngine — probe_cmdi_blind_boolean retired; strategy-switch preserved
- [x] SqliAuthBypassEngine — probe_sqli_auth_bypass retired; bookmarklet at Layer 3
- [x] DefaultCredsEngine — probe_api_default_creds_auth retired; Pattern 16
- [x] api_discovery.py substrate — D5=Option B; 39 unit tests
- [x] AccessControlEngine — probe_api_exploit + probe_api_idor_mutate both retired (D4 revised)
- [x] MetasploitRecipeEngine — net-new; Pattern 17; resource_cost=heavy
- [x] V2.2 consolidated bug-fix — probe_api_idor_mutate fully dropped; dead docstrings cleaned
- [x] V2.2 closeout Playwright milestone gate — static tests pass; browser tests skip cleanly in WSL2

**V2.3 — COMPLETE (pending live verification).** Three-level mindmap (`exploitation-mindmap.js`), right-side panel (Pattern 19 / Seam 22), branch state polling (`/exploitation-data.json`). 683 passing, 25 skipped. Milestone gate: 7 static tests pass, 3 browser scenarios skip cleanly in bare WSL2.
**V2.3 REGRESSION FIX — APPLIED.** R2: `RF.default` undefined in UMD bundle → `RF.ReactFlow || RF.default || RF` (line 416). R3 first-pass fix: poll before render (structurally unsound — fetch always resolves after render regardless of call order). Tests 7–8 added.
**V2.3 CONSOLIDATED FIX — APPLIED.** R3-Bug1 (async race): server-side pre-seed — `BranchReader` called at render time in `investigations.py`; branch state serialized into `<script id="ws-exploitation-initial-data">` tag; read synchronously before `_buildGraph()` in `mountExploitationMindmap`. R3-Bug2 (V1 probe persistence): documented limitation — V1 probes write to in-memory `_RUNS` only; Steps 3+7 of checklist updated. Dagre CDN replaced with `/static/vendor/dagre.min.js` (operator must place dagre@0.8.5 there). Silent Execute `.catch` fixed with visible error signal. Arm state persisted in module-level `_armedNodes` dict across tab switches. Tests 9–12 added (preseed tag, preseed-before-build, no CDN, no silent catch). **Operator action required:** place `dagre@0.8.5` at `frontend/static/vendor/dagre.min.js`.
**V2.3 FINDING-TYPE RENAME — APPLIED.** `verbose_banner_disclosed` → `server_version_leaked`; `stack_trace_disclosed` → `stack_trace_leaked`; nmap `service_exposure` (http/https) → `http_service_detected`, (other) → `service_banner_disclosed`; `open_port` → `open_port_detected`. 7 downstream files updated atomically. Pattern 20 seam test (`test_seam_finding_type_registry.py`) added. Total: 698 passing, 28 skipped.
**V2.3 ENGINE TOPOLOGY REGISTRATION — APPLIED.** 4 fixes atomic: (1) `SuggestionSpec.engine_id` field added; 9 V2 engine SuggestionSpec entries wired into SUGGESTIONS catalog; Phase 2 gate (`topology_v2.py:631`) updated to pass engine_id specs; V2 engine dispatch branch in execute_suggestion route. (2) `cmdi_reflect` → `cmdi_reflected` rename (engine_id, logger, log messages, test suite). (3) XssReflectedEngine registered under all 3 trigger finding_types. (4) MetasploitRecipeEngine SQL query updated `service_detected` → `service_banner_disclosed`/`open_port_detected`. V2 exploitation engines added to `engines/__init__.py` (bootstrap gap). Pattern 21 seam test (`test_seam_v2_engine_topology_registration.py`) added. Seam 23 added. Total: 701 passing, 28 skipped.
**V2.3 CONDUCTOR–WORKSPACE ID ALIGNMENT — APPLIED.** Root cause of permanent 409 on every V2 engine Execute: `conductor.start_investigation()` generated its own UUID (`str(uuid4())`); `runtime.py` never passed workspace `run.investigation_id`; `_active` keyed by conductor UUID; `get_context(workspace_uuid)` always returned None. Fix: added optional `investigation_id` param to `start_investigation()` (`conductor.py:173`); `runtime.py:284` now passes `investigation_id=run.investigation_id`. Pattern 22 seam test (`test_seam_conductor_workspace_id_alignment.py`); Seam 24 added. Total: 720 passing, 24 skipped.
**V2.3 GHOST EXECUTE FIX — APPLIED.** Both Execute fetch `.then()` handlers (critical and non-critical path) now accept `resp` parameter and check `resp.ok` before `setLocalExec(true)`. On 4xx/5xx: shows error badge, does not fire localExec or poll. `_kickPoll()` order preserved: resp.ok → setLocalExec → _kickPoll. Critical path `.catch()` now also calls `setExecError()`. Tests 13–14 added to `test_v23_surfaces.py` (resp.ok guard, _kickPoll order). Diagnostic tests: `test_credential_brute_state_persistence.py` (8 backend, Docker-only), `test_credential_brute_state_badges.py` (7 static), `test_credential_brute_e2e.py` (milestone skip). Total: 718 passing, 29 skipped.
**V2.3 LIVE VERIFICATION GATE: OPEN (third pass).** Checklist at `/docs/testing/v2-3-closeout-live-verification.md`. Prerequisites: dagre vendor file in place. Use V2 engine nodes only (Steps 3+7) — V1 probes do not write to exploitation_branches. V2.3 closes when Steps 0–6 pass + 2 engines verified.
**V2.4 STEP 1 — APPLIED.** 6 V1 probe specs removed from SUGGESTIONS catalog (`api_browser_recon`, `api_method_enum`, `api_endpoint_enum`, `api_authed_recon`, `api_full_discovery`, `purchase_flow`); non-exploitable finding filter added at topology layer (`_has_v2_engine` in `topology_v2._emit_ghost_actions` Phase 2); Pattern 23 seam test (`test_seam_v1_probe_retirement.py`, 4 tests). Total: 724 passing, 24 skipped.
**V2.4 (CONTINUING — pending V2.3 live verification gate):** Suggestion layer routing retirement, ghost node cleanup, Defects B/C frontend filter fix, final canonical doc reconciliation.
**V2.5 STEP 1 — COMPLETE.** Qwen connectivity foundation: `apps/conductor/qwen/client.py` (ping/chat/error types), `GET /admin/qwen/ping` live, OLLAMA_BASE_URL=http://172.29.32.175:11434 confirmed reachable from container, model=qwen2.5:7b. 3 tests on host.
**[V2.4 ENTRY — all 10 required, operator confirms after V2.3 live verification gate passes]**
1. All V2.3 substantive work complete (Steps 1–4: substrate defects, exploitation-data.json endpoint, three-level mindmap)
2. V2.3 milestone gate passed: Playwright scenarios + operator-driven live verification checklist Steps 0–6
3. Pattern catalog at 21; Pattern 18 (BranchWriter wiring) + Pattern 19 (panel data source) + Pattern 20 (finding-type registry) + Pattern 21 (engine topology registration) added
4. `BranchWriter` wired in production; `exploitation_branches` written live across all 9 engines
5. `SqliAuthBypassEngine` writes captured session via `output_channel.store_auth()` — cross-engine auth flow functional
6. Seam 16 stub keys (`extended_payloads`, `extended_wordlists`) on all 9 engine `run()` signatures; `test_seam_v2_reinvocation_hook.py` in pattern catalog
7. `/exploitation-data.json` endpoint live; mindmap + panel consume it exclusively (Pattern 19 / Seam 22)
8. Three-level mindmap operational: Layer 1 arm/execute, Layer 2 running, Layer 3 artifact/exhaustion
9. `exploit-tree.js` retired in favor of `exploitation-mindmap.js`; workspace.js updated
10. V2.4 scope confirmed: suggestion layer routing retirement, ghost node cleanup, Defects B/C frontend filter fix, final canonical doc reconciliation
**V2.5 — COMPLETE.** Qwen loop + dynamic probe spawning; operator-provided knowledge on demand. Step 1: client + ping. Step 2: technique selection. Step 3: persistent chat panel. Step 4: AI branch spawning + 4B: extended payloads (mass assignment), ai_probe synthetic findings, access_control custom payload execution, Seam 17 wired. Milestone gate: test_v25_milestone.py 4 static pass, 2 browser skip. Live verification checklist at `/docs/testing/v2-5-closeout-live-verification.md`. PortSwigger mass assignment lab solved end-to-end (credential_brute captured session wiener:peter; chosen_discount.percentage=100 exploitation confirmed; lab marked is-solved).
**V2.6 STEP 1 — APPLIED.** API context enrichment for Qwen: `_fetch_openapi_schema()` + `_fetch_product_catalog()` helpers in `context_builder.py`; 5s timeout, verify=False, never raise; three new context sections (API Schema, Product catalog, Discovered endpoints); session cookies sourced from `exploitation_branches` artifact where `artifact_type='captured_session'`; graceful degradation — all fetches fail → Qwen still responds. 8 new tests in `test_qwen_context_enrichment.py`; `test_ai_probe_label_uses_finding_title` added to `test_v25_surfaces.py`; V2.5 milestone test file at `tests/milestone/test_v25_milestone.py` (4 static, 2 browser skip).
**[V2.6 ENTRY — all 10 required, operator confirms after V2.5 live verification gate passes]**
1. V2.5 complete: Qwen chat panel, ACTION block, approval card, ai_probe, authenticated session
2. API context enrichment live: Qwen sees openapi.json schema + product catalog
3. access_control custom payloads use correct finding_id (Bug 1 fixed)
4. Session pipe bridged: target-URL-keyed auth read correctly (Bug 2 fixed)
5. ai_probe mindmap rendering: finding+action nodes appear in exploit_tree
6. Milestone gate: test_v25_milestone.py 4 static pass, 2 browser skip
7. Live verification gate: operator checklist Steps 0-8 complete
8. Pattern catalog at 23; no new patterns required for V2.5
9. Context enrichment graceful degradation: all fetches fail → Qwen still responds
10. V2.6 scope confirmed: knowledge vault activation, V2.7 prep
**V2.7+V2.8 — COMPLETE.** Knowledge vault write pipeline (vault_writer.py: export_finding, export_lab_walkthrough, sequential IDs, MITRE/OWASP tag mapping); read pipeline (context_builder.py: _search_vault_by_tags, semantic search via vault_embedder.py with ChromaDB+TF-IDF fallback); docker-compose.yml vault mount (/home/unctad/projects/knowledge-vault → /app/knowledge-vault:rw); OutputChannel._last_artifact capture; execution.py wired asyncio.create_task export on success. Tag search live: past exploits injected into Qwen context. Write pipeline live: new findings written to vault and visible in Obsidian.
**V2.9 STEP 1 — COMPLETE.** Embedding-based engine recommendation: `concept_matcher.py` (BM25 primary on `concepts/` only, ChromaDB+nomic-embed-text when indexed); `technique_selector.py` fast-path — high-confidence (≥0.7) bypasses Foundation-Sec; vault_embedder near-dedup guard (dist<0.05), title+tags metadata, rebuild_index uses frontmatter `id` (preserves CONCEPT- prefix), `concepts/` in scan dirs; `POST /admin/vault/rebuild` + Rebuild Vault Index button in settings UI. 7 tests (6 pass). Live: login_form_detected→credential_brute, api_exposure→access_control.
**V2.9 TRACK A — COMPLETE.** JS endpoint discovery: `JSSpiderEngine` (`apps/conductor/engines/js_spider_engine.py`) — authenticated crawl, parses `fetch()`/XHR/axios/`$.ajax` in script files, emits `api_endpoint_discovered` findings; auto-dispatches after `credential_brute` succeeds; `api_endpoint_discovered` binding in topology + SUGGESTIONS catalog → `access_control` ghost nodes appear; `concept-js-spider.md` added to vault (now 40 entries). 9 tests passing. Root-cause fix for `/user/lookup` blindspot from NoSQL rookie run.
**V2.9 TRACK B — COMPLETE.** (1) Streaming SSE: `POST /qwen/chat/stream` returns `text/event-stream` with token/action/done events; `_chatSend()` tries ReadableStream fetch first, falls back to POST. (2) Reranker: `rerank_results()` in vault_embedder.py — retrieve 10 candidates, cross-encoder score via qwen3-reranker if available, fall back to embedding order; `qwen3-reranker:0.6B` not yet in Ollama registry — fallback active. (3) Failure feedback: `OutputChannel._last_exhaustion` captured on `emit_stage("exhausted")`; `vault_writer.export_failure()` writes FAIL-WEB-*.md; auto-fires in execution.py after non-success run. (4) Vault enrichment: Common Form Fields appended to 4 concept files; `concept-iteration-strategy.md` + `concept-js-spider.md` added; vault rebuilt to 41 entries. 11 tests passing, 1 skipped.
**V2.9 CONTINUING:** Knowledge vault curation UI (Step 2).
**V3:** Manual prompt refinement cadence.

**Explicitly dropped (do not implement):**
- CVE matcher chain — infrastructure parked in codebase, not wired, recoverable
- ZAP active scan — exploitation-phase work, deferred to V2
- AJAX spider — deferred until regular spider proves insufficient
- Catalog mapping (finding_type → exploit category) — deferred until exploitation phase design locked
- Tag-based filtering in nuclei — deferred until severity filtering proves insufficient

---

## Locked decisions

- Reference scenario: telnet (port 23, unusual write technique) + HTTP login `/api/login` chain
- Three-level orchestration: Conductor L3 → 5 domain orchestrators L2 → stateless engines L1. No fourth level without operator approval.
- Operator drives car; never sees engine names in UI
- Session inheritance from `_API_AUTH_STORE` non-negotiable — engines never re-authenticate
- No lab-specific code, ever
- Rules as Python code in `apps/conductor/rules/` (not YAML)
- Dropped findings retained in DB — not deleted; audit trail for filter behavior debugging
- `core/` and `sdk/` cleanup deferred — load-bearing until `sdk.Logger` replaced across all consumers
- Knowledge vault dormant code must NOT be deleted — planned V2.7 ingestion target (`apps/investigation_core/exports/`, `exporters/`)
- Enumeration gap surfacing is informational, not corrective — operator decides whether to enrich recon engines
- [INVARIANT] FilterOrchestrator runs after enumeration phase (NOT recon) — chain-dispatched findings arrive during enumeration
- Seam tests added before shipping V2 seams, not after the first bug surfaces
- Legacy investigation workspace (`investigation_workspace/api/routes.py` + 19 ACTIVE-LEGACY backend modules) is the real cleanup target. Deferred to "Legacy Workspace Deprecation Sprint" — likely V2.5+ scope. Do NOT attempt incidental deletion during V2 work. See `/docs/_cleanup/block-c-closeout.md`.
- ACTIVE-LEGACY classification: old code with live route callers. Distinct from VESTIGE (zero callers) and DORMANT_V2 (planned activation). Requires redirect PR before any deletion.
- [V2] V2 = EXPLOITATION phase activated in `PhaseOrchestrator._PHASE_SEQUENCE`. Continuation of the recon→enum pipeline; not a parallel system. Design doc: `/docs/architecture/exploitation.md`.
- [V2] Per-technique templates, not one universal form. Each technique class has its own engine with its own `template_spec`.
- [V2] Three-level mindmap only: Layer 1 (arm/execute), Layer 2 (running), Layer 3 (artifact or exhaustion record). No node deeper than Layer 3.
- [V2] Right-side panel is the per-node detail surface including artifacts inline at Layer 3. No separate artifact registry in V2.
- [V2] Branch state persists in `validation.db` (`exploitation_branches` table) until operator deletes the investigation. Reconstructs across restarts.
- [V2] Single investigation-scoped `SessionOrchestrator` per investigation, owned by `_InvestigationContext`. No process-level store on `Conductor`. Operator-driven refresh only (via `POST /admin/session-auth/refresh`). The module-level `_API_AUTH_STORE` was retired in V2.1 Step 2; the process-level `Conductor.session_orch` was retired in V2.1 Step 2b. ACTIVE-LEGACY probes access the investigation-scoped store via `INVESTIGATION_ID_CTX` set in `_runner_from_probe` — `store_target_auth(base, auth)` / `get_target_auth(base)`. Expired state surfaced in admin conductor panel (collected across active investigations). No automatic re-auth.
- [V2] Engine structure: standalone Python files in `apps/conductor/engines/`, shared utility modules (`exploit_payloads.py`, `exploit_detection.py`, `exploit_approval.py`, `exploit_exhaustion.py`, `exploit_artifacts.py`). No ABC inheritance framework. No meta-engine.
- [V2] No gating during engine migration. Engine replaces probe atomically per PR; probe is retired in the same PR. Outcome verification (mock + live lab) is the safety mechanism. No `EXPLOITATION_PARALLEL_TRACK` flag. (Clarification C4: arm gate is engine-layer only; route-layer `?confirm=` gate for that `action_kind` is deleted in the same PR — the two never coexist. Clarification C3: EXPLOITATION phase completion is operator-driven — no auto-complete, no quiescence detection; phase can be re-entered after operator marks done. Clarification C6: exploitation engines carry NO system-level gate_id — per-action Arm→Execute flow is the operator control at the correct granularity; recon/enum gates remain. `xss_reflected_exploit` gate retroactively removed from gates.py. Future engine lifts must not add gate entries. See exploitation.md §15 C6.)
- [V2] V2 ships pipes for V2.1+ consumers: session pipe (active, merged V2.1 Step 2), `ExhaustionRecord` schema (locked, Seam 14), re-invocation hook (stubbed, Seam 16), feedback hook (stubbed, Seam 17), RAG injection point (no-op, Seam 18), vault-ingestion-ready branch shape. `OutputChannel.emit_stage()` shipped in V2.1 Step 1 (Pattern 9 seam test at `tests/conductor/_patterns/test_seam_output_channel_stage.py`).
- [V2] Exploitation engine count bounded to ~8 (see `/docs/architecture/exploitation.md` §7). New engines require explicit operator approval — must be a new technique class, not a per-lab variant. (Clarification C1: `probe_api_full_discovery`, `probe_api_endpoint_enum`, `probe_api_browser_recon`, `probe_api_authed_recon` lift as ENUMERATION engines in V2.2 — they execute in the enumeration phase; the Exploitation tab displays them as "Execute →" cards via UI grouping logic only. Phase ≠ tab. Clarification C5: no post-exploitation classification orchestrator — engine emission at Layer 3 IS the classification; `EXPLOIT_COMPLETE → COMPLETED` transition has no intermediate step.)
- [V2.2 ENTRY — all 9 met, operator-approved 2026-05-26] (1) EXPLOITATION phase active and operator-driven; (2) single investigation-scoped SessionOrchestrator, auth via INVESTIGATION_ID_CTX; (3) branch state persists in exploitation_branches; (4) utility modules at apps/conductor/exploitation/; (5) OutputChannel.emit_stage() live (Pattern 9 seam test); (6) phase badges track Conductor state (Pattern 13); (7) verification infrastructure in place (mocks + frontend smoke + Playwright harness); (8) Pattern catalog 9–14 all passing; (9) atomic probe retirement enforced per engine PR (Pattern 12). Do not start next V2.2 engine PR until live verification gate passed.
- [V2.3 ENTRY — all 12 met, operator-approved 2026-05-27] (1) All suggestion-layer exploitation probes retired; engines cover their probe-equivalent outcomes. (2) Pattern catalog at 17, covering all V2.1 and V2.2 seams. (3) Verification stack operational: backend mocks + frontend smoke + milestone Playwright + operator-driven live checklist. (4) EXPLOITATION phase active and operator-driven completion working (POST /admin/exploitation/complete). (5) Per-action Arm→Execute flow is the only operator control mechanism (C6 locked). (6) Single investigation-scoped SessionOrchestrator; auth state flows through INVESTIGATION_ID_CTX. (7) OutputChannel.store_auth() seam established (Pattern 16). (8) Branch state persists in validation.db; bookmarklet artifact preserved at Layer 3. (9) Engine count is 9 (8 probe-replacement + 1 net-new MetasploitRecipeEngine); engine-count bound respected. (10) Shared utility modules at apps/conductor/exploitation/. (11) Live verification milestone gate passed (operator-driven checklist at docs/testing/v2-2-closeout-live-verification.md complete). (12) Playwright milestone scenarios passing against the full engine set (static scenarios pass; browser scenarios require Docker — skip cleanly in bare WSL2). Do not begin V2.3 graph wiring until live verification gate passed and operator confirms start.
- [V2] Frontend smoke tests added to the per-PR mock system. Three categories, structural only, no JS execution: (a) Rendered HTML assertions — Jinja templates rendered with mock state; HTML output parsed and asserted on structural properties (elements present, badge text, data attributes). (b) JSON endpoint shape assertions — API endpoints called with mock state; JSON response asserted on field presence and shape. (c) Static asset reference checks — JS source files read as text; grep for forbidden references (e.g., retired identifiers after atomic retirements). Runs per-PR alongside existing backend mock tests. Catches backend-shaped UI defects (the class V2.1 hit repeatedly). Does not catch JS logic bugs (Playwright scope).
- [V2] Playwright at milestone closeout gates only: V2.2 closeout (all engine lifts complete), V2.3 closeout (graph wiring + handover verification complete), V2.4 closeout (suggestion layer retirement complete), and equivalent major sub-phase boundaries. Real browser, real JS execution. Catches JS logic bugs (event wiring, filter logic, DOM rendering, race conditions) before operator-driven live verification. Not used per-PR. Not used for individual engine lifts. Operator-driven live verification continues at each engine lift gate per the V2 phase plan.

---

## Hard-learned lessons

Condensed; full detail in seams.md and `tests/conductor/_patterns/README.md`.

- Audits underestimate scope ~3x consistently.
- Big PRs hide regressions (V1.4a → 13 regressions). Bounded PRs with live verification between each.
- Static "PASS" reports diverge from operator reality. Live verification > static checks.
- Architecture-first prevents engine explosion. Wire nothing until Conductor + orchestrators are in place.
- Documentation-first prevents context loss across Claude Code restarts. Every PR updates relevant `.md` files.
- The inherited stack (nmap, nuclei, ZAP, validation plugins, CVE matcher, knowledge vault) is inherited — activate, do not duplicate. Metasploit RPC routes and operator UI are live; the container must be started separately.
- Aggregation whitelist gap surfaces silently. Add catch-all card for any unhandled `finding_type`; do not rely on the whitelist being exhaustive.
- Security controls should fail-closed. Unknown `gate_id` → engine BLOCKED at startup, with explicit logging.
- `FindingEvent` schema must carry producer identity. New engines require a downstream-write audit for `probe_id` / `source_scanner`.
- Default values in production wiring are not always safe. `max_chain_depth=0` silently disabled Chain Orchestrator entirely.
- Adapters drift silently from the tool they wrap. Check exit code. Validate CLI flags whenever tool version changes (nuclei v2→v3: `-json` removed, use `-jsonl-export`).
- Partial adapter rewrites miss response parsing. ZAP spider returned int count; new function returns URL list.
- Dead next_actions pollute. When dropping a chain, also remove its `next_action` emissions and stale `capabilities.finding_types`.
- Watchdog must account for `resource_cost`. Heavy engines (nmap, nuclei, ZAP) get 600s; light/medium get 30s.
- Gap surfacing is informational, not corrective. System surfaces gaps; operator decides whether to enrich recon engines.
- Build config files silently replaced twice (2026-05-25). `/files/` is the canonical protected backup; compare mtimes before `docker compose build`.
- Version pin widening during reconstruction broke the frontend (FastAPI `<1.0.0` → starlette 1.1.0 → `TemplateResponse` API change). Pins in this project are hard compatibility gates; copy verbatim from `/files/` backup.
- [INVARIANT] FilterOrchestrator DB writers must target `validation.db`. Closures capturing `_db_path` silently target `orchestration.db`.
- FilterOrchestrator must run after enumeration. Chain-dispatched findings (auth_recon, api_recon, sqli_recon) arrive during enumeration, not recon.
- [INVARIANT] Two-parallel-ID-systems (PR L): `finding_id` must be explicitly passed as `evt.id` to `NormalizedFinding`. The `default_factory=uuid4()` breaks all FilterOrchestrator UPDATEs silently.
- Seam bugs evade mock-based unit tests. `tests/conductor/_patterns/` is the enforcement layer. Add `test_seam_*.py` before shipping V2 seams.
- Pre-deletion grep requires two passes. Pass 1 (call-site): grep for runtime callers (function calls, class instantiations, attribute access). Pass 2 (import-time): grep for bare `import <module>` and `from <module> import` in all retained files. VESTIGE-1 passed Pass 1 but missed Pass 2 — two retained ACTIVE-LEGACY modules still imported the deleted modules at module load time; container crashed with ImportError on startup before any HTTP request could land. Both passes must clear before committing any deletion. (Pattern 14: `test_seam_import_time_reachability.py`.) Stage-2 audit separately missed `investigation_core_router` in `validation/api/__init__.py:22` — all investigation_core/* API routes are live. C2 + C3 checks caught ~5,295 lines of would-be wrongful deletions. Architecture-fit heuristics alone are not sufficient for VESTIGE classification.

---

## UI work — verification is mandatory

Full playbook: `/docs/ui-verification-playbook.md`

Any change touching a template, an HTML-rendering route, a React Flow node, a
click handler, or an htmx trigger/target MUST follow the playbook.

- **Before coding**: state the full click-to-render chain — all six links (trigger →
  event → route → condition → response → DOM target). A missing link IS the work.
  The trigger is as important as what the route returns; confirm the click fires
  a request at all before touching the route.
- **Definition of done for UI** = the playbook's Playwright protocol passes against
  the running stack (Step 0 connectivity proof first, then the real operator action
  asserted). Mock tests are necessary but NOT sufficient and never replace it.
- **On any UI bug**: attach page.on("request"/"response"/"console"), reproduce with
  Playwright, screenshot on failure, localize the broken chain link before changing code.
- **Never misdiagnose a connectivity failure** (wrong port / WSL2↔container / URL) as
  a render bug. If Step 0 fails, fix connectivity before anything else.

---

## Operator preferences

- Senior engineer voice. Direct, concise, technically accurate. Push back on weak ideas.
- Verifiable evidence over session memory.
- Parallel subagents when tasks are independent.
- Short prompts referencing canonical docs by path — do not restate architecture in prompts.
- Playwright at milestone gates only — never per-PR. Screenshots and `.md` ceremony in prompts unless asked.
- Small fix = small prompt. Don't add scope not requested.

---

## PR delivery history

Full record at `/docs/history/pr-delivery-history.md` (split from CLAUDE.md 2026-05-27 per rule 11).

Most recent entries:
- V2.7+V2.8 KNOWLEDGE VAULT INTEGRATION: vault_writer.py + vault_embedder.py; docker-compose.yml vault mount; OutputChannel._last_artifact; execution.py fire-and-forget export; context_builder.py tag+semantic vault search. Write live: FIND-WEB-20260528-001_credential_brute.md. Read live: Qwen context includes past sqli/credential exploits. 13 new tests. Total: 183 passing, 11 skipped.
- V2.6 STEP 1 API CONTEXT ENRICHMENT + V2.5 CLOSEOUT: context_builder.py _fetch_openapi_schema + _fetch_product_catalog (5s timeout, graceful degradation); test_v25_milestone.py (4 static, 2 browser skip); v2-5-closeout-live-verification.md. V2.5 marked complete. V2.6 entry conditions (10) locked. 16 new tests.
- V2.5 COMPLETE: PortSwigger mass assignment lab solved. credential_brute captured wiener:peter; chosen_discount.percentage=100 → HTTP 201 → is-solved. ai_probe synthetic findings, access_control custom payload path, authenticated session via target-URL-keyed store, ai_probe mindmap rendering via _build_exploit_tree synthesis.
- V2.5 Step 3 PERSISTENT QWEN CHAT PANEL: context_builder.py; POST /qwen/chat; #qwen-chat-panel in template; 115 lines chat JS in mindmap IIFE; context capped at top-25 findings. Live: Qwen responds in 90s timeout window.
- V2.5 Step 2 QWEN TECHNIQUE SELECTION: apps/conductor/qwen/technique_selector.py; execute route wired (5s timeout, non-blocking); recommendation stored in branch.operator_params via OutputChannel.create_branch(); mindmap panel renders recommendation with confidence colour; Seam 18 partially wired (qwen_recommendation logged at DEBUG). 5 tests pass on host.
- V2.5 Step 1 QWEN CONNECTIVITY: apps/conductor/qwen/client.py; GET /admin/qwen/ping; OLLAMA_BASE_URL=http://172.29.32.175:11434 confirmed; model=qwen2.5:7b.
- V2.4 Step 1 V1 PROBE RETIREMENT + NON-EXPLOITABLE FILTER: 6 V1 probe specs removed from SUGGESTIONS catalog; non-exploitable finding filter added at topology layer (Option A, `_has_v2_engine` in `_emit_ghost_actions` Phase 2); Pattern 23 added (`test_seam_v1_probe_retirement.py`, 4 tests). Total: 724 passing, 24 skipped.
- V2.2 Step 12 METASPLOITRECIPEENGINE (NET-NEW): Pattern 17 seam test; Seam 21; resource_cost=heavy. Total: 670 passing.
- V2.2 Step 11 CONSOLIDATED BUG-FIX: probe_api_idor_mutate fully dropped; D4 revised; dead docstrings cleaned. Total: 670 passing.
- V2.2 CLOSEOUT MILESTONE: Playwright milestone gate (tests/milestone/); conductor state machine fix; live verification checklist; exploitation.md §17 + seams.md V2.2 arc + patterns README V2.2 arc; V2.3 entry conditions (12) locked. Total: 672 passing.
- V2.2 OPERATOR LIVE VERIFICATION (CLOSED 2026-05-27): PortSwigger lab. Phase progression confirmed end-to-end. Layer 3 artifact rendering confirmed. Defects B/C + MetasploitRecipeEngine deferred. V2.2 fully closed.
- V2.3 STEP 1 PRE-IMPLEMENTATION INVENTORY: 5-subagent read-only audit; inventory at docs/audits/v2-3-graph-wiring-inventory.md. Critical gaps surfaced: BranchWriter not wired in production (emit_stage no-op), BranchReader has no route caller, test_seam_v2_reinvocation_hook.py missing (unfulfilled V2.2 commitment), SqliAuthBypassEngine missing store_auth() call. V2.3 step 2 is next.
- V2.3 STEP 2 SUBSTRATE DEFECT CLOSURE: 3 V2.2 production defects closed atomically. (1) BranchWriter wired in ExecutionOrchestrator.__init__ + _launch(); (2) SqliAuthBypassEngine store_auth() added (Pattern 16 invariant); (3) Seam 16 stub keys (extended_payloads/extended_wordlists) added to all 9 engine run() signatures. Pattern 18 seam test + Seam 16 stub test created. Total: 674 passing, 22 skipped (3 new P18 host-skips), 14 pre-existing failures (pydantic/aiosqlite missing on host).
- V2.3 STEP 3 EXPLOITATION-DATA.JSON ENDPOINT: GET /exploitation-data.json added to workspace routes; BranchReader.list_for_investigation() first production consumer; D2 resolved (state+artifact+exhaustion_record+stage_log+operator_params); empty investigation returns 200 with branches:{}; Category 3 smoke test + backend mock tests (fastapi-skip on host) + Category 2 httpx tests. Total: 675 passing, 25 skipped.
- V2.3 STEP 4 THREE-LEVEL MINDMAP: exploitation-mindmap.js (replaces exploit-tree.js); three-level React Flow tree (L1=arm/execute, L2=running progress, L3=artifact/exhaustion); right-side panel populated from cached _branchMap; Pattern 19 seam test (5 tests); 3 new Category 3 smoke tests in test_v23_surfaces.py. Seam 22 added. Total: 683 passing, 25 skipped.
- V2.3 CLOSEOUT MILESTONE: Playwright milestone scenarios (tests/milestone/test_v23_milestone.py) — 7 static pass on host, 3 browser documented-skip; mindmap page object (tests/milestone/pages/mindmap_page.py); operator checklist (docs/testing/v2-3-closeout-live-verification.md — 8 steps, Pattern 19 live check included); V2.4 entry conditions (10) locked in CLAUDE.md; exploitation.md §18 V2.3 arc; seams.md + patterns README V2.3 closeout notes; pr-delivery-history.md V2.3 closeout entry. Total: 683 passing, 25 skipped (unchanged baseline — milestone scenarios are milestone-gated).
- V2.3 CLOSEOUT CONSOLIDATED FIX: server-side pre-seed (R3-Bug1 async race eliminated structurally); V1 probe limitation documented (R3-Bug2 — V1 probes write to _RUNS only, not exploitation_branches; V2.4 scope); dagre CDN replaced with /static/vendor/dagre.min.js; silent Execute .catch fixed with visible error signal; arm state persisted in module-level _armedNodes dict. Tests 9–12 added to test_v23_surfaces.py. Checklist updated with prerequisites + V1 limitation notes. Operator action required: place dagre@0.8.5 at frontend/static/vendor/dagre.min.js.
- V2.5 Step 1 QWEN CONNECTIVITY: apps/conductor/qwen/client.py created; GET /admin/qwen/ping live; OLLAMA_BASE_URL=http://172.29.32.175:11434 confirmed; model=qwen2.5:7b; 3 tests pass on host.

---

## Restructure history

CLAUDE.md reduced from 661 lines to ~200 lines on 2026-05-25 as part of Stage 1B .md rectification.
Original at `/files/CLAUDE.md.pre-restructure.bak`. Audit reports at `/docs/_audit_md/`.
Decisions log at `/docs/_cleanup/decisions-log.md`. Archived files at `/files/_orphaned_md/`.
Nine factory-era files moved to `/files/_orphaned_md/`; one redundant audit retired.
PR delivery history split to `/docs/history/pr-delivery-history.md` on 2026-05-27 (rule 11).
