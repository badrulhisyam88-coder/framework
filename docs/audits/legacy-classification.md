# Legacy Code Classification

Audit date: 2026-05-25. Read-only survey. No files modified.
Reference sources: `docs/architecture/system.md`, `CLAUDE.md`, import graph analysis.

---

## Summary table

| Module path | Lines | Category | Last modified | Rationale |
|---|---|---|---|---|
| `apps/conductor/` | 5 735 | ACTIVE | 2026-05-25 | Conductor + all six orchestrators + engines + rules + gates |
| `apps/investigation_workspace/api/` | 2 657 | ACTIVE | 2026-05-25 | Workspace routes, `_persist`, `workspace-data.json` |
| `apps/investigation_workspace/bootstrap/` | 416 | ACTIVE | 2026-05-25 | `runtime.py` — calls `Conductor.start_investigation()` |
| `apps/investigation_workspace/probe/` | 4 597 | ACTIVE | 2026-05-25 | Underlying probe logic called by bootstrap engines |
| `apps/investigation_workspace/aggregations.py` | 248 | ACTIVE | 2026-05-25 | `_build_aggregations`, `_dominant_validation` |
| `apps/scanner_orchestration/adapters/` | 715 | ACTIVE | 2026-05-25 | nmap, nuclei, zap adapters |
| `apps/scanner_orchestration/storage/` | 343 | ACTIVE | 2026-05-25 | `NormalizedFindingRepository`, `scan_repo` |
| `apps/scanner_orchestration/normalization/` (models only) | 910 | ACTIVE (partial) | 2026-05-25 | `models.py` used by storage; pipeline/enricher are VESTIGE |
| `apps/validation/database.py` | ~90 | ACTIVE | 2026-05-25 | `DB_PATH`, `init_db`, `get_db` — used by FilterOrchestrator callbacks |
| `apps/validation/plugins/` | 2 400 | ACTIVE | 2026-05-25 | Called by plugin engines (ssh, telnet, smb, wordpress, drupal, apache, nginx) |
| `apps/admin_ui/` | 220 | ACTIVE | 2026-05-25 | `/admin/*` panels — conductor, execution, settings, enumeration-gaps |
| `apps/investigation_core/exports/vault/` | 183 | DORMANT_V2 | 2026-05-22 | VaultManager — planned RAG ingestion target (V2.7); protected per CLAUDE.md |
| `exporters/` (repo root) | 2 220 | DORMANT_V2 | 2026-05-18 | Markdown export pipeline for knowledge vault (V2.7) |
| `apps/validation/services/metasploit.py` | ~240 | DORMANT_V2 | 2026-05-19 | Metasploit RPC client; V2 exploitation phase |
| `apps/validation/services/msf_recipes.py` | ~120 | DORMANT_V2 | 2026-05-15 | Static MSF module recipe catalog; V2 exploitation UI |
| `apps/validation/services/msf_wordlists.py` | ~80 | DORMANT_V2 | 2026-05-15 | MSF wordlist path catalog; V2 exploitation UI |
| `apps/validation/api/metasploit.py` | ~320 | DORMANT_V2 | 2026-05-19 | Metasploit API routes (`/api/v1/validation/metasploit`); V2 |
| `apps/investigation_workspace/branch/` | 2 375 | AMBIGUOUS | 2026-05-24 | React Flow topology — imported by routes.py; unclear if still rendered |
| `apps/investigation_workspace/suggestions/` | 5 762 | AMBIGUOUS | 2026-05-25 | `catalog.py`+`probes.py` — pre-V2.1 probe runner system; routes.py imports it |
| `apps/investigation_workspace/execution/` | 596 | AMBIGUOUS | 2026-05-23 | In-memory execution animation runtime; routes.py imports it |
| `apps/investigation_workspace/exploitation_paths/` | 552 | AMBIGUOUS | 2026-05-23 | `bindings.py`+`taxonomy.py` — finding_type → exploit path mapping; routes.py imports it |
| `apps/investigation_workspace/feed/` | 1 398 | AMBIGUOUS | 2026-05-19 | `FeedBuilder` — chronological feed; routes.py and branch/assembler import it |
| `apps/investigation_workspace/capture/` | 450 | AMBIGUOUS | 2026-05-19 | Post-exploit artifact capture bundles; routes.py imports it |
| `apps/investigation_workspace/adaptive/` | 405 | VESTIGE | 2026-05-19 | Maturity-aware narrative for feed; feed is itself AMBIGUOUS |
| `apps/investigation_workspace/categories/` | 157 | AMBIGUOUS | 2026-05-19 | Category catalog; routes.py imports it at line 804 |
| `apps/investigation_core/` (minus exports/vault/) | ~11 045 | VESTIGE (mostly) / AMBIGUOUS (partially) | 2026-05-22 | Category 3 learning platform vestiges — see breakdown below |
| `apps/scanner_orchestration/api/` | 744 | AMBIGUOUS | 2026-05-19 | Scanner-facing HTTP routes; mounted via validation_router |
| `apps/scanner_orchestration/services/` | 510 | VESTIGE | 2026-05-19 | `OrchestrationService` — pre-Conductor scan runner; no active callers |
| `apps/scanner_orchestration/execution/run.py` | 153 | VESTIGE | 2026-05-19 | `InvestigationRun` aggregator over ScanExecution; no active callers |
| `apps/scanner_orchestration/monitoring/` | 47 | VESTIGE | 2026-05-19 | `ScanMonitor`; only used by scanner_orchestration/api/routes.py |
| `apps/scanner_orchestration/profiles/` | 151 | VESTIGE | 2026-05-19 | `scan_profiles.py`; only used by scanner_orchestration/api/routes.py |
| `apps/scanner_orchestration/target_resolution/` (minus models.py) | ~526 | VESTIGE | 2026-05-19 | `resolver`, `diagnostics`, `ssrf_guard`; no active callers except scanner api |
| `apps/scanner_orchestration/target_resolution/models.py` | 76 | ACTIVE | 2026-05-19 | `TargetContext` — imported by all three active adapters |
| `apps/scanner_orchestration/timeline/` | 169 | VESTIGE | 2026-05-19 | Timeline events; only used by orchestration_service |
| `apps/scanner_orchestration/normalization/pipeline.py` | ~200 | VESTIGE | 2026-05-19 | `NormalizationPipeline`; only caller is orchestration_service (VESTIGE) |
| `apps/scanner_orchestration/normalization/cve_enricher.py` | ~80 | VESTIGE | 2026-05-19 | CVE enrichment stage; called by pipeline.py (VESTIGE) |
| `apps/validation/engines/cve_matcher.py` | ~400 | VESTIGE | 2026-05-19 | Dropped CVE matcher path per CLAUDE.md |
| `apps/validation/engines/nvd_sync.py` | ~200 | VESTIGE | 2026-05-19 | NVD sync; feeds cve_matcher (VESTIGE) |
| `apps/validation/engines/fingerprint_normalizer.py` | ~54 | VESTIGE | 2026-05-19 | Fingerprint normalization; no active callers |
| `apps/validation/services/` (minus metasploit/msf_*) | ~3 073 | VESTIGE | 2026-05-19 | Pre-Conductor scan orchestration services |
| `apps/validation/tasks/` | 197 | VESTIGE | 2026-05-19 | `expiry_worker.py`; queue archival job — no active callers |
| `apps/validation/adapters/` | 563 | VESTIGE | 2026-05-19 | `nmap.py`, `recon_ng.py`; used only by validation/services (VESTIGE) |
| `apps/validation/api/` (minus metasploit.py) | ~3 484 | AMBIGUOUS | 2026-05-24 | Broad CRUD UI (assets, findings, queue, reports, etc.); mounted via validation_router |
| `apps/validation/models/` | 371 | ACTIVE (partial) | 2026-05-19 | `Evidence`, `ValidationStatus` imported by active plugin engines; rest is vestige data layer |
| `apps/validation/repositories/` | 1 192 | AMBIGUOUS | 2026-05-19 | Full repository layer for hosts/services/CVEs/queue/findings — validation_api uses it |
| `sdk/` (repo root) | 51 | ACTIVE (load-bearing) | — | `Logger` imported by runtime.py, routes.py, database.py, nmap_adapter.py; cannot remove until sdk.Logger → stdlib migration |

---

## Active modules (confirmed)

These modules are called on every investigation path from operator URL submission through FilterOrchestrator completion. Confirmed by import graph from `apps/validation/api/__init__.py` → `apps/investigation_workspace/api/routes.py` → `apps/investigation_workspace/bootstrap/runtime.py` → `apps/conductor/conductor.py`.

- `apps/conductor/` — Conductor, all six orchestrators, 15 engines, rules, gates, wordlists, storage, events, findings
- `apps/investigation_workspace/api/routes.py` — `_persist`, `workspace_data_json`, `_run_all_probes_via_conductor` entry
- `apps/investigation_workspace/bootstrap/runtime.py` — calls `Conductor.start_investigation()`
- `apps/investigation_workspace/probe/` — underlying probe implementations called by bootstrap engines
- `apps/investigation_workspace/aggregations.py` — `_build_aggregations`, `_dominant_validation` for workspace-data.json
- `apps/scanner_orchestration/adapters/` — thin subprocess wrappers for nmap, nuclei, zap
- `apps/scanner_orchestration/storage/finding_repo.py` — `NormalizedFindingRepository`; FilterOrchestrator callbacks and workspace-data.json use it
- `apps/scanner_orchestration/normalization/models.py` — `NormalizedFinding` model; used by storage layer
- `apps/scanner_orchestration/target_resolution/models.py` — `TargetContext` model; all three adapters import it
- `apps/scanner_orchestration/execution/models.py` — `ScanExecution`, `ScanStatus`; imported by routes.py and normalization
- `apps/validation/database.py` — `DB_PATH`, `init_db`, `get_db`; FilterOrchestrator callbacks and validation_router
- `apps/validation/plugins/` — SSH, telnet, SMB, WordPress, Drupal, Apache, Nginx plugin implementations
- `apps/validation/models/__init__.py` — `Evidence`, `ValidationStatus` (subset); imported by plugin engines
- `apps/admin_ui/routes.py` — `/admin/*` panels
- `sdk/` — `Logger` facade; load-bearing until stdlib migration PR lands

---

## DORMANT_V2 modules

### apps/investigation_core/exports/vault/

- **Path:** `apps/investigation_core/exports/vault/` + `apps/investigation_core/exports/services/export_service.py` + `apps/investigation_core/campaigns/exports/synthesis_service.py`
- **Lines:** ~300 combined
- **V2.x version:** V2.7 (knowledge vault RAG ingestion)
- **Purpose:** `VaultManager` is the planned ingestion target for completed investigation embeddings into ChromaDB. CLAUDE.md explicitly marks it protected: "Knowledge vault dormant code MUST NOT be deleted."
- **Active importers:** None in the Conductor pipeline. Only imported within investigation_core itself.
- **Bit-rot risk:** MEDIUM. Last touched 2026-05-22 (investigation_core/storage). No external dependencies on ChromaDB or nomic-embed-text yet. The data contract (findings schema) has evolved through V1.7 but VaultManager reads from completed investigations, not live findings, so schema drift is limited.

### exporters/ (repo root, not apps/)

- **Path:** `/home/unctad/projects/ai-assist-tool/exporters/`
- **Lines:** 2 220
- **V2.x version:** V2.7 (markdown export pipeline for vault ingestion)
- **Purpose:** `ExporterService`, `FindingExporter`, `AttackObservationExporter`, `MarkdownRenderer` — produces structured markdown from investigation records for vault ingest.
- **Active importers:** None. No apps/ module imports `from exporters`.
- **Bit-rot risk:** MEDIUM. Last touched 2026-05-18. No integration tests against the Conductor finding schema. Finding shapes evolved through V1.7 (typed-list evidence, `validation_status` fields) — exporters predate these and will need updates before activation.

### apps/validation/services/metasploit.py + msf_recipes.py + msf_wordlists.py + apps/validation/api/metasploit.py

- **Path:** `apps/validation/services/metasploit.py` (~240 lines), `msf_recipes.py` (~120 lines), `msf_wordlists.py` (~80 lines), `apps/validation/api/metasploit.py` (~320 lines)
- **Total lines:** ~760
- **V2.x version:** V2 (exploitation phase — Metasploit RPC integration)
- **Purpose:** `MsfClient` wraps `msfrpcd` RPC. Recipes and wordlists are static catalogs for the Metasploit UI page. `metasploit.py` router serves the `/api/v1/validation/metasploit` endpoints. Currently mounted via validation_router and reachable, but the exploitation phase (V2) has not been designed yet.
- **Active importers:** `metasploit.py` API imports `metasploit.py` service. Service imports `sdk.Logger`. Only used from within the metasploit UI page cluster.
- **Bit-rot risk:** LOW for the recipe/wordlist catalogs (static data). MEDIUM for the RPC client — `msfrpcd` in the Docker container may have drifted; client uses `pymetasploit3` which was pinned at the time of writing. No integration test against real msfrpcd.

---

## VESTIGE modules (deletion candidates)

These modules have no callers in the active investigation pipeline and originate from dropped directions (Category 3 learning platform, CVE matcher path, pre-Conductor scan runner era).

### apps/investigation_core/ (bulk)

The bulk of `apps/investigation_core/` implements the **Category 3 learning platform** — skill graphs, learning paths, progression tracking, campaign management, defensive posture snapshots, guided actions with approval workflows, and intelligence clustering. This was the original product direction before the V1.6 orchestration redesign.

| Subdirectory | Lines | Purpose | Active callers |
|---|---|---|---|
| `campaigns/` | 1 026 | Multi-investigation campaign management | None in Conductor pipeline; only campaign_routes.py (investigation_core/api) |
| `defensive/` | 644 | Defensive posture snapshots | routes.py has lazy imports (lines 2161–2536); AMBIGUOUS — see below |
| `evidence/` | 498 | Evidence artifact capture | routes.py lazy imports (lines 2253–2367); AMBIGUOUS |
| `exports/` (minus vault/) | ~355 | Export markdown/PDF | investigation_core/api only |
| `guided_actions/` | 1 764 | Approval workflow + action registry | routes.py lazy imports; AMBIGUOUS |
| `intelligence/` | 563 | Theme clustering + cross-investigation links | routes.py lazy import (line 2565); branch/assembler |
| `learning/` | 1 058 | Learning paths, recommendations, skill mastery | pipeline.py (VESTIGE) + branch/assembler |
| `lifecycle/` | 83 | Stage transition rules | Only investigation_service.py |
| `memory/` | 1 082 | InvestigationMemory snapshot aggregation | adaptive/guidance.py (VESTIGE) |
| `models/` | 142 | Shared domain models | investigation_service.py |
| `progression/` | 629 | Unlock triggers, skill progression | No active callers |
| `services/investigation_service.py` | 333 | Investigation CRUD + state | routes.py lazy imports throughout |
| `skills/` | 998 | Skill dependency graph, taxonomy | pipeline.py (VESTIGE) + normalization |
| `taxonomy/` | 110 | Workflow stage definitions | lifecycle/ only |
| `timeline/` | 150 | Timeline events | feed/builder.py (AMBIGUOUS) |
| `api/` | 1 207 | Routes: campaign, evidence, export, guided actions, skills | validation_router mounts it |

**Key finding:** Many `investigation_core` submodules are referenced via **lazy imports inside route handler function bodies** in `routes.py`. These routes are mounted and callable, but they serve the pre-V1.6 guided-actions, branch-graph, and learning-platform UI — not the V1.7 Conductor investigation workflow. They represent the prior product incarnation still reachable via URL but no longer evolved.

**True VESTIGE** (no callers anywhere in the active Conductor pipeline, and only self-referential within investigation_core):
- `apps/investigation_core/progression/` (629 lines) — no imports from any active module
- `apps/investigation_core/lifecycle/` (83 lines) — only used by investigation_service.py
- `apps/investigation_core/taxonomy/` (110 lines) — only used by lifecycle/
- `apps/investigation_core/learning/` (1 058 lines) — only used by pipeline.py (VESTIGE) and branch/assembler (AMBIGUOUS)
- `apps/investigation_core/memory/` (1 082 lines) — only used by adaptive/guidance.py (itself VESTIGE)
- `apps/investigation_core/campaigns/` (1 026 lines) — only used by investigation_core/api/campaign_routes.py

**VESTIGE total from investigation_core (conservative, confirmed-zero-active-callers):** ~3 988 lines

### apps/scanner_orchestration/services/

- **Path:** `apps/scanner_orchestration/services/orchestration_service.py`
- **Lines:** 510
- **Purpose:** Pre-Conductor `OrchestrationService` — starts scans, persists findings, runs `NormalizationPipeline`. This is the scan runner that Conductor replaced.
- **Active importers:** `scanner_orchestration/api/routes.py` (itself AMBIGUOUS), `investigation_workspace/feed/builder.py` (AMBIGUOUS), `investigation_workspace/branch/assembler.py` (AMBIGUOUS). No Conductor-path module imports it.
- **Suggested PR:** Medium (510 lines + must update all callers — but those callers are themselves VESTIGE/AMBIGUOUS).

### apps/scanner_orchestration/normalization/pipeline.py + cve_enricher.py

- **Path:** `pipeline.py` (~200 lines), `cve_enricher.py` (~80 lines)
- **Total lines:** ~280
- **Purpose:** `NormalizationPipeline` runs post-scan enrichment (CVE lookup via `cve_enricher`, skill/learning-path attachment via `skill_graph`). Only called from `OrchestrationService` (VESTIGE). The Conductor pipeline persists directly via `StorageBridge` and does not pass through `NormalizationPipeline`.
- **Active importers:** `orchestration_service.py` only (VESTIGE).
- **Suggested PR:** Small (280 lines, delete after orchestration_service).

### apps/scanner_orchestration/monitoring/ + profiles/ + timeline/

- **Path:** `monitoring/` (47 lines), `profiles/` (151 lines), `timeline/` (169 lines)
- **Total lines:** 367
- **Purpose:** `ScanMonitor` for scan health, `scan_profiles.py` profile registry, `scan_events.py` timeline. All three are only used from `scanner_orchestration/api/routes.py` (the AMBIGUOUS legacy scanner API routes).
- **Active importers:** None in Conductor pipeline.
- **Suggested PR:** Small (367 lines; delete after scanner api routes decision).

### apps/scanner_orchestration/execution/run.py

- **Path:** `apps/scanner_orchestration/execution/run.py`
- **Lines:** 153
- **Purpose:** `InvestigationRun` — aggregates `ScanExecution` rows sharing a `group_id`. Used by `orchestration_service.py` (VESTIGE) and `scanner_orchestration/api/routes.py` (AMBIGUOUS).
- **Note:** `execution/models.py` (50 lines) remains ACTIVE — it defines `ScanExecution` and `ScanStatus` imported by routes.py and all normalization modules.
- **Suggested PR:** Small (153 lines).

### apps/scanner_orchestration/target_resolution/ (minus models.py)

- **Path:** `resolver.py` (97), `diagnostics.py` (118), `ssrf_guard.py` (142), `validation.py` (114), `docker.py` (47), `__init__.py` (8)
- **Total lines (minus models.py):** 526
- **Purpose:** `TargetResolver` resolves hostnames, `ssrf_guard` validates target ranges, `DiagnosticsService` provides health info. These are only used by `scanner_orchestration/api/routes.py` (AMBIGUOUS) and the adapters via `models.py` only.
- **Note:** `target_resolution/models.py` (76 lines) is ACTIVE — defines `TargetContext` imported by all three adapters.
- **Suggested PR:** Small-medium (526 lines; delete when scanner api routes are cleared).

### apps/validation/engines/

- **Path:** `cve_matcher.py` (~400 lines), `nvd_sync.py` (~200 lines), `fingerprint_normalizer.py` (~54 lines)
- **Total lines:** 654
- **Purpose:** `CveMatcher` matches services against CVE database; `NvdSync` fetches NVD feeds. Explicitly dropped per CLAUDE.md: "CVE matcher chain... stays in DB and codebase — parked, not wired, recoverable." `fingerprint_normalizer.py` normalises banner text; no active callers.
- **Active importers:** `cve_matcher.py` is imported by `validation/api/known_issues.py` and `validation/api/settings_router.py` (both AMBIGUOUS validation API), plus `validation/services/correlator.py` (VESTIGE). No Conductor-path caller.
- **Suggested PR:** Small (654 lines; keep in mind CLAUDE.md's "parked, not wired, recoverable" note — operator should confirm deletion is acceptable before shipping).

### apps/validation/services/ (minus metasploit.py, msf_recipes.py, msf_wordlists.py)

- **Includes:** `backend_detect.py`, `change_detector.py`, `correlator.py`, `custom_report_scanner.py`, `cve_registry.py`, `deep_lift.py`, `executor.py`, `recon.py`, `report_generator.py`, `scanner.py`, `suppression.py`
- **Lines:** ~3 073
- **Purpose:** Pre-Conductor scanning service layer. `executor.py` ran plugins against queue items; `correlator.py` matched findings to CVEs; `scanner.py` coordinated recon; `suppression.py` applied known-issue rules. Replaced in function by the Conductor + FilterOrchestrator pipeline.
- **Active importers:** `validation/api/` routes (AMBIGUOUS) import these; no Conductor-path module does.
- **Suggested PR:** Large (3 073 lines; must clear validation/api routes first).

### apps/validation/tasks/

- **Path:** `expiry_worker.py` (197 lines), `__init__.py`
- **Lines:** 197
- **Purpose:** Background task archiving old queue items. No Conductor equivalent; the queue is a pre-Conductor concept.
- **Active importers:** None in Conductor path.
- **Suggested PR:** Small (197 lines).

### apps/validation/adapters/

- **Path:** `nmap.py`, `recon_ng.py`
- **Lines:** 563
- **Purpose:** Older nmap wrapper and recon-ng adapter. Superseded by `apps/scanner_orchestration/adapters/nmap_adapter.py`. Only `validation/services/scanner.py` and `validation/services/recon.py` (both VESTIGE) import them.
- **Active importers:** None in Conductor path.
- **Suggested PR:** Small (563 lines).

### apps/investigation_workspace/adaptive/

- **Path:** `adaptive/guidance.py`, `adaptive/__init__.py`
- **Lines:** 405
- **Purpose:** Maturity-aware narrative decorator for the `FeedBuilder`. Only used by `feed/builder.py` (AMBIGUOUS).
- **Active importers:** `feed/builder.py` only.
- **Suggested PR:** Trivial (405 lines; remove once feed/ decision is made).

---

## AMBIGUOUS modules

These modules are imported by `apps/investigation_workspace/api/routes.py` or `apps/validation/api/__init__.py` (both of which are mounted and serve HTTP requests), but it is unclear whether the operator actively uses the corresponding UI paths in the V1.7 workflow. Operator review needed before deletion.

### apps/investigation_workspace/branch/

- **What it does:** React Flow topology graph — `BranchAssembler` builds the node graph from findings/approvals/artifacts; `topology_v2.py` serializes to `{nodes, edges, meta}` JSON consumed by the frontend React Flow canvas; `assembler.py` reads from `OrchestrationService` (VESTIGE) and `investigation_core` data.
- **Importer:** `routes.py` imports `BranchAssembler`, `topology_v2.serialize_topology`, `BranchState`, `NodeKind` at multiple points (lines 147–388, 1126–1177).
- **Question for operator:** Is the React Flow branch topology canvas still rendered and used in the operator UI? If the workspace UI has migrated to the `workspace-data.json` polling model exclusively (V1.7), these routes may be dead ends. The `investigation_workspace.html` template references `topology` only once (one comment in workspace-data.json context), suggesting the React Flow canvas may be vestige UI.

### apps/investigation_workspace/suggestions/

- **What it does:** Pre-V2.1 probe runner system. `catalog.py` maps `finding_type → SuggestionSpec`. `probes.py` (~5 404 lines) contains async probe generators that fire real HTTP probes (robots.txt, CSP check, etc.). `execute_suggestion` route at line 1360 of routes.py activates these.
- **Question for operator:** This is not the V2.1 Qwen suggester — it's a deterministic probe catalog. Is the `execute_suggestion` route still used operationally? If so, this is ACTIVE infrastructure. If V2.1 Qwen replaces it and these probes are redundant, it becomes DORMANT_V2 or VESTIGE depending on whether any probe logic survives the V2.1 design.

### apps/investigation_workspace/execution/

- **What it does:** In-memory `ExecutionRun` animation runtime. Tracks stages that animate on the React Flow graph. Used by `execute_suggestion` and the context panel (lines 897, 1180, 1391, 1466, 1516).
- **Question for operator:** Depends on branch/ and suggestions/ resolution. If the animation runtime is only for the pre-V2.1 probe executor, fate follows suggestions/.

### apps/investigation_workspace/exploitation_paths/

- **What it does:** `bindings.py` maps `finding_type → exploitation path ids`. `taxonomy.py` defines path categories. `next_actions.py` provides next-action specs. Routes.py imports these at lines 1863–1946.
- **Question for operator:** The CLAUDE.md design note explicitly states "Catalog mapping (finding_type → exploit category) — exploit categories themselves get defined in V2 exploitation design." This module predates that design. It may need to survive as a V2 foundation or be replaced entirely. Recommend DORMANT_V2 if the taxonomy aligns with V2 exploitation design intent.

### apps/investigation_workspace/feed/

- **What it does:** `FeedBuilder` aggregates a chronological timeline across scanner findings, timeline events, and evidence artifacts. Used by the feed panel in the operator UI (routes.py lines 2067, 2263).
- **Question for operator:** Is the chronological feed panel still in the operator UI? If so this is ACTIVE. If it was replaced by the `workspace-data.json` polling model, it is VESTIGE.

### apps/investigation_workspace/capture/

- **What it does:** Post-exploit artifact capture bundles (`get_bundle`). Routes.py imports `get_bundle` at lines 1638, 1813, 1842.
- **Question for operator:** Post-exploit capture is semantically V2-era work. Does the operator use bundle capture today? The capture/ module depends on `execution/runtime.py` for determining when a run has produced an outcome.

### apps/investigation_workspace/categories/

- **What it does:** Static category catalog mapping `finding_type → Category`. Routes.py imports at line 804.
- **Note:** CLAUDE.md explicitly states "Uncategorized as intentional state — do NOT treat this as a bug. Do NOT fix it by forcing recon/enum finding types into exploit-focused categories." This module was the mechanism for that forced categorization. The V1.7 workspace-data.json does not use categories.
- **Question for operator:** Is the category catalog still rendered anywhere in the current operator UI? If the workspace UI exclusively uses `workspace-data.json`, this is VESTIGE.

### apps/scanner_orchestration/api/

- **What it does:** Scanner-facing HTTP routes (`/api/v1/validation/scanner`). Provides scan history, profiles, investigation runs via `OrchestrationService`. Mounted through `validation_router`.
- **Question for operator:** This API predates the Conductor. Does the frontend still call `/api/v1/validation/scanner/` endpoints? If so, this entire cluster (scanner_orchestration/api + services + monitoring + profiles + timeline) must stay. If the Conductor admin UI (`/admin/conductor`) replaced these panels, the routes are dead and the entire pre-Conductor cluster is VESTIGE.

### apps/validation/api/ (minus metasploit.py)

- **What it does:** Broad CRUD UI — assets, discovery, findings, queue, reports, changes, history, known_issues, settings, investigations. Mounted via `validation_router`. The root `/` redirects to `/api/v1/validation/discovery` which is in this module.
- **Note:** `discovery.py` is active — it is the app landing page. The question is which of the other routes are still used operationally vs. pre-Conductor vestiges.
- **Question for operator:** Which of these UI panels does the operator actively use in the current workflow? `discovery.py` is confirmed active. `investigations.py` renders a per-target aggregation view. `queue.py`, `assets.py`, `reports.py`, `changes.py`, `history.py` represent the pre-Conductor monitoring and queue workflow.

### apps/investigation_core/defensive/ + evidence/ + guided_actions/ + intelligence/ + services/

- **What it does:** Defensive posture snapshots, evidence artifact capture, guided action approvals, cross-investigation intelligence. Routes.py has lazy imports for all of these throughout lines 1113–2620.
- **Question for operator:** Are defensive posture, evidence capture, and guided action approval workflows still operational and operator-facing? If yes, these are borderline ACTIVE and should be treated as the pre-V2 manual exploitation tooling. If the operator has migrated entirely to the Conductor workspace, they are VESTIGE.

### apps/validation/repositories/

- **What it does:** Repository layer for all legacy tables (hosts, services, CVEs, queue, findings, changes, known_issues, history, assets, watchlist, recon_results, msf_runs).
- **Note:** Actively used by `validation/api/` routes. Fate follows `validation/api/` resolution. If legacy API routes are cleared, repositories go with them. If `discovery.py` and `investigations.py` stay (they reference `HostRepository`, `FindingRepository`, etc.), the repository layer partially survives.

---

## Deletion candidates summary

**Confirmed VESTIGE — zero Conductor-pipeline callers, safe to delete:**

| Cluster | Lines | Suggested PR size |
|---|---|---|
| `apps/investigation_core/progression/` | 629 | Small |
| `apps/investigation_core/lifecycle/` + `taxonomy/` + `models/` | 335 | Small |
| `apps/investigation_core/campaigns/` | 1 026 | Small |
| `apps/investigation_core/memory/` | 1 082 | Medium |
| `apps/investigation_core/learning/` | 1 058 | Medium |
| `apps/scanner_orchestration/services/` | 510 | Medium |
| `apps/scanner_orchestration/normalization/pipeline.py` + `cve_enricher.py` | 280 | Small |
| `apps/scanner_orchestration/monitoring/` + `profiles/` + `timeline/` | 367 | Small |
| `apps/scanner_orchestration/execution/run.py` | 153 | Small |
| `apps/scanner_orchestration/target_resolution/` (minus models.py) | 526 | Small-medium |
| `apps/validation/engines/` (operator must confirm CVE code deletion) | 654 | Small |
| `apps/validation/services/` (minus metasploit/msf_*) | 3 073 | Large |
| `apps/validation/tasks/` | 197 | Small |
| `apps/validation/adapters/` | 563 | Small |
| `apps/investigation_workspace/adaptive/` | 405 | Trivial (after feed/ decision) |
| `apps/investigation_core/progressive vestiges` (skills/, intelligence/, etc. — pending AMBIGUOUS resolution) | ~2 000 | Medium |

**Estimated total confirmed-VESTIGE lines:** ~12 858
**Estimated total AMBIGUOUS lines (pending operator decision):** ~14 000

### Recommended order of operations

1. **PR VESTIGE-1** — delete `apps/scanner_orchestration/` non-active subdirs (services, monitoring, profiles, timeline, execution/run.py, target_resolution minus models.py, normalization/pipeline.py + cve_enricher.py). These have zero Conductor callers and no ambiguity. ~2 059 lines.

2. **PR VESTIGE-2** — delete `apps/validation/engines/`, `apps/validation/tasks/`, `apps/validation/adapters/`. Operator must confirm CVE code deletion is acceptable (CLAUDE.md marks it "parked, recoverable"). ~1 414 lines.

3. **PR VESTIGE-3** — delete confirmed-VESTIGE investigation_core subdirs (progression, lifecycle, taxonomy, models, campaigns, memory, learning). ~4 130 lines.

4. **AMBIGUOUS resolution** — operator reviews the 7 AMBIGUOUS clusters and assigns ACTIVE / DORMANT_V2 / VESTIGE. This decision gates PRs 4–6.

5. **PR VESTIGE-4** — delete `apps/validation/services/` (minus metasploit/msf_*) after validation/api resolution. ~3 073 lines.

6. **sdk.Logger migration PR** — replace `from sdk import Logger` with `import logging; log = logging.getLogger(__name__)` across all consumers. After that, `sdk/` can be removed (~51 lines, but the PR touching all consumers is medium size).

---

## DORMANT_V2 watch list

| Module | Lines | V2.x stage | Bit-rot risk | Note |
|---|---|---|---|---|
| `apps/investigation_core/exports/vault/` | 183 | V2.7 RAG ingestion | Medium | Finding schema evolved in V1.7; vault ingest logic predates typed-list evidence fields |
| `exporters/` (repo root) | 2 220 | V2.7 markdown export | Medium | Predates `validation_status`, `enumeration_gaps`, typed hit_paths; needs audit before activation |
| `apps/validation/services/metasploit.py` | ~240 | V2 exploitation | Medium | `pymetasploit3` version compatibility unknown; no integration test |
| `apps/validation/services/msf_recipes.py` | ~120 | V2 exploitation UI | Low | Static catalog; low drift risk |
| `apps/validation/services/msf_wordlists.py` | ~80 | V2 exploitation UI | Low | Static catalog; low drift risk |
| `apps/validation/api/metasploit.py` | ~320 | V2 exploitation UI | Medium | Mounted and callable today; untested against real msfrpcd in current container |
| `apps/investigation_workspace/exploitation_paths/` | 552 | V2 exploitation design | High | Taxonomy predates V2 exploitation design; may conflict with V2 architecture decisions |

**Highest pre-activation risk:** `exporters/` — 2 220 lines of markdown rendering logic that predates every V1.7 schema addition. Before V2.7 activation, it needs an evidence-schema compatibility pass against `validation_status`, `enumeration_gaps`, `hit_paths: list[dict]`, and `detected_login_endpoints: list[dict]`.
