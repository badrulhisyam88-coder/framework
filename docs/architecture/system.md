# System Architecture

## In one paragraph

When an operator pastes a target URL into the workspace UI, a FastAPI route in `apps/investigation_workspace/api/routes.py` creates a `PhasedRun` record, then calls `_run_all_probes_via_conductor` in `apps/investigation_workspace/bootstrap/runtime.py`. That function hands control to the `Conductor` (`apps/conductor/conductor.py`), which boots six orchestrators sharing a common investigation context. The Conductor advances through phases (recon → enumeration) by telling the Phase Orchestrator to move forward, which tells the Execution Orchestrator to dispatch the appropriate engines. Engines are stateless Python classes that run nmap, nuclei, ZAP, passive HTTP probes, and a set of validation plugins; they emit `FindingEvent` objects into an output channel. The Findings Orchestrator deduplicates those events and passes them to the StorageBridge, which writes a `NormalizedFinding` row to `validation.db` with a deterministic `fnd_xxx` ID. The Chain Orchestrator reads each finding's `next_actions` field and auto-fires enumeration engines (like `api_recon`, `auth_recon`, `sqli_recon`) that dig deeper into what recon found. Once all enumeration engines finish, the Filter Orchestrator runs 19 rules over every finding in two passes — classifying each as `validated`, `dropped`, or `incomplete`, and triggering targeted re-invocations when evidence gaps need filling. The workspace UI polls a `/workspace-data.json` endpoint and renders status badges (green/orange/grey) per finding. Dropped findings are hidden by default; the operator can toggle them. The `/admin/*` panel shows investigation health, gate toggles, and an enumeration-gaps summary.

---

## Three-level hierarchy

```
Level 3 — Conductor (apps/conductor/conductor.py)
   Top coordinator. Knows nothing about individual engines.
   Receives operator intent (target + config), emits investigation-level events.
   Boots all six orchestrators with a shared _InvestigationContext.

Level 2 — Domain Orchestrators (apps/conductor/orchestrators/)
   Six orchestrators, each owns one concern:
   - PhaseOrchestrator   — phase state machine (recon → enumeration → exploitation)
   - ExecutionOrchestrator — engine lifecycle, dispatch, concurrency policy (mutex table)
   - FindingsOrchestrator  — single ingress, dedup by finding_id, translation
   - ChainOrchestrator    — next_actions chains, depth limits, cycle detection
   - SessionOrchestrator  — _API_AUTH_STORE, rate limiting, target classification
   + FilterOrchestrator (V1.7) — two-pass rule evaluation after enumeration phase,
     sets validation_status, fires REINVOCATION_RULES, records evidence gaps

Level 1 — Engines (apps/conductor/engines/)
   Stateless. Subclass Engine ABC (apps/conductor/engines/base.py).
   Implement run(), cancel(), health_check(), capabilities property.
   Never talk to each other; all coordination flows through orchestrators.
   Registered via @engine_registry.register — no orchestrator code changes needed.
```

---

## Components

### Conductor
- Purpose: Top coordinator. Boots orchestrators, drives _run_phases(), emits investigation events.
- Lives at: `apps/conductor/conductor.py` (class `Conductor`, line 154)
- Inputs: `start_investigation(target, config)` from runtime.py
- Outputs: `investigation_started`, `investigation_completed`, `investigation_failed` events
- Key behavior: wires FilterOrchestrator after enumeration phase; `_validation_update` and `_block_reason_update` callbacks import `DB_PATH` from `apps.validation.database` and write to `validation.db`, not to `orchestration.db`

### PhaseOrchestrator
- Purpose: Investigation phase state machine.
- Lives at: `apps/conductor/orchestrators/phase.py` (class `PhaseOrchestrator`, line 41)
- Phases: recon → enumeration → exploitation (exploitation not yet wired)
- Key behavior: phase completes when all phase-initial engines finish; chain-dispatched engines do not block phase transition
- Events: `phase_started`, `phase_completed`, `phase_failed`

### ExecutionOrchestrator
- Purpose: Engine lifecycle, dispatch, concurrency enforcement.
- Lives at: `apps/conductor/orchestrators/execution.py` (class `ExecutionOrchestrator`, line 45)
- Key behavior: maintains per-target mutex table; consults SessionOrchestrator before dispatch (rate limit + auth readiness); enforces gate filter fail-closed — unknown `gate_id` blocks engine, not passes it
- Watchdog: `_HUNG_THRESHOLD_HEAVY=600s` for nmap/nuclei/zap; `_HUNG_THRESHOLD_LIGHT=30s` for light/medium engines

### FindingsOrchestrator
- Purpose: Single ingress for all engine output.
- Lives at: `apps/conductor/orchestrators/findings.py` (class `FindingsOrchestrator`, line 28)
- Key behavior: deduplicates by `finding_id` (fnd_xxx format from `generate_finding_id()`); merges duplicate findings, translates engine-specific shapes to `FindingEvent`
- Events: `finding_created`, `finding_updated`, `finding_correlated`

### ChainOrchestrator
- Purpose: Evaluate `next_actions` on each finding; auto-fire or gate enumeration chains.
- Lives at: `apps/conductor/orchestrators/chain.py` (class `ChainOrchestrator`, line 26)
- Key behavior: trigger types `auto_fire`, `operator_arm_required`, `operator_confirm_required`; linear depth cap 5; cycle detection cap 3 (set to 3 in PR D-fix-2, never 0)
- Events: `chain_auto_fired`, `chain_depth_limit_reached`, `chain_operator_*`

### SessionOrchestrator
- Purpose: Auth store, rate limiting, target classification.
- Lives at: `apps/conductor/orchestrators/session.py` (class `SessionOrchestrator(SessionStore)`, line 57)
- Key behavior: owns `_API_AUTH_STORE`; engines never re-authenticate — they read from the store; classifies targets as local / private-range / external / WAF-fronted
- Methods: `get_session()`, `can_dispatch()`

### FilterOrchestrator
- Purpose: Two-pass rule evaluation over all findings after enumeration phase completes.
- Lives at: `apps/conductor/orchestrators/filter.py` (class `FilterOrchestrator`, line 34)
- Pass 1: applies `REGISTERED_RULES` (drop → validate → incomplete); first-match-wins per finding
- Pass 2: collects `REINVOCATION_RULES` results, deduplicates requests, dispatches engine re-invocations via `ExecutionOrchestrator`, re-filters new findings
- Key behavior: `RuleResult.evidence_gap()` signals missing evidence without blocking — chain continues, `enumeration_block_reason` recorded; **runs after enumeration phase, not after recon** (PR K fix — chain-dispatched engines must finish first)
- Wired callbacks: `wire_db_writer()` (validation_status), `wire_block_reason_writer()` (enumeration_block_reason), `wire_reinvocation_dispatcher()` (re-invocation)

### StorageBridge
- Purpose: Routes `FindingEvent` from Conductor's output channel to the legacy persist path.
- Lives at: `apps/conductor/findings/storage_bridge.py` (class `StorageBridge`, line 18)
- Key behavior: calls `emit_finding` for Conductor path AND `_persist` in `apps/investigation_workspace/api/routes.py`; `_persist` passes `finding_id=(evt.id or str(uuid4()))` — the PR L one-line fix that ended the two-parallel-ID-systems bug; `source_scanner` populated from `evt.probe_id` (PR D-fix-2)

### Gate Registry
- Purpose: In-memory runtime feature gates; controls which engines and severities are active.
- Lives at: `apps/conductor/gates.py`; thread-safe via `threading.Lock` (`_LOCK`)
- Multi-gate engines (nuclei, zap): visible iff ANY gate in `gate_ids` tuple is ON
- Admin UI toggle at `/admin/settings`
- Helpers: `get_gate()`, `set_gate()`, `list_gates()`, `reset_all_gates_to_defaults()`, `engine_is_visible(engine)`
- Fail-closed: engine with unknown `gate_id` → BLOCKED with explicit log; startup validation refuses to register such engines

### Engines

All 15 active engines (excluding `mock.py`):

| Engine class | File | Type | Phase |
|---|---|---|---|
| `PassiveProbeEngine` | `passive_probe_engine.py` | recon | recon |
| `NmapEngine` | `nmap_engine.py` | recon | recon |
| `NucleiEngine` | `nuclei_engine.py` | enumeration | enumeration |
| `ZapEngine` | `zap_engine.py` | enumeration | enumeration |
| `ApiReconEngine` | `api_recon_engine.py` | enumeration | enumeration |
| `AuthReconEngine` | `auth_recon_engine.py` | enumeration | enumeration |
| `SqliReconEngine` | `sqli_recon_engine.py` | enumeration | enumeration |
| `CmdiReconEngine` | `cmdi_recon_engine.py` | enumeration | enumeration |
| `SshEngine` | `ssh_engine.py` | validation plugin | enumeration |
| `TelnetEngine` | `telnet_engine.py` | validation plugin | enumeration |
| `SmbEngine` | `smb_engine.py` | validation plugin | enumeration |
| `WordpressEngine` | `wordpress_engine.py` | validation plugin | enumeration |
| `DrupalEngine` | `drupal_engine.py` | validation plugin | enumeration |
| `ApacheEngine` | `apache_engine.py` | validation plugin | enumeration |
| `NginxEngine` | `nginx_engine.py` | validation plugin | enumeration |

Engine ABC: `apps/conductor/engines/base.py` — `class Engine(ABC)` at line 105. Required interface: `capabilities` property, `run()`, `cancel()`, `health_check()`. Asyncio primitives must be created inside `run()`, not `__init__`.

### Adapters

Thin subprocess / HTTP wrappers. Engines call them; adapters own CLI flag construction, exit code checking, output parsing, and timeout handling. They do NOT own scope, gates, or profile logic — that belongs to the engine layer.

| Adapter | File |
|---|---|
| `NucleiAdapter` (backward compat class) + `run_scan()` module function | `apps/scanner_orchestration/adapters/nuclei_adapter.py` |
| `NmapAdapter` | `apps/scanner_orchestration/adapters/nmap_adapter.py` |
| `ZAPAdapter` (backward compat class) + `run_spider()`, `run_passive_scan()` module functions | `apps/scanner_orchestration/adapters/zap_adapter.py` |

Nuclei adapter note: rewritten in PR E-fix for v3.3.5 — uses `-jsonl-export` flag, not `-json`; checks `returncode != 0`.

### Rules

All rules live in `apps/conductor/rules/` as Python class instances. Imported into `REGISTERED_RULES` and `REINVOCATION_RULES` lists via `apps/conductor/rules/registry.py`.

| File | List name | Rule count | What they do |
|---|---|---|---|
| `drop_rules.py` | `DROPPED_RULES` | 6 | Verified dead ends: wrong server type, empty endpoints, tool unavailable |
| `validate_rules.py` | `VALIDATE_RULES` | 7 | Confirmed worth exploit time: accessible API, sqli endpoints found, version-confirmed service, etc. |
| `incomplete_rules.py` | `INCOMPLETE_RULES` | 6 | Worth exploit's time but data missing: auth status unknown, API behind auth, etc. |
| `reinvocation_rules.py` | `REINVOCATION_RULES` | 8 | Trigger targeted re-probes: e.g., api_recon with candidate paths from earlier findings |

`RuleResult` class: `apps/conductor/rules/base.py` (line 13). Rule evaluation returns a 4-tuple `(status, reason, gaps, block_reason)`. `RuleResult.evidence_gap(reason)` is opt-in — use only when missing field is meaningfully actionable by operator.

`ReinvocationRequest` dataclass also lives in `rules/base.py`.

### NormalizedFindingRepository
- Purpose: Query, update, and persist `normalized_findings` rows.
- Lives at: `apps/scanner_orchestration/storage/finding_repo.py` (class `NormalizedFindingRepository`, line 35)
- Key methods: `update_block_reason()`, `map_validation_status()`, `list_enumeration_gaps()`
- Used by: FilterOrchestrator callbacks (via conductor.py), workspace-data.json route, admin enumeration-gaps panel

### Validation DB
- Path: `/app/data/validation.db` (Docker path)
- Source: `DB_PATH` in `apps/validation/database.py` (line 11)
- Tables: `normalized_findings` — includes `validation_status`, `validation_reason`, `enumeration_gaps`, `validated_at`, `superseded_by`, `enumeration_block_reason` columns (added V1.7 PR H/J, idempotent migration)
- CRITICAL: FilterOrchestrator callbacks MUST connect to this DB, not `orchestration.db`. Pre-PR K, all V1.7 UPDATEs silently no-oped because they targeted the wrong DB.

### Orchestration DB
- Path: `data/orchestration.db` (relative to app root)
- Source: `apps/conductor/storage/db.py` (`_DEFAULT_DB_PATH`, line 20)
- Purpose: Investigation state — active investigations table, phase transitions, conductor event log
- Does NOT contain `normalized_findings`

### Workspace UI
- Purpose: Operator-facing investigation interface.
- Lives at: `apps/investigation_workspace/` — routes in `apps/investigation_workspace/api/routes.py`
- Key endpoint: `GET /investigations/{id}/workspace-data.json` — polled by `workspace.js`
- Key behavior: `include_dropped=false` hides dropped findings by default; `wsToggleDropped` toggle in JS; status badges per finding (validated=green, incomplete=orange, dropped=grey, pending=no badge)
- `_dominant_validation()` in `apps/investigation_workspace/aggregations.py` computes group-level status

### Admin UI
- Purpose: Backend operator panel — investigation health, gate management, enumeration gaps.
- Lives at: `apps/admin_ui/routes.py`; mounted at `/admin/*` prefix on port 8000
- No auth — single-operator local tool
- Panels: `/admin/conductor` (active investigations), `/admin/execution` (engine status), `/admin/settings` (gate toggles), `/admin/enumeration-gaps` (evidence gap aggregation)

---

## Data flow (typical investigation)

1. Operator submits target URL in workspace UI
2. `apps/investigation_workspace/api/routes.py` creates `PhasedRun` row; calls `_run_all_probes_via_conductor` in `apps/investigation_workspace/bootstrap/runtime.py`
3. `runtime.py` calls `Conductor.start_investigation(target, config)`
4. Conductor boots all orchestrators with shared `_InvestigationContext`; creates `recon_run` stub with `completed_at=None` before starting
5. Phase Orchestrator advances to recon phase; Execution Orchestrator dispatches phase-initial engines: `PassiveProbeEngine` and `NmapEngine`
6. Engines run; emit `FindingEvent` objects via `output_channel` with deterministic `fnd_xxx` IDs
7. Findings Orchestrator ingests, deduplicates by `finding_id`, translates
8. StorageBridge routes to `_persist` in routes.py → `NormalizedFinding` written to `validation.db` with `finding_id=(evt.id or str(uuid4()))` (PR L fix — ensures FilterOrchestrator UPDATEs match rows)
9. Chain Orchestrator evaluates `next_actions` on each finding; `auto_fire` chains dispatch enumeration engines: `api_recon_engine`, `auth_recon_engine`, `sqli_recon_engine`, `cmdi_recon_engine`, plus `nuclei`, `zap`, and validation plugins based on service type
10. Phase Orchestrator advances to enumeration phase when all phase-initial engines complete
11. Chain-dispatched engines run; emit more `FindingEvent` objects through same StorageBridge path
12. After all enumeration engines finish, Conductor calls `FilterOrchestrator.run()` (pass 1: 19 rules, drop → validate → incomplete, first-match-wins; pass 2: REINVOCATION_RULES fire re-invocations)
13. Findings in `validation.db` updated with `validation_status`, `validation_reason`, `enumeration_block_reason`
14. Workspace UI polls `/workspace-data.json`; status badges (green/orange/grey) appear per finding card; dropped findings hidden unless `wsToggleDropped` active
15. Investigation completes; `/admin/enumeration-gaps` shows any surfaced evidence gaps for operator review

```
Operator → Workspace UI → bootstrap/runtime.py → Conductor
                                                      ↓
                                       [PhaseOrch] → [ExecOrch] → [Engines]
                                                      ↓
                                       [FindingsOrch] ← engine output (FindingEvent)
                                            ↓
                                       [StorageBridge] → NormalizedFinding → validation.db
                                            ↓
                                       [ChainOrch] → next_actions → ExecOrch → more engines
                                            ↓
                                    [FilterOrch (after enumeration)]
                                            ↓
                                       validation_status written to validation.db
                                            ↓
                                    Workspace UI polls → operator sees status badges
```

---

## Gate registry

| Gate ID | Default | Controls | Related engine |
|---|---|---|---|
| `nuclei_severity_info` | **ON** | nuclei info-severity templates | `NucleiEngine` |
| `nuclei_severity_low` | **ON** | nuclei low-severity templates | `NucleiEngine` |
| `nuclei_severity_medium` | OFF | nuclei medium-severity templates | `NucleiEngine` |
| `nuclei_severity_high` | OFF | nuclei high-severity templates | `NucleiEngine` |
| `nuclei_severity_critical` | OFF | nuclei critical-severity templates | `NucleiEngine` |
| `nmap_external_scan` | OFF | nmap against EXTERNAL targets (local/private always allowed) | `NmapEngine` |
| `ssh_credential_testing` | OFF | SSH default-credential validation via paramiko | `SshEngine` |
| `telnet_credential_capture` | OFF | Telnet cleartext-credential capture | `TelnetEngine` |
| `smb_null_session_enum` | OFF | SMB null-session enumeration via impacket | `SmbEngine` |
| `wordpress_vuln_check` | OFF | WordPress vulnerability checks on HTTP services | `WordpressEngine` |
| `drupal_vuln_check` | OFF | Drupal vulnerability checks on HTTP services | `DrupalEngine` |
| `apache_misconfig_check` | OFF | Apache misconfiguration checks on HTTP services | `ApacheEngine` |
| `nginx_misconfig_check` | OFF | Nginx misconfiguration checks on HTTP services | `NginxEngine` |
| `zap_passive_scan` | OFF | ZAP passive scan: observe HTTP traffic for alerts | `ZapEngine` |
| `zap_spider` | OFF | ZAP spider: crawl target to discover URLs and forms | `ZapEngine` |

Nuclei and ZAP use `gate_ids: tuple[str, ...]` — engine visible iff ANY gate in tuple is ON. All others use single `gate_id`. `engine_is_visible(engine)` helper handles both cases. Setting both `gate_id` and `gate_ids` on the same engine → fail-closed.

---

## Reference scenario

The canonical design test case: a cross-protocol telnet + HTTP login chain used to evaluate whether each system stage helps the operator.

**Target characteristics:**
- HTTP service with login page; login authenticates via `POST /api/login`
- Telnet service exposed on port 23 with an unusual write command that adds credentials with `admin=true` flag
- The telnet technique is NOT in nuclei templates or nmap NSE scripts — operator brings this knowledge

**Exploit chain:**
- Step 1: Connect to telnet, send write command adding operator's credentials (`admin=true`)
- Step 2: `POST /api/login` with those credentials
- Step 3: Receive admin session

**What V1.7 does for this target:**

Recon phase: `PassiveProbeEngine` discovers HTTP service, login form, `/api/login` endpoint. `NmapEngine` discovers telnet on port 23 (`service_detected` finding for both).

Chain dispatch: nmap's `service_detected` findings trigger `auto_fire` chains that dispatch `api_recon_engine` (targets HTTP), `auth_recon_engine` (probes `/api/login`), and `TelnetEngine` (probes port 23 per gate setting).

Enumeration: `ApiReconEngine` verifies `/api/login` returns 200. `AuthReconEngine` probes for auth requirement, records `auth_required` and `detected_login_endpoints` in evidence. `SqliReconEngine` records detected login endpoints.

FilterOrchestrator (after enumeration): `ValidateApiExposureAccessible` rule marks the `/api/login` finding as `validated` (200-only hits, no 401/403). `ValidateServiceDetectedWithVersion` or equivalent telnet rule marks the telnet finding as `validated` (or `incomplete` if evidence version field is empty). Low-noise findings (wrong-server plugin results, empty-endpoint sqli) are `dropped`.

Result: operator sees two `validated` findings — telnet service + accessible `/api/login` — highlighted in green, not buried under low-ROI noise.

**V1.7 design boundary:** The unusual telnet write technique is operator knowledge. FilterOrchestrator surfaces the components (telnet service, accessible API endpoint); it cannot synthesize the cross-protocol chain. That is the design: system surfaces the attack surface, operator brings the exploit.

---

## V1.7 contributions

V1.7 adds enumeration-phase curation to the investigation pipeline. The core new component is `FilterOrchestrator` (`apps/conductor/orchestrators/filter.py`) — a two-pass rule evaluator that runs after enumeration completes. Pass 1 applies 19 `REGISTERED_RULES` (6 drop, 7 validate, 6 incomplete) in a first-match-wins chain; pass 2 fires 8 `REINVOCATION_RULES` and dispatches targeted engine re-invocations for findings where additional evidence would change classification. The `RuleResult.evidence_gap()` protocol lets rules signal that a field is absent without halting the chain — the gap reason is written to `enumeration_block_reason` and surfaced in the `/admin/enumeration-gaps` panel as an aggregated count, letting the operator decide whether to enrich a recon engine in a future PR. In the workspace UI, per-finding `validation_status` badges appear (validated=green, incomplete=orange, dropped=grey); dropped findings are hidden by default and toggled via `wsToggleDropped`. The pattern catalog at `tests/conductor/_patterns/README.md` documents the 7 seam bug patterns discovered during V1.6–V1.7 development; the 7 corresponding `test_seam_*.py` files enforce the fixes as regression tests that run on every test suite invocation. For cross-layer contracts and what breaks at each seam, see `/docs/architecture/seams.md`.
