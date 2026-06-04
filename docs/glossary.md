# Glossary

Canonical terminology for ai-assist-tool. When operator uses a non-canonical term, map to canonical and confirm before proceeding.

## Quick map (non-canonical → canonical)

| Non-canonical / informal | Canonical term |
|---|---|
| scan | investigation |
| probe (post-V1.6) | engine |
| filter | FilterOrchestrator |
| validation (as in "running validation plugins") | enumeration (the phase) |
| validator | plugin (specific service-check) or engine (general) |
| feature flag (for engine visibility) | gate |
| flag | gate |
| active investigation | investigation in RECON_RUNNING / ENUM_RUNNING state |
| scan execution | ScanExecution (legacy pre-Conductor model) |
| findings filter | FilterOrchestrator |
| whitelist / blacklist (finding status) | validated / dropped |
| incomplete finding | finding with validation_status='incomplete' |
| re-run | re-invocation |

---

## V2 exploitation terms

### arm / armed
- **Definition:** Operator-initiated approval state that precedes exploitation engine execution. A branch is "armed" when the operator has filled the template form and clicked the arm button. Armed state is transient — a 5-second window before the operator must confirm, or the state reverts to `pending`. Only a confirmed arm triggers actual execution.
- **Enforced at:** `exploit_approval.py` (engine layer) and the arm-gate on the exploitation mindmap Layer 1 node. Server-side: HTTP 409 if execution is requested without `?confirm=<engine_id>`.
- **NOT to be confused with:** executing (arm is the gate before execution; execution begins after confirm)

### artifact
- **Definition:** Operational output produced by a successful exploitation engine. Typed by technique class: bookmarklet (SQLi bypass — contains JavaScript to replay the authenticated session), session capture (cookies + JWT), credential proof (username/password pair confirmed), extracted data (harvested secrets or content). Written to `exploitation_branches.artifact` as a JSON blob. Rendered inline at Layer 3 of the mindmap right-side panel.
- **Lives at:** `apps/conductor/engines/exploit_artifacts.py` (construction); `exploitation_branches.artifact` column (persistence)
- **NOT to be confused with:** exhaustion record (artifact = success; exhaustion record = all presets tried, no success)

### branch (exploitation)
- **Definition:** A single exploitation attempt: one technique class applied to one finding, with one set of operator-supplied parameters. Persisted as a row in `exploitation_branches` in `validation.db`. Identified by a deterministic `exb_xxx` ID. A finding may have multiple branches (one per technique class applicable to it). A branch has exactly one terminal state: `succeeded` (artifact produced) or `exhausted` (preset exhausted, no artifact) or `failed` (error or cancelled).
- **Lives at:** `exploitation_branches` table in `validation.db`
- **NOT to be confused with:** finding (a finding is the input; a branch is an exploitation attempt against that finding)

### exhaustion
- **Definition:** Terminal branch state reached when an engine has tried every payload and wordlist in its preset without producing a positive result. Distinct from failure (failure = error; exhaustion = legitimate negative result). Exhaustion is the V2.1 handoff signal: the `ExhaustionRecord` written at exhaustion is what Qwen reads to suggest next steps.
- **NOT to be confused with:** failure (failure = error/crash; exhaustion = complete negative run), pending (pending = not yet started)

### exhaustion record
- **Definition:** Structured data emitted by an exploitation engine at Layer 3 when a preset is exhausted. Contains: technique class, engine identity, target identity, payloads/wordlists tried (with sources), detection method used, negative evidence (best attempt's response shape), finding context (evidence fields from the source finding), operator params supplied. Schema locked in V2 (Seam 14). V2.1 Qwen single-shot suggester reads this record as its primary input.
- **Schema:** `ExhaustionRecord` dataclass in `apps/conductor/engines/exploit_exhaustion.py`
- **NOT to be confused with:** artifact (artifact = success; exhaustion record = complete negative run)

### Layer 1 / Layer 2 / Layer 3
- **Definition:** Depth semantics of the V2 exploitation mindmap.
  - **Layer 1** — template node: arm/execute entry point. Shows finding evidence context on left; template form (technique-specific parameter fields) on right-side panel. Pre-execution state.
  - **Layer 2** — running node: in-progress state. Shows streaming engine output (stage events). Operator can cancel from here.
  - **Layer 3** — terminal node: either an artifact node (success, operator has output) or an exhaustion record node (complete negative run, V2.1 Qwen handoff). No node is created beyond Layer 3.
- **Design rationale:** Three levels because Layer 1 = operator intent, Layer 2 = system execution, Layer 3 = system output. A fourth level would require a new phase (which is V2.1+ Qwen scope, not V2 scope).

### preset
- **Definition:** An engine's bounded payload and wordlist set for one technique class. The preset is the complete set of inputs the engine will try before declaring exhaustion. Defined in `apps/conductor/engines/exploit_payloads.py`. Operator-configurable via the template form (operator can supply additional payloads that are unioned with the preset, not replacements). A finished preset always terminates in either an artifact or an exhaustion record — engines do not loop indefinitely.
- **NOT to be confused with:** wordlist (a wordlist is one input source within a preset; a preset may combine multiple wordlists and inline payloads)

### session pipe
- **Definition:** The `SessionOrchestrator`-owned `_API_AUTH_STORE` as a read interface for exploitation engines and future Qwen. Investigation-scoped: one auth store per active investigation. Engines call `session_store.get_auth(investigation_id)` to read it; they never write to it. Operator-driven refresh on expiration. The canonical single source of session truth — the duplicate `_API_AUTH_STORE` in `suggestions/probes.py` line 54 is retired in V2.4.
- **Lives at:** `apps/conductor/orchestrators/session.py` (`SessionOrchestrator`, line 57)
- **Seam:** Seam 15 (`/docs/architecture/seams.md`)

### template (exploitation)
- **Definition:** A per-technique form definition that the exploitation engine exposes via `capabilities.template_spec`. Contains: field name, type, label, default, required flag, and description for each operator-configurable parameter (wordlist selection, custom payload, path override, auth hint). The frontend renders the form dynamically from this spec at Layer 1. Each engine owns its own template — there is no universal form. Operator fills the form before arming.
- **NOT to be confused with:** probe (legacy term for pre-V2 exploitation functions in `suggestions/probes.py`), preset (preset is the engine's internal payload set; template is what the operator sees and fills)

---

## Domain terms

### adapter
- **Definition:** Thin subprocess or HTTP wrapper. Owns CLI flag construction, exit code checks, output parsing, and timeout handling. Does NOT own scope or policy decisions — those belong to the engine layer.
- **Lives at:** `apps/scanner_orchestration/adapters/` (nmap_adapter.py, nuclei_adapter.py, zap_adapter.py)
- **NOT to be confused with:** engine (adapter is called by engine; engine decides what to run and passes config down)

### chain dispatch / chain_depth / next_actions
- **Definition:** Engines emit `next_actions` on findings. Chain Orchestrator evaluates these and dispatches additional engines mid-phase. Dispatched engines are tagged `is_phase_initial=False` and do not block phase transitions.
- **chain_depth:** Linear depth per (investigation_id, root_finding_id), capped at 5. Cycle depth per (investigation_id, engine_id), capped at 3. Both gates are enforced independently.
- **next_actions format:** `list[{engine_id, action_kind, trigger, label, reason, has_input, ...}]`. `trigger` values: `auto_fire`, `operator_arm_required`, `operator_confirm_required`.
- **Lives at:** `apps/conductor/orchestrators/chain.py` (ChainOrchestrator)
- **NOT to be confused with:** phase-initial dispatch (Chain Orchestrator dispatch; does not block phase completion gate)

### conductor / Conductor
- **Definition:** Level 3 top coordinator. Knows nothing about individual engines. Receives operator intent, manages investigation lifecycle, instantiates and wires the five domain orchestrators. Emits `investigation_completed` and `investigation_failed` events.
- **Lives at:** `apps/conductor/conductor.py` (class `Conductor`, line 154)
- **NOT to be confused with:** orchestrator (Conductor is L3; orchestrators are L2)

### engine / engine_id
- **Definition:** Stateless L1 execution unit. Subclasses `Engine` ABC. Implements `run()`, `cancel()`, `health_check()`, `capabilities`. Never stores state across calls. Registered via `@engine_registry.register` at import time. Never visible to operator by name — operator sees findings.
- **Engine ABC lives at:** `apps/conductor/engines/base.py` (class `Engine`, line 105)
- **Examples:** NmapEngine, NucleiEngine, ZapEngine, PassiveProbeEngine, SshEngine, SqliReconEngine
- **NOT to be confused with:** adapter (engine owns policy; adapter is called by engine), probe (legacy term)

### enumeration_block_reason
- **Definition:** Text column on `normalized_findings` set when a rule signals `evidence_gap`. Records why the finding could not be classified. Surfaced in `/admin/enumeration-gaps` panel. System does NOT auto-enrich recon engines — operator reviews and decides.
- **Lives at:** `normalized_findings.enumeration_block_reason` column in `validation.db`

### evidence
- **Definition:** The `dict` carried on a finding record with observation data from the engine (e.g., api_recon `hit_paths: list[dict{path, status_code, content_type}]`, sqli_recon `detected_login_endpoints: list[dict{path, status_code, method}]`). Evidence shape is typed-list (not flat-list); backward-compat `isinstance(x, dict)` guards exist in aggregations.py for old records.
- **Critical:** Rules depend on per-item metadata inside evidence dicts. Regressing to flat lists breaks V1.7 rules.

### evidence_gap
- **Definition:** Signal from a rule that it would classify a finding but a required evidence field is absent. Returned via `RuleResult.evidence_gap(reason_text)`. NOT first-match-wins — the rule chain continues after an evidence_gap. FilterOrchestrator records the reason in `enumeration_block_reason`; finding stays `pending`.
- **Lives at:** `apps/conductor/rules/base.py` (`RuleResult.evidence_gap` classmethod, line 23)
- **NOT to be confused with:** a classification result (evidence_gap is informational; the finding keeps its prior status)

### FilterOrchestrator
- **Definition:** V1.7 orchestrator that runs after the enumeration phase. Two-pass design: (1) first pass applies `REGISTERED_RULES` (drop → validate → incomplete, first-match-wins); (2) re-invocation dispatch fires `REINVOCATION_RULES`, dedupes requests, dispatches engines via ExecutionOrchestrator; second pass filters new findings. DB writers must target `validation.db`, not `orchestration.db`.
- **Lives at:** `apps/conductor/orchestrators/filter.py` (class `FilterOrchestrator`, line 34)
- **Rules at:** `apps/conductor/rules/` (registry.py, drop_rules.py, validate_rules.py, incomplete_rules.py, reinvocation_rules.py)
- **Critical timing:** Must run after enumeration phase (not recon). Chain-dispatched engines (auth_recon, api_recon, sqli_recon) emit during enumeration; running after recon misses them (PR K bug).

### finding / FindingEvent
- **Definition:** Structured engine output. `FindingEvent` is the dataclass emitted by engines; carries `id`, `confidence`, `type`, `title`, `evidence`, `next_actions`, `source_scanner`. Findings Orchestrator deduplicates by `finding_id` (same ID on re-entry → update, new ID → insert).
- **Lives at:** `apps/investigation_workspace/probe/events.py` (class `FindingEvent`, line 33)

### finding_id
- **Definition:** Deterministic ID generated by `generate_finding_id()`. Format: `fnd_` + 12 hex chars (16 chars total). Same inputs always produce the same ID.
- **Lives at:** `apps/investigation_workspace/probe/finding_id.py`
- **Stored as:** `NormalizedFinding.finding_id` in `normalized_findings` table (`validation.db`)
- **Critical:** Must be passed explicitly as `finding_id=evt.id` when constructing `NormalizedFinding`. Default factory is `uuid4()`. If not passed, creates the two-parallel-ID-systems bug (PR L): FilterOrchestrator `UPDATE WHERE finding_id='fnd_xxx'` matches 0 rows silently.
- **NOT to be confused with:** `NormalizedFinding.id` (internal DB row id), `investigation_id`

### finding_type
- **Definition:** String category of a finding (e.g., `service_detected`, `vulnerability_confirmed`, `zap_endpoint_discovered`, `zap_alert`, `http_methods_advertised`). Declared in `engine.capabilities.finding_types`. Drives UI card routing in `_build_aggregations`.
- **Aggregation catch-all:** A catch-all card was added in PR D-fix for any `finding_type` not in the hardcoded whitelist. Do not rely on the whitelist being exhaustive when adding new engines.
- **Lives at:** `apps/scanner_orchestration/aggregations/aggregations.py`

### gate / gate_id
- **Definition:** Runtime feature flag controlling engine visibility and behavior. In-memory, reset on restart, thread-safe. Fail-closed: unknown `gate_id` blocks engine dispatch. Startup validation refuses to register engines with unknown `gate_id`. Multi-gate engines use `gate_ids: tuple[str, ...]`; an engine with both `gate_id` and `gate_ids` set is fail-closed.
- **Lives at:** `apps/conductor/gates.py`
- **API:** `get_gate(gate_id)`, `set_gate(gate_id, bool)`, `list_gates()`, `reset_all_gates_to_defaults()`, `engine_is_visible(engine)`
- **Admin UI:** `/admin/settings`

### investigation
- **Definition:** A single operator-initiated security assessment against one target. Lifecycle: `CREATED → RECON_RUNNING → RECON_COMPLETE → ENUM_RUNNING → ENUM_COMPLETE → EXPLOIT_RUNNING → EXPLOIT_COMPLETE → COMPLETED` (or `FAILED`/`CANCELLED`). Identified by `investigation_id`. All orchestrator state is scoped to one investigation.
- **Persisted in:** `orchestration.db` investigations table

### investigation_id
- **Definition:** UUID generated by `Conductor.start_investigation()`. Threads through all orchestrator calls, engine runs, events, and DB rows. Used as correlation ID for event tracing.

### max_chain_depth
- **Definition:** Config parameter (default 5) on `_run_all_probes_via_conductor` in runtime.py capping linear chain depth per branch. Separate from cycle depth (default 3). A value of 0 silently disables the Chain Orchestrator entirely (PR D-fix-2 lesson). Raise this when legitimate chains hit the cap; watch for runaway behavior as the signal to investigate cycle detection.

### NormalizedFinding
- **Definition:** SQLite ORM record in `normalized_findings` table in `validation.db`. Carries: `id`, `type`, `evidence`, `confidence`, `next_actions`, `source_scanner`, `validation_status`, `validation_reason`, `enumeration_block_reason`, `validated_at`, `superseded_by`.
- **Lives at:** `apps/scanner_orchestration/normalization/models.py` (class `NormalizedFinding`, line 12)
- **Repository:** `apps/scanner_orchestration/storage/finding_repo.py` (class `NormalizedFindingRepository`, line 35)

### orchestrators
- **PhaseOrchestrator** (`apps/conductor/orchestrators/phase.py`, line 41): State machine for phase transitions. Dispatches phase-initial engines. Blocks on phase-initial completion before advancing. Applies gate filter.
- **ExecutionOrchestrator** (`apps/conductor/orchestrators/execution.py`, line 45): Engine lifecycle, dispatch, concurrency policy, watchdog. Differentiates `_HUNG_THRESHOLD_HEAVY=600s` vs `_HUNG_THRESHOLD_LIGHT=30s` by `resource_cost`.
- **FindingsOrchestrator** (`apps/conductor/orchestrators/findings.py`, line 28): Single ingress for all findings. Deduplication, translation, correlation. Forwards to StorageBridge.
- **ChainOrchestrator** (`apps/conductor/orchestrators/chain.py`, line 26): Evaluates `next_actions`, enforces linear and cycle depth caps, dispatches chain engines via ExecutionOrchestrator.
- **SessionOrchestrator** (`apps/conductor/orchestrators/session.py`, line 57): `_API_AUTH_STORE`, rate limiting, target type detection. Session inheritance is non-negotiable — engines never re-authenticate.
- **FilterOrchestrator** (`apps/conductor/orchestrators/filter.py`, line 34): See entry above.

### phase (recon / enumeration / exploitation)
- **recon:** Passive discovery. Phase-initial engines: passive_probe, nmap. Produces raw finding pool.
- **enumeration:** Targeted probing within recon scope. Chain-dispatched: sqli_recon, auth_recon, api_recon, cmdi_recon, nuclei, zap, plugin engines. FilterOrchestrator runs after this phase completes.
- **exploitation:** Operator-driven or Qwen-suggested attacks. V2+; deferred.
- **Lives at:** `apps/conductor/orchestrators/phase.py` — `_PHASE_SEQUENCE = ("recon", "enumeration", "exploitation")`

### phase-initial / chain-dispatched
- **phase-initial:** Engine dispatched by PhaseOrchestrator at phase start. Tagged `is_phase_initial=True`. Phase completion gate counts only these.
- **chain-dispatched:** Engine spawned by ChainOrchestrator mid-phase via `next_actions`. Tagged `is_phase_initial=False`. Does not block phase transition.

### plugin
- **Definition:** Service-specific validation logic (ssh, telnet, smb, wordpress, drupal, apache, nginx). Subclasses `PluginEngine` which subclasses `Engine`. Wrapped as Conductor Engines in PR D.
- **Plugin logic lives at:** `apps/validation/plugins/` (ssh.py, wordpress.py, etc.)
- **Engine wrappers live at:** `apps/conductor/engines/` (ssh_engine.py, wordpress_engine.py, etc.)
- **PluginEngine base:** `apps/conductor/engines/plugin_base.py` (class `PluginEngine`, line 31)
- **NOT to be confused with:** adapter (plugin is a service-check; adapter is a subprocess/HTTP wrapper)

### probe
- **Definition:** Legacy term (pre-V1.6) for recon functions in `apps/investigation_workspace/probe/`. Post-V1.6, all are wrapped as Engine subclasses. The `probe/` directory still exists with underlying logic.
- **NOT to be confused with:** engine (current canonical term), adapter

### re-invocation / ReinvocationRequest
- **Definition:** V1.7 mechanism enabling FilterOrchestrator to dispatch additional engine runs after the first filtering pass. A reinvocation rule returns `list[ReinvocationRequest]` specifying which engine to re-run with what config override.
- **ReinvocationRequest fields:** `engine_id`, `config`, `source_finding_id`, `rule_id`
- **Deduplication:** `_dedup_requests()` dedupes by `(engine_id, config)` before dispatch.
- **Lives at:** `apps/conductor/rules/base.py` (class `ReinvocationRequest`, line 39); rules at `apps/conductor/rules/reinvocation_rules.py`

### rule / REGISTERED_RULES / RuleResult
- **Definition:** Python functions in `apps/conductor/rules/`. Protocol: `id`, `description`, `evaluate(finding, all_findings) → RuleResult`.
- **REGISTERED_RULES:** Evaluated first-match-wins across drop → validate → incomplete passes. Defined in `apps/conductor/rules/registry.py`.
- **REINVOCATION_RULES:** Evaluated separately after first pass to collect `ReinvocationRequest` objects. Defined in `apps/conductor/rules/reinvocation_rules.py`.
- **RuleResult:** Dataclass in `apps/conductor/rules/base.py`. `_evaluate()` in FilterOrchestrator returns a 4-tuple `(status, reason, gaps, block_reason)`. `evidence_gap` signals missing evidence — chain continues (not first-match-wins for gaps); first-match-wins applies only to the outer drop/validate/incomplete classification loop.
- **NOT YAML:** Rules are Python code; YAML would add loader/validator overhead without operator benefit at this stage.

### ScanExecution
- **Definition:** Legacy pre-Conductor model for one scanner run. `ScanExecution` records persist to `orchestration.db`. Lifecycle callback in runtime.py closes the row to `COMPLETED`/`FAILED` after `investigation_completed` event.
- **Lives at:** `apps/scanner_orchestration/execution/models.py` (class `ScanExecution`, line 21)
- **NOT to be confused with:** investigation (Conductor's model), engine run (Conductor's in-memory record)

### source_scanner
- **Definition:** Field on `NormalizedFinding` identifying which engine produced the finding. Set by `StorageBridge` from `finding["probe_id"]`. Critical for source-based queries. Bug history: PR D-fix-2 fixed StorageBridge hardcoding `"passive_probe"` for all engines.
- **Seam test:** `tests/conductor/_patterns/test_seam_attribution_preservation.py`

### StorageBridge
- **Definition:** Routes findings from Conductor's `FindingsOrchestrator` path (`FindingEvent`) to the legacy persistence path (`NormalizedFinding` → SQLite `validation.db`).
- **Lives at:** `apps/conductor/findings/storage_bridge.py` (class `StorageBridge`, line 18)
- **Critical line (PR L fix):** `_persist` must pass `finding_id=evt.id` (not default `uuid4()`) to `NormalizedFinding`.

### target / target_type
- **Definition:** `target` is the operator-supplied URL or IP. `target_type` is its classification: `local`, `private`, `external`, or `waf_fronted`. Classification drives concurrency limits, gate checks (nmap skips external unless `nmap_external_scan` gate ON), and session policy.
- **Classification lives at:** `apps/conductor/engines/target_classification.py` (`classify_target()`, line 21); called from `SessionOrchestrator.detect_target_type()`.

### validation_status (validated / dropped / incomplete / pending)
- **validated:** Verified worth exploit's time. Passed to exploitation phase. UI badge: green.
- **dropped:** Verified dead end. Hidden from operator UI by default (toggle shows them). Retained in DB for audit trail. UI badge: grey.
- **incomplete:** Worth exploit's time but missing data. Carries `enumeration_gaps` array describing what's missing. Handoff point for V2.x Qwen collaboration. UI badge: orange.
- **pending:** No rule has classified yet. Initial state. No badge.
- **Dominant status for group cards:** all-dropped → dropped; any-validated → validated; any-incomplete → incomplete; else pending. Logic in `aggregations.py` (`_dominant_validation()`).

### wordlist / wordlist_id / REGISTERED_WORDLISTS
- **Definition:** Named lists of credentials, paths, or payloads under `data/wordlists/`. Engines request them by stable ID via `load_entries(wordlist_id)`. Format-aware loader handles yaml, csv, txt transparently.
- **Registry lives at:** `apps/conductor/wordlists.py` (`REGISTERED_WORDLISTS` dict, line 35; `Wordlist` dataclass, line 26)
- **API:** `get_wordlist(wordlist_id)` returns metadata; `load_entries(wordlist_id)` returns parsed entries.

---

## Code formatting conventions

Observed in `apps/conductor/` (conductor.py, phase.py, gates.py, wordlists.py, nmap_engine.py, base.py, filter.py, rules/).

### Indentation
4 spaces per level (PEP 8). No tabs.

### Keyword argument alignment
Flush left at the function's indent level — no column alignment:
```python
def __init__(
    self,
    investigation_id: str,
    bus: EventBus,
    db_path: Path,
) -> None:
```

### String quotes
Double quotes preferred. Single quotes used sparingly (nested strings, error messages).

### Trailing commas
Always present in multi-line constructs (signatures, dict literals, tuples, lists):
```python
Gate(
    gate_id="nuclei_severity_info",
    description="...",
    default=True,
)
```

### Import ordering
stdlib → third-party → first-party (`apps.*`), blank line between groups, alphabetical within groups:
```python
import asyncio
import logging
from pathlib import Path

from apps.conductor.events.bus import EventBus
from apps.conductor.orchestrators.chain import ChainOrchestrator
```

### Type annotations
Present on all function signatures. Return type always annotated. Union types use `|` (Python 3.10+). `Optional[T]` written as `T | None`. `TYPE_CHECKING` guards used for circular import avoidance.

---

## Why this doc exists

The `probe → engine` transition and the `finding_id` two-parallel-ID bug (PR L) were both cases where imprecise terminology in prompts and documentation contributed to confusion and silent failure. Canonical definitions allow prompts to be short and precise: "the `finding_id` (`fnd_xxx` format) must survive from `FindingEvent` to `NormalizedFinding`" says more in fewer words than three paragraphs of explanation. When operator uses a non-canonical term, map it to canonical, confirm, then proceed — terminology drift is how architectural constraints get accidentally violated.
