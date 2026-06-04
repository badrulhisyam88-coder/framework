# Conductor Framework — Layer Contracts

**Productization baseline · Forked 2026-06-04**  
Source: `/home/unctad/projects/conductor-framework`  
Canonical seam names from: `docs/architecture/seams.md` · `docs/architecture/system.md`

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Layer 3 — Conductor](#2-layer-3--conductor)
3. [Layer 2 — Domain Orchestrators](#3-layer-2--domain-orchestrators)
   - 3.1 PhaseOrchestrator
   - 3.2 ExecutionOrchestrator & OutputChannel
   - 3.3 FindingsOrchestrator
   - 3.4 ChainOrchestrator
   - 3.5 SessionOrchestrator
   - 3.6 FilterOrchestrator
4. [Layer 1 — Engines](#4-layer-1--engines)
   - 4.1 Engine ABC & EngineCapabilities
   - 4.2 Representative Engine: CredentialBruteEngine
5. [Support Layer — Agent Loop](#5-support-layer--agent-loop)
   - 5.1 AgentState
   - 5.2 GraphResolver
   - 5.3 LeafEvaluator
   - 5.4 Planner
6. [Vault Pipeline](#6-vault-pipeline)
   - 6.1 QwenClient
   - 6.2 ContextBuilder
   - 6.3 VaultWriter
   - 6.4 VaultEmbedder
7. [Export Layer](#7-export-layer)
   - 7.1 VaultManager
   - 7.2 ExportService (investigation_core)
   - 7.3 ExporterService (exporters)
8. [Seam Inventory](#8-seam-inventory)
9. [Input / Output Summary](#9-input--output-summary)
10. [Database Map](#10-database-map)

---

## 1. Architecture Overview

The conductor-framework implements a **three-level orchestration** architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 3 — Conductor                                            │
│  conductor.py · _InvestigationContext                           │
│  Manages investigation lifecycle, wires all orchestrators       │
└──────────────────────────┬──────────────────────────────────────┘
                           │ wires 6 orchestrators
┌──────────────────────────▼──────────────────────────────────────┐
│  LAYER 2 — Domain Orchestrators                                 │
│  Phase · Execution · Findings · Chain · Session · Filter        │
│  Coordinate investigation phases; enforce seam contracts        │
└──────────────────────────┬──────────────────────────────────────┘
                           │ dispatches via OutputChannel
┌──────────────────────────▼──────────────────────────────────────┐
│  LAYER 1 — Stateless Engines                                    │
│  apps/conductor/engines/*.py  (9 exploitation + recon/enum)     │
│  Run(target, config, session, channel) → EngineResult           │
└─────────────────────────────────────────────────────────────────┘

Cross-cutting:
  Support Layer  →  AgentState · GraphResolver · LeafEvaluator · Planner
  Vault Pipeline →  QwenClient · ContextBuilder · VaultWriter · VaultEmbedder
  Export Layer   →  VaultManager · ExportService · ExporterService
```

**Phase sequence**: `recon → enumeration → exploitation`  
**Three-level rule**: No fourth orchestration level without explicit approval.  
**Operator drives**: Phase completions are operator-triggered, never auto-complete.

---

## 2. Layer 3 — Conductor

**File:** `apps/conductor/conductor.py`

### Class: `Conductor`

The top-level coordinator. Creates one `_InvestigationContext` per investigation, wires all six domain orchestrators, and manages state persistence in `data/orchestration.db`.

#### Constructor

```python
async def __init__(
    bus: EventBus | None = None,
    db_path: Path | None = None,
) -> None
```

| Parameter | Type | Default | Notes |
|-----------|------|---------|-------|
| `bus` | `EventBus \| None` | `_default_bus` | Module-level singleton |
| `db_path` | `Path \| None` | `data/orchestration.db` | SQLite investigation store |

#### Public Methods

```python
async def start_investigation(
    target: str,
    config: dict,
    storage_bridge=None,
    investigation_id: str | None = None,
) -> str
```

| | |
|---|---|
| **Inputs** | target URL, config dict, optional StorageBridge, optional investigation_id |
| **Output** | `investigation_id` (string) |
| **Writes** | `investigations` table (state=CREATED) |
| **Seams** | Seam 24 — when `investigation_id` provided, becomes key in `_active` dict |
| **Side-effect** | Fires `_run_phases()` as background task |

---

```python
async def cancel_investigation(investigation_id: str) -> None
async def get_investigation_status(investigation_id: str) -> dict
async def list_active_investigations() -> list[dict]
async def operator_complete_exploitation(investigation_id: str) -> bool
def refresh_target_auth(target_base: str, auth: dict) -> int
def get_context(investigation_id: str) -> _InvestigationContext | None
```

#### Investigation State Machine

```
start_investigation()
  │
  ▼  CREATED
_run_phases()
  │
  ├─ RECON_RUNNING  → phase_orch.start_next_phase() → engines dispatched
  │                   wait phase_completed event (timeout 300s)
  │
  ├─ ENUM_RUNNING   → same as above
  │                   AFTER enumeration: filter_orch.run_filter()
  │
  ├─ EXPLOIT_RUNNING → operator-driven completion only (Seam C3)
  │
  └─ COMPLETED / FAILED / CANCELLED
```

### Internal: `_InvestigationContext`

**Responsibility**: Runtime container — holds all six orchestrators for one active investigation.

**Orchestrators instantiated**: SessionOrchestrator, FindingsOrchestrator, ChainOrchestrator, ExecutionOrchestrator, PhaseOrchestrator, FilterOrchestrator.

**Wiring graph** (constructor, lines 101–136):

```
findings_orch ──wire_chain──────────────► chain_orch
chain_orch    ──wire_execution──────────► exec_orch
chain_orch    ──wire_session────────────► session_orch
exec_orch     ──wire_findings──────────► findings_orch
exec_orch     ──wire_session────────────► session_orch
exec_orch     ──wire_phase─────────────► phase_orch
phase_orch    ──wire_execution──────────► exec_orch
filter_orch   ──wire_findings──────────► findings_orch
filter_orch   ──wire_reinvocation_dispatcher()
filter_orch   ──wire_db_writer()        → validation.db  ← Seam 3
filter_orch   ──wire_block_reason_writer() → validation.db
```

**Seam 3 closure** (lazy DB_PATH import, inside constructor closure):
- Target: `validation.db` via `NormalizedFindingRepository`
- Guard: import is inside the closure body to prevent accidental `orchestration.db` capture

---

## 3. Layer 2 — Domain Orchestrators

### 3.1 PhaseOrchestrator

**File:** `apps/conductor/orchestrators/phase.py`

```python
async def start_next_phase() -> str | None
def current_phase(investigation_id: str) -> str
async def operator_complete_exploitation() -> None
```

| Method | Input | Output | Seam |
|--------|-------|--------|------|
| `start_next_phase()` | — | phase name or `None` | Seam 19 |
| `current_phase()` | investigation_id | `"recon" \| "enumeration" \| "exploitation" \| "complete"` | — |
| `operator_complete_exploitation()` | — | — | Seam C3 |

**Phase sequence constant**: `_PHASE_SEQUENCE = ["recon", "enumeration", "exploitation"]`

**Events emitted**: `phase_started`, `phase_completed`, `phase_failed`

---

### 3.2 ExecutionOrchestrator & OutputChannel

**File:** `apps/conductor/orchestrators/execution.py`

```python
async def dispatch_phase(phase: str) -> None
async def dispatch_engine(engine_id: str, extra_config: dict | None = None) -> str
async def cancel_all(investigation_id: str) -> None
def running_engines(investigation_id: str) -> list[dict]
```

**Watchdog thresholds** (Seam 9):

| `resource_cost` | Threshold |
|-----------------|-----------|
| `"light"` | 30 s |
| `"medium"` | 120 s |
| `"heavy"` | 600 s |

#### OutputChannel

Constructed before each `engine.run()` call. The single ingress point for all engine output (Seam 8).

```python
# Construction (inside ExecutionOrchestrator._launch)
channel = OutputChannel(
    investigation_id=investigation_id,
    engine_id=engine_id,
    findings_orch=self._findings_orch,
    session_orch=self._session_orch,
    branch_writer=self._branch_writer,
)
```

**OutputChannel public methods**:

| Method | Input | Effect | Seam |
|--------|-------|--------|------|
| `emit_finding(finding)` | finding dict | → FindingsOrchestrator.ingest() | Seam 8 |
| `record_request(target)` | URL | → SessionOrchestrator.record_request() | — |
| `record_response(target, status_code)` | URL, int | 429 detection + cooldown | — |
| `create_branch(branch_id, finding_id, technique_class, operator_params)` | — | Creates `exploitation_branches` record | Seam 13 |
| `emit_stage(branch_id, state, payload)` | — | Updates branch state + stage_log | Seam 13 |
| `store_auth(investigation_id, auth)` | investigation_id, dict | → SessionOrchestrator.store_auth() | Seam 20 |

**Branch state machine** (emit_stage, Seam 13 — unidirectional):
```
pending → armed → running → succeeded
                          → exhausted
                          → failed
                          → cancelled
```

---

### 3.3 FindingsOrchestrator

**File:** `apps/conductor/orchestrators/findings.py`

```python
async def ingest(finding: dict, engine_id: str) -> str | None
```

| | |
|---|---|
| **Input** | finding dict from OutputChannel, engine_id |
| **Output** | `finding_id` if new/updated, `None` if exact duplicate |
| **Algorithm** | translate → dedup by finding_id → merge evidence or insert → evaluate next_actions |
| **Events** | `finding_created`, `finding_updated`, `finding_correlated` |
| **Seam 8** | Single ingress — findings never bypass this orchestrator |

**Finding dict required keys**: `id` (fnd_xxx), `category`, `title`, `severity`, `evidence`, `probe_id`, `phase`

---

### 3.4 ChainOrchestrator

**File:** `apps/conductor/orchestrators/chain.py`

```python
async def evaluate_finding(investigation_id: str, finding: dict) -> None
async def operator_arm(investigation_id: str, action_id: str) -> None
def chain_depth(investigation_id: str, branch_id: str) -> int
```

**Chain depth limits**: linear depth ≤ 5; per-engine dispatch count ≤ 3 (cycle guard).

**Events emitted**: `chain_auto_fired`, `chain_depth_limit_reached`, `chain_operator_arm_pending`, `chain_edge`

---

### 3.5 SessionOrchestrator

**File:** `apps/conductor/orchestrators/session.py`

```python
def get_auth(investigation_id: str) -> dict | None
def can_dispatch(target, engine_capabilities) -> tuple[bool, float]
def record_request(target: str) -> None
def record_response(target: str, status_code: int) -> None
def store_target_auth(target_base: str, auth: dict) -> None
def store_auth(investigation_id: str, auth: dict) -> None
```

**Seam 15**: Per-investigation auth store. No process-level store. `INVESTIGATION_ID_CTX` context var used by ACTIVE-LEGACY probes.

---

### 3.6 FilterOrchestrator

**File:** `apps/conductor/orchestrators/filter.py`

```python
async def run_filter(investigation_id: str) -> None
```

**Timing**: Called by Conductor **after enumeration completes** — not after recon (Seam 3 invariant).

**Two-pass algorithm**:
1. REGISTERED_RULES — drop / validate / incomplete, first-match-wins per finding
2. REINVOCATION_RULES — collect results, deduplicate, dispatch engines

**Wired callbacks** (set in `_InvestigationContext.__init__`):

```python
wire_db_writer(async callable(finding_id, status, reason, gaps_json, validated_at))
# → writes normalized_findings.validation_status  (validation.db, Seam 3)

wire_block_reason_writer(async callable(finding_id, reason))
# → writes normalized_findings.enumeration_block_reason  (validation.db)

wire_reinvocation_dispatcher(async callable(engine_id, config))
# → dispatches via ExecutionOrchestrator
```

---

## 4. Layer 1 — Engines

### 4.1 Engine ABC & EngineCapabilities

**File:** `apps/conductor/engines/base.py`

```python
class Engine(ABC):
    @property
    @abstractmethod
    def capabilities(self) -> EngineCapabilities: ...

    @abstractmethod
    async def run(
        self,
        target: str,
        config: dict,
        session_store: SessionStore,
        output_channel: OutputChannel,
    ) -> EngineResult: ...

    @abstractmethod
    async def cancel(self) -> None: ...

    @abstractmethod
    def health_check(self) -> EngineHealth: ...
```

#### EngineCapabilities (frozen dataclass)

| Field | Type | Values |
|-------|------|--------|
| `phases` | `tuple[str, ...]` | `("recon",)` · `("enumeration",)` · `("exploitation",)` |
| `finding_types` | `tuple[str, ...]` | e.g. `("login_form_detected", "api_exposure")` |
| `target_types` | `tuple[str, ...]` | `("http",)` · `("tcp",)` · `("any",)` |
| `resource_cost` | `str` | `"light"` · `"medium"` · `"heavy"` |
| `concurrency_safe_with` | `tuple[str, ...]` | engine_ids safe to co-run |
| `mutex_with` | `tuple[str, ...]` | engine_ids that must not co-run |

#### EngineResult

```python
@dataclass
class EngineResult:
    status: str          # "success" | "failed" | "cancelled"
    findings_count: int
    error: str | None
```

#### Engine Conformance Rules

1. **Stateless across runs** — no instance variables persist between invocations
2. **Auth read-only** — never call login endpoints; read from `session_store`
3. **Stream findings immediately** — call `output_channel.emit_finding()` as they emerge
4. **Respect `cancel()` within 5 s** — kill subprocesses, close sockets
5. **Declare capabilities truthfully** — concurrency and phase fields are enforced
6. **Never create asyncio primitives in `__init__`** — bind event loop inside `run()`
7. **Seam 16** — accept `extended_payloads` and `extended_wordlists` kwargs in `run()`

#### V2 Engine Inventory

| Engine | File | Phase | resource_cost |
|--------|------|-------|---------------|
| CredentialBruteEngine | `credential_brute_engine.py` | exploitation | medium |
| XssReflectedEngine | `xss_reflected_engine.py` | exploitation | light |
| CmdiReflectedEngine | `cmdi_reflected_engine.py` | exploitation | light |
| CmdiBlindTimeEngine | `cmdi_blind_time_engine.py` | exploitation | medium |
| CmdiBlindBooleanEngine | `cmdi_blind_boolean_engine.py` | exploitation | medium |
| SqliAuthBypassEngine | `sqli_auth_bypass_engine.py` | exploitation | medium |
| DefaultCredsEngine | `default_creds_engine.py` | exploitation | medium |
| AccessControlEngine | `access_control_engine.py` | exploitation | medium |
| MetasploitRecipeEngine | `metasploit_recipe_engine.py` | exploitation | heavy |
| JSSpiderEngine | `js_spider_engine.py` | enumeration | light |

---

### 4.2 Representative Engine: CredentialBruteEngine

**File:** `apps/conductor/engines/credential_brute_engine.py`

```python
async def run(
    target: str,
    config: dict,
    session_store: SessionStore,
    output_channel: OutputChannel,
    *,
    extended_payloads: list | None = None,   # Seam 16 stub
    extended_wordlists: list | None = None,  # Seam 16 stub
) -> EngineResult
```

**Key behaviors**:
- Reads `login_form_detected` findings (validated/incomplete status only — Seam 12)
- Loads credential pairs from payload registry YAML
- Refreshes CSRF token per-request from `finding.evidence["csrf_field"]`
- On success: `output_channel.store_auth(investigation_id, captured_session)` — Seam 20
- On exhaustion: `output_channel.emit_stage("exhausted", payload={...})` → ExhaustionRecord — Seam 14

---

## 5. Support Layer — Agent Loop

### 5.1 AgentState

**File:** `apps/conductor/agent_state.py`

The persistent investigation reasoning state. Tracks facts, artifacts, pending work queue, and current position.

#### Schema

```python
{
    "goal": {
        "objective": str,
        "success_conditions": list[str],
        "provided_self_user": str | None,
        "target_user": str | None,
    },
    "facts": list[str],
    "artifacts": {
        "credentials": list[dict],
        "sessions": list[dict],
        "tokens": list[dict],
        "files": list[dict],
    },
    "pending": list[{"concept": str, "priority": int}],
    "ruled_out": list[str],
    "completed": list[str],
    "current_position": {
        "authentication": "none" | "authenticated" | "admin",
        "privilege": "none" | "user" | "admin" | "root",
        "execution": "none" | "file_read" | "rce",
        "access_scope": list[str],
    },
    "solved": bool,
    "solved_reason": str,
    "planner_log": list[dict],
    "interrogation_attempts": int,
    "interrogation_log": list,
}
```

#### Persistence API

```python
async def init_agent_state_async(investigation_id, target, objective) -> dict
async def load_agent_state_async(investigation_id: str) -> dict
async def save_agent_state_async(investigation_id: str, agent_state: dict) -> None
async def apply_verdict_to_state_async(
    investigation_id: str,
    verdict: Verdict,
    concept_id: str = "",
    engine_id: str = "",
    exec_state: str = "",
) -> None
```

**`apply_verdict_to_state_async`**:
- Concurrency-safe via per-investigation `asyncio.Lock`
- Updates: facts, artifacts, pending (add unlocks, remove rules_out), completed, current_position
- Calls `check_success()` → sets `solved=True` if goal condition met

**Environment**: `KNOWLEDGE_VAULT_PATH` (default: `/app/knowledge-vault`)

---

### 5.2 GraphResolver

**File:** `apps/conductor/graph_resolver.py`

```python
def resolve_branches(
    finding_type: str,
    satisfied_preconditions: set[str] | None = None,
    enrich_from_manifest: bool = True,
) -> list[BranchSpec]
```

| | |
|---|---|
| **Input** | `finding_type` (e.g. `"login_form_detected"`) |
| **Output** | `list[BranchSpec]` — sorted: executable first, NONE-YET last |
| **Reads** | `KNOWLEDGE_VAULT_PATH/concepts/*.md` (parsed at startup, cached) |

#### BranchSpec fields

| Field | Type | Description |
|-------|------|-------------|
| `concept_id` | str | e.g. `CONCEPT-CREDENTIAL-BRUTE` |
| `engine_id` | `str \| None` | dispatch key (None for NONE-YET) |
| `executable` | bool | False = documented but no implementation |
| `grows_from` | `list[str]` | trigger finding_types |
| `leaf_type` | str | `"terminal"` · `"can_be_blocked"` · `"unknown"` |
| `stem_engines` | `list[dict]` | Phase 4 fallback engines |
| `preconditions` | tuple | position/goal preconditions |

---

### 5.3 LeafEvaluator

**File:** `apps/conductor/leaf_evaluator.py`

```python
def evaluate_leaf(
    engine_id: str,
    concept_id: str,
    artifact: dict | None,
    state: str,
    finding_id: str = "",
) -> LeafClassification

def evaluate_verdict(
    engine_id: str,
    concept_id: str,
    artifact: dict | None,
    state: str,
    finding_id: str = "",
) -> Verdict
```

**LeafClassification kinds**: `"terminal"` · `"blocked"` · `"none_yet"` · `"inconclusive"`

**Verdict fields**: `match_kind`, `goal_advanced`, `state_changes`, `artifacts_captured`, `unlocks`, `rules_out`

**Evaluation algorithm**:
1. Fast path: `_is_solved(artifact)` → TERMINAL
2. RAG path: read `leaf_type` from graph
   - `"terminal"` → TERMINAL
   - `"can_be_blocked"` + exhausted/timeout/failed → BLOCKED (grow stem)
   - Otherwise → INCONCLUSIVE

---

### 5.4 Planner

**File:** `apps/conductor/planner.py`

```python
def plan_next_step(agent_state: dict) -> PlannerDecision
```

**PlannerDecision fields**: `action`, `concept_id`, `engine_id`, `priority`, `reason`, `log_entry`

**Action values**: `"execute"` · `"sweep"` · `"stuck"` · `"park"` · `"solved"`

**Algorithm**:
1. If `agent_state["solved"]` → SOLVED
2. Filter `pending` − `ruled_out` − `completed`
3. Filter unmet preconditions (position + goal)
4. Reachable items → EXECUTE highest-priority
5. Only blocked items → SWEEP
6. Nothing → STUCK

---

## 6. Vault Pipeline

**Environment variable**: `KNOWLEDGE_VAULT_PATH` (all components)  
**Docker default**: `/app/knowledge-vault`  
**Host default (new folder)**: `/home/unctad/projects/conductor-framework/knowledge-vault`

### 6.1 QwenClient

**File:** `apps/conductor/qwen/client.py`

```python
async def chat(messages: list[dict], tools: list | None, timeout: int = 30) -> dict
async def ping() -> bool
async def ping_details() -> dict
```

| | |
|---|---|
| **Config** | `OLLAMA_BASE_URL` env var (default: `http://localhost:11434`) |
| **Model** | `qwen2.5:7b-instruct` |
| **Errors** | `QwenUnavailableError`, `QwenTimeoutError` |
| **`ping()`** | Never raises — returns False on any error |

---

### 6.2 ContextBuilder

**File:** `apps/conductor/qwen/context_builder.py`

```python
async def build_investigation_context(
    investigation_id: str,
    target: str = "",
    max_findings: int = 25,
) -> str
```

**Context sections** (all graceful — section omitted on error):

| Section | Source | Timeout |
|---------|--------|---------|
| Findings Summary | `validation.db` normalized_findings | — |
| API Schema (V2.6) | `GET /openapi.json` on target | 5 s |
| Product Catalog (V2.6) | `GET /api/products` on target (with session cookies) | 5 s |
| Vault Context (V2.7) | `KNOWLEDGE_VAULT_PATH/findings/ + /labs/` tag search | — |

---

### 6.3 VaultWriter

**File:** `apps/conductor/qwen/vault_writer.py`

```python
async def export_finding(finding_id, engine_id, finding, artifact, target, investigation_id) -> str | None
async def export_lab_walkthrough(investigation_id, target, findings, artifact) -> str | None
async def export_failure(investigation_id, engine_id, finding, exhaustion, error) -> str | None
```

| Method | Writes to | Format |
|--------|-----------|--------|
| `export_finding` | `KNOWLEDGE_VAULT_PATH/findings/web/FIND-WEB-YYYYMMDD-NNN.md` | OWASP/MITRE tagged markdown |
| `export_lab_walkthrough` | `KNOWLEDGE_VAULT_PATH/labs/web/LAB-WEB-YYYYMMDD-NNN.md` | Lab walkthrough |
| `export_failure` | `KNOWLEDGE_VAULT_PATH/findings/web/FAIL-WEB-YYYYMMDD-NNN.md` | Failure + exhaustion record |

**Threading**: all operations fire-and-forget via `asyncio.create_task()`.  
**Sequential ID**: `_seq_lock` (threading.Lock) ensures no ID collisions.  
**Never raises** — errors logged silently.

---

### 6.4 VaultEmbedder

**File:** `apps/conductor/qwen/vault_embedder.py`

```python
async def rebuild_index() -> None
async def search_by_tags(tags: list[str], top_k: int = 10) -> list[dict]
async def search_semantic(query: str, top_k: int = 10) -> list[dict]
```

**Fallback chain**:
```
ChromaDB + Ollama nomic-embed-text
    ↓ (unavailable)
TF-IDF similarity
    ↓ (error)
Empty results []
```

**`rebuild_index()`** scans: `concepts/` · `findings/web/` · `labs/web/`  
**`search_semantic()`** applies reranker (qwen3-reranker:0.6B if in Ollama registry; fallback to embedding order).

---

## 7. Export Layer

### 7.1 VaultManager

**File:** `apps/investigation_core/exports/vault/vault_manager.py`

```python
class VaultManager:
    @property
    def root(self) -> Path

    def investigation_dir(investigation_id: str) -> Path
    def investigation_report_path(investigation_id: str, target: str) -> Path
    def ensure_investigation_dir(investigation_id: str) -> Path
    def campaign_dir(campaign_id: str) -> Path
    def campaign_synthesis_path(campaign_id: str, title: str) -> Path
    def ensure_campaign_dir(campaign_id: str) -> Path
    def vault_relative(absolute: Path) -> str
```

**Path resolution**:
- Root: `KNOWLEDGE_VAULT_PATH` env var **or** `<repo_root>/knowledge-vault`
- Investigation dir: `{root}/investigations/{id[:8]}/`
- Campaign dir: `{root}/campaigns/{id[:8]}/`

---

### 7.2 ExportService (investigation_core)

**File:** `apps/investigation_core/exports/services/export_service.py`

```python
async def generate_export(
    investigation_id: str,
    target: str,
    findings: list[Any],
    evidence: list[Any],
    guided_action_objects: list[Any] | None = None,
) -> ExportRecord
```

**Reads**: orchestration.db, timeline events, mastery records, knowledge vault  
**Writes**: VaultManager investigation_dir (markdown files)  
**Returns**: `ExportRecord` with file paths + errors list

---

### 7.3 ExporterService (exporters)

**File:** `exporters/exporter_service.py`

```python
class ExportBatch:
    findings: list[Finding]
    hosts: dict[str, Host]
    services: dict[str, Service]
    cves: dict[str, CVE]

class ExportReport:
    findings_written: list[Path]
    remediations_written: list[Path]
    discovery_written: list[Path]
    chains_written: list[Path]
    errors: list[str]

class ExporterService:
    def __init__(self, vault_path: Path | None = None) -> None
    def export_findings(batch: ExportBatch, export_remediations: bool = True) -> ExportReport
```

---

## 8. Seam Inventory

All seams defined in `docs/architecture/seams.md`. Regression tests in `tests/conductor/_patterns/`.

| # | Contract | Guard | Pattern test |
|---|----------|-------|--------------|
| 1 | Finding ID round-trip: `evt.id → normalized_findings.finding_id` | Explicit `finding_id=evt.id` pass | test_seam_identity_roundtrip |
| 2 | Finding ID determinism: `SHA256(probe_id|target|path|type)[:12]` | `generate_finding_id()` | test_seam_identity_roundtrip |
| 3 | DB target: FilterOrchestrator writes to `validation.db` (not `orchestration.db`) | Lazy `DB_PATH` import inside closure | test_seam_db_target_consistency |
| 4 | Attribution: `probe_id → source_scanner` (not hardcoded) | StorageBridge reads finding dict | test_seam_attribution_preservation |
| 5 | Gate registry: `engine.gate_id` must exist in `REGISTERED_GATES` | `engine_is_visible()` fail-closed | test_seam_adapter_contract |
| 6 | RuleResult protocol: matched, status, reason, gaps, is_evidence_gap fields | RuleResult dataclass | test_seam_rule_chain_evidence_gap |
| 7 | Wordlist registry: engines use `load_entries(wordlist_id)`, never open files | `WordlistNotFoundError` on unknown ID | (integration coverage) |
| 8 | OutputChannel: engine output through `emit_finding()`, never DB direct | Single ingress principle | test_seam_output_channel |
| 9 | Watchdog: threshold from `resource_cost` at dispatch time | Threshold selection in `_launch()` | test_seam_resource_policy |
| 10 | Event bus: orchestrators emit via `bus.emit()`, no external broker | EventBus singleton | (integration coverage) |
| 11 | Audit log: events → `orchestration_audit.jsonl` | NOT YET WIRED — deferred | (deferred) |
| 12 | Filter→Exploit: only validated/incomplete findings dispatched | `_has_v2_engine` filter in topology | test_seam_v2_enum_to_exploit_input |
| 13 | Branch persistence: deterministic `branch_id`, state unidirectional | `exploitation_branches` table | test_seam_v2_branch_persistence |
| 14 | Exhaustion handoff: ExhaustionRecord schema locked V2→V2.1 | Schema in leaf_evaluator.py | test_seam_v2_exhaustion_record |
| 15 | Session pipe: per-investigation `SessionOrchestrator`, no re-auth | `INVESTIGATION_ID_CTX` in runtime.py | test_seam_session_pipe |
| 16 | Re-invocation stub: `extended_payloads`, `extended_wordlists` kwargs in all 9 `run()` | All engines accept stubs | test_seam_v2_reinvocation_hook |
| 17 | Feedback hook: `template_spec.feedback_hook` stub (no-op V2) | V2.1 renders control | test_seam_v2_feedback_hook |
| 18 | RAG injection: `_inject_rag_context(finding, template_spec) → template_spec` | Pure function, no side effects | test_seam_v2_rag_injection |
| 19 | Bootstrap phase state: PhasedRun fields ↔ `PhaseOrchestrator._PHASE_SEQUENCE` | `is_exploitation_active()` predicate | test_seam_bootstrap_phase_state |
| 20 | Engine auth write-back: `output_channel.store_auth()` → SessionOrchestrator | Credential engines call `store_auth` | test_seam_engine_auth_write |
| 21 | MSF recipe lookup: `service_name → RECIPES` key deterministically | `lookup_recipe_key()` pure function | test_seam_msf_recipe_lookup |
| 22 | Exploitation mindmap panel: `_branchMap` from `/exploitation-data.json` only | No secondary server fetch in panel | test_seam_panel_data_source |
| 23 | Engine topology registration: `SuggestionSpec.engine_id` matches registry | Execute route calls `dispatch_engine` | test_seam_v2_engine_topology_registration |
| 24 | Conductor ID alignment: `start_investigation(investigation_id=workspace_uuid)` | `_active[investigation_id]` keyed correctly | test_seam_conductor_workspace_id_alignment |

---

## 9. Input / Output Summary

### Layer 3

| Component | Inputs | Outputs | Reads | Writes |
|-----------|--------|---------|-------|--------|
| Conductor | target, config, investigation_id | investigation_id (str) | `orchestration.db` | `orchestration.db` (investigations) |
| _InvestigationContext | investigation_id, target, config, bus, db_path | context object | — | wires 6 orchestrators |

### Layer 2

| Component | Inputs | Outputs | Reads | Writes |
|-----------|--------|---------|-------|--------|
| PhaseOrchestrator | — | phase name or None | phase state | `orchestration.db` phase state |
| ExecutionOrchestrator | engine_id, target, config | run_id (str) | engine registry | `_running` dict |
| OutputChannel | finding dict, target, status, auth | — | session_store | FindingsOrch, SessionOrch, BranchWriter |
| FindingsOrchestrator | finding dict, engine_id | finding_id or None | findings store | deduplicated findings, events |
| ChainOrchestrator | finding dict | — | next_actions | chain events, `orchestration.db` |
| SessionOrchestrator | target, engine_caps, auth dict | (bool, float) | `_api_auth_store` | `_api_auth_store` |
| FilterOrchestrator | — | — | `validation.db` normalized_findings | `validation.db` (validation_status, block_reason) |

### Layer 1

| Component | Inputs | Outputs | Reads | Writes |
|-----------|--------|---------|-------|--------|
| Engine.run() | target, config, session_store, output_channel | EngineResult | session_store, external APIs | output_channel (findings, branches, auth) |

### Vault Pipeline

| Component | Inputs | Outputs | Reads | Writes |
|-----------|--------|---------|-------|--------|
| QwenClient.chat() | messages, tools, timeout | response dict | Ollama API | — |
| ContextBuilder | investigation_id, target | context string | `validation.db`, target APIs, vault | — |
| VaultWriter | finding/artifact data | file path or None | engine metadata | `KNOWLEDGE_VAULT_PATH/findings/` `labs/` |
| VaultEmbedder | tags or query, top_k | `list[dict]` | vault .md files, ChromaDB | ChromaDB (on rebuild) |

---

## 10. Database Map

| Database | Location | Owner | Tables (key) |
|----------|----------|-------|--------------|
| `validation.db` | `data/validation.db` | apps.validation | `normalized_findings`, `exploitation_branches`, `investigations` (workspace layer) |
| `orchestration.db` | `data/orchestration.db` | Conductor | `investigations`, `investigation_state`, `orchestration_events` |

**Seam 3 invariant**: FilterOrchestrator DB writers **must** target `validation.db`. Lazy import inside closure prevents accidental `orchestration.db` capture.

**Seam 13 invariant**: `exploitation_branches` lives in `validation.db`. Written by BranchWriter (wired in ExecutionOrchestrator.__init__). Branch state transitions unidirectional.

---

*Generated 2026-06-04 from conductor-framework productization fork.*
