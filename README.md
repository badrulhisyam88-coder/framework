# conductor-framework

A framework for building **deterministic agentic systems** that know when to
call an LLM and when not to. Domain-specific content is loaded from a
knowledge vault — not baked into prompts.

---

## Core idea

Most agentic systems use an LLM to decide what to do next. This framework
inverts that: a **deterministic planner** selects the next action from a
ranked pending queue. The LLM (optional, via Qwen/Ollama) handles only the
cases the planner cannot classify — high-similarity vault matches, success
verification, and failure diagnosis.

**Key properties**:
- Single selection authority: the Planner owns next-step decisions. No
  engine, orchestrator, or LLM can bypass it.
- Vault-driven routing: domain knowledge lives in `knowledge-vault/concepts/`
  as structured markdown. The graph resolver reads vault files to decide which
  techniques apply to a given finding type.
- Inquiry layer: pre-flight detection (detect before acting), success
  precision (verify before claiming solved), failure interrogation (diagnose
  before giving up) — all governed by vault concepts.
- Approval gates: every action passes through an Arm → Execute flow.
  The operator approves each step; the framework enforces it.

---

## Architecture

```
Conductor (Layer 3)
  └─ _InvestigationContext
       ├─ PhaseOrchestrator       phase state machine (recon → enum → exploit)
       ├─ ExecutionOrchestrator   engine lifecycle + OutputChannel
       ├─ FindingsOrchestrator    dedup + translation
       ├─ ChainOrchestrator       next_action routing + depth capping
       ├─ SessionOrchestrator     per-investigation auth store + rate limits
       └─ FilterOrchestrator      rule evaluation after enumeration

Engines (Layer 1)
  └─ Engine ABC  →  run(target, config, session_store, output_channel)
       OutputChannel: emit_finding() · create_branch() · store_auth()

Support
  ├─ AgentState    persistent investigation reasoning state
  ├─ GraphResolver vault-driven concept selection per finding_type
  ├─ LeafEvaluator terminal / blocked / none-yet classification
  └─ Planner       deterministic next-step selection

Vault Pipeline
  ├─ VaultWriter    writes findings/labs/failures to knowledge-vault/
  ├─ VaultEmbedder  ChromaDB + TF-IDF semantic search over vault
  └─ ContextBuilder assembles Qwen context from findings + vault
```

Full contract specification: `docs/productization/layer-contracts.md`

---

## Getting started

### 1. Add a concept

Copy `knowledge-vault/concepts/concept-example.md`, rename it, and fill in
all frontmatter fields. The `finding_types` field controls which findings
surface this concept via GraphResolver. The `priority` field controls planner
ranking.

### 2. Add an engine

Copy `examples/example_engine.py`, rename the class and `engine_id`, and
implement `run()` with your domain logic. Import the module in
`apps/conductor/engines/__init__.py` so it registers at startup.

### 3. Wire the concept to the engine

Add one entry to `apps/conductor/constants.py::CONCEPT_ENGINE_MAP`:

```python
CONCEPT_ENGINE_MAP = {
    "CONCEPT-MY-THING": "my_engine_id",
}
```

### 4. Run

```bash
docker compose up
# POST http://localhost:8000/api/v1/investigations
# { "target": "...", "config": {} }
```

---

## Reference

| File | Purpose |
|---|---|
| `docs/productization/layer-contracts.md` | Full architecture + interface spec |
| `examples/example_engine.py` | Minimal Engine ABC implementation |
| `knowledge-vault/concepts/concept-example.md` | Vault concept schema reference |
| `apps/conductor/constants.py` | Domain mapping tables (populate these) |
| `apps/conductor/planner.py` | Planner precondition tables |

**Reference implementation**: the original `ai-assist-tool` repo applies this
framework to security investigation. Consult it to see every layer in
production use.

---

Forked from `ai-assist-tool` + `knowledge-vault` on 2026-06-04.
Stripped to bare framework template on 2026-06-04.
