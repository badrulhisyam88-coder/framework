# Agent Loop Architecture

**Platform**: AI-powered security investigation workbench  
**Stack**: FastAPI · Jinja2 · htmx · Preact · React Flow · SQLite · ChromaDB · Ollama (Qwen)

---

## High-Level Overview

```
Operator
  │ open investigation → recon → enumeration → exploitation
  ▼
Planner (deterministic, priority-ranked)
  │ reads STATE → picks next technique
  ▼
Engine (credential_brute / username_enum / counter_reset / probe / …)
  │ executes, emits artifact
  ▼
Verdict wire → STATE update → Success check
  │
  ├─ SOLVED → surface in Zone A + Zone C
  └─ not solved → planner continues
```

---

## Core Components

| Component | Role |
|---|---|
| **Planner** (`planner.py`) | Deterministic step selection: pops highest-priority pending concept; sweeps or parks when no reachable lead |
| **ENGINE** (`engines/`) | Executes a single technique: brute, timing enum, pre-flight probe, counter-reset, etc. Emits findings + artifacts |
| **STATE** (`agent_state.py`) | Per-investigation memory: `goal`, `facts`, `artifacts`, `pending`, `completed`, `current_position`, `planner_log` |
| **Evaluator** (`leaf_evaluator.py`) | Classifies a branch result: KNOWN verdict (state_changes + artifact bucket) or no_concept_match |
| **Vault** (`knowledge-vault/concepts/`) | Technique knowledge: grows_from, unlocks, state_changes, artifacts_captured, priority, preconditions |
| **Unknown store** (`unknown_store.py`) | Parks unclassifiable results for operator review; surfaced in Zone B |
| **Protection probe** (`login_protection_probe_engine.py`) | Pre-flight detection (IP-block, CSRF, XFF); routes to the correct variant before committing |

---

## STATE Shape

```json
{
  "goal": {
    "objective": "...",
    "success_conditions": ["valid_credentials_found"],
    "provided_self_user": null,
    "target_user": null
  },
  "facts":            ["ip_block_detected", "protection_probed", …],
  "artifacts":        {"credentials": [], "sessions": [], "tokens": [], "files": []},
  "pending":          [{"concept": "CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET", "priority": 95}],
  "ruled_out":        [],
  "completed":        ["CONCEPT-LOGIN-PROTECTION-PROBE"],
  "current_position": {"authentication": "none", "privilege": "none",
                       "access_scope": [], "execution": "none"},
  "planner_log":      ["[1] EXECUTE priority=99 [CONCEPT-LOGIN-PROTECTION-PROBE] …"],
  "solved":           false,
  "solved_reason":    null
}
```

---

## Vault → Planner Connection

Each vault concept `.md` has:
- `grows_from: [finding_type]` → `graph_resolver` seeds concept into `pending` when that finding type exists
- `unlocks: [{concept, priority}]` → after concept executes, adds linked concepts to `pending`
- `priority: N` → planner ordering (99 = first, 78 = normal brute, etc.)
- `state_changes` / `artifacts_captured` → what lands in STATE facts + artifact buckets after a successful run

---

## Inquiry Layer (Phases 1–3)

```
Phase 1 (pre-flight probe, priority 99)
  Probe login endpoint → detect IP-block / CSRF / XFF
  → Route to matching variant (counter-reset if IP-block, plain brute if NONE)
  Counter-neutral: probe POSTs use spoofed XFF so real IP failure budget is unaffected

Phase 2 (success precision)
  provided_self_user set at objective level (not engine-scoped)
  Credential classified provided vs discovered via origin tag
  SOLVED only fires on a DISCOVERED credential — not the operator's own login
  Fact-fallback removed: bare credential_obtained fact alone cannot fire SOLVED

Phase 3 (failure interrogation) — not yet built
```

---

## Variant Library

| Concept | Engine | When used |
|---|---|---|
| `CONCEPT-LOGIN-PROTECTION-PROBE` | `login_protection_probe` | Always first (priority 99) — detects defenses |
| `CONCEPT-DEFAULT-CREDS` | `default_creds` | Quick check before full brute (priority 90) |
| `CONCEPT-CREDENTIAL-BRUTE` | `credential_brute` | Plain wordlist brute (priority 85) |
| `CONCEPT-USERNAME-ENUMERATION` | `username_enum` | Oracle-guided two-phase; timing sequential (priority 80) |
| `CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET` | `credential_brute_counter_reset` | IP-block with counter-reset; interleaves self-login (priority 78/95 after probe) |
| `CONCEPT-SQLI-AUTH-BYPASS` | `sqli_auth_bypass` | SQL injection bypass (priority 70) |
| `CONCEPT-ACCESS-CONTROL` | `access_control` | IDOR / mass assignment on discovered endpoints (priority 85) |
| `CONCEPT-JS-SPIDER` | `js_spider` | Authenticated endpoint discovery post-capture (priority 75) |

---

## Right-Panel Zones

| Zone | Content |
|---|---|
| **Zone A** (PROCESS strip) | Live STATE: current_position, artifacts count, pending count, facts count; SOLVED indicator |
| **Zone B** (Unknowns strip) | Cross-run count of unclassified results pending operator review |
| **Zone C** (AI workspace) | Persistent chat: operator instructions, AI responses, planner decisions, SOLVED/EXHAUSTED/BLOCKED events; persisted per-investigation |

---

## Data Persistence

| Store | What | Table |
|---|---|---|
| `exploitation_branches` | Branch lifecycle per technique run | `validation.db` |
| `agent_state` blob | Full STATE per investigation | `exploitation_branches` (synthetic `state_{inv_id}` row) |
| `agent_loop_unknowns` | Unknown artifacts for batch review | `validation.db` |
| `investigation_chat_history` | Zone C chat per investigation | `validation.db` |
| Vault concepts | Technique knowledge (editable) | `knowledge-vault/concepts/*.md` |
| ChromaDB | Semantic embeddings for vault retrieval | container volume |

---

## Key Invariants

- **Planner pops, never self-directs**: the engine just runs what the planner selects; sweep is the fallback when no reachable lead exists
- **Timing oracle: sequential only** — parallel probing corrupts timing via correlated jitter (proven on live lab)
- **Pre-flight probe: counter-neutral** — probe POSTs use spoofed XFF; real IP failure budget preserved for the routed technique
- **Success precision: discovered only** — SOLVED requires a credential with `origin="discovered"`; bare facts or provided self-logins cannot fire SOLVED
- **No hardcoded lab values** — self_user/target_user come from `operator_params`; no literals in engines
- **Zombie branch recovery** — on startup, any branch stuck `running`/`armed` with no live task transitions to `failed`
- **Branch cleanup on delete** — investigation hard-delete removes branches, chat history, unknowns, and agent_state

---

## Known Open Gaps (as of this writing)

- **Counter-reset live-solve** (Piece 2+3): both planner-params + probe-neutrality bugs fixed; live re-verification pending a fresh PortSwigger "Broken brute-force protection, IP block" lab
- **Phase 3 failure interrogation**: not built — post-exhaustion analysis of why a technique failed
- **Planner self_pass threading**: `self_pass` (password) cannot be stored in STATE for security; must be supplied in `operator_params` at each `planner/run` call
