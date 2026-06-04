# Unknown-Resolution Playbook

**Read this first when:** an operator says "process unknown `<id>`" or opens Zone B for review.

**What this governs:** how operator + Claude Code turn a flagged unknown artifact into runnable vault
knowledge. PROCESS is automated (steps, conformance, linking, verification). JUDGMENT stays human
(is this a generalizable technique? durable principle vs lab-specific detail?).

**Canonical location:** `docs/unknown-resolution-playbook.md`

---

## A. What an Unknown Artifact Is

An unknown artifact is created when `evaluate_verdict()` returns `match_kind="no_concept_match"` —
the system executed an engine and got a result it could not classify against any vault concept.

**DB table:** `agent_loop_unknowns` in `data/validation.db`

**Schema (existing fields):**
- `id` — UUID, primary key
- `investigation_id` — which investigation generated it
- `context` — free text: `"exploitation, finding=<type>, attempting=<concept/engine>"`
- `raw_result` — JSON-serialized engine artifact (full output)
- `expected_concept` — the concept that was attempted (`CONCEPT-XXX` or None)
- `evidence` — JSON dict with structured error + metadata (see below)
- `status` — `pending_review` | `resolved` | `ignored`
- `resolution` — free text set when status changes

**Structured-error fields (inside `evidence` JSON — `park_unknown_async` Part 1):**

| Field | What it carries |
|---|---|
| `what_was_tried` | Engine ID + objective at the moment of the unknown |
| `unclassifiable_signal` | The specific signal/error the system could NOT classify |
| `suggested_concept_shape` | Best-effort authoring starting point (finding_type, pattern, engine hint) — may be absent |
| `engine_id` | Engine that ran |
| `exec_state` | Terminal state (`exhausted`, `failed`, etc.) |
| `finding_id` | Finding that triggered this engine |

**Surfacing:**
- Zone B badge (right panel) — count of `pending_review` unknowns for this investigation
- Left-panel amber banner — cross-investigation `pending_review` count (polls `/unknowns/count`)
- Zone B `<details>` — list loaded from `GET /api/v1/validation/workspace/unknowns?limit=50`

**Listing pending unknowns (Claude Code command):**
```
sqlite3 data/validation.db "SELECT id, context, json_extract(evidence,'$.what_was_tried'),
  json_extract(evidence,'$.unclassifiable_signal'), status FROM agent_loop_unknowns
  WHERE status='pending_review' ORDER BY created_at DESC LIMIT 20;"
```
Or via the API: `GET /api/v1/validation/workspace/unknowns?status=pending_review`

**Reading one unknown's structured error:**
```
sqlite3 data/validation.db "SELECT json(evidence) FROM agent_loop_unknowns WHERE id='<id>';"
```

---

## B. Operator Command Flow

```
Operator:    "process unknown <id>"
Claude Code: 1. Read THIS playbook
             2. Fetch the unknown's structured error (id → evidence JSON)
             3. SHOW the operator:
                  - what_was_tried
                  - unclassifiable_signal
                  - evidence (engine_id, exec_state, raw_result excerpt)
                  - suggested_concept_shape (if present)
Operator:    JUDGES (human decision — playbook does not decide):
               ✓ YES — real, generalizable technique class → proceed to Step C
               ✗ NO  — one-off / lab artefact → mark resolved/ignored with note (skip C)
Claude Code: mark the unknown resolved/ignored via
             POST /api/v1/validation/workspace/unknowns/<id>/status
             with resolution="<operator's note>"
```

The operator decides the durable PRINCIPLE vs lab-specific detail. Claude Code executes the
mechanical steps under that judgment. Nothing auto-resolves.

---

## C. Authoring Procedure (8 steps — execute in order)

### Step 1 — Discover conventions (mandatory first step)

Read and conform to:
- Existing concept files in `/home/unctad/projects/knowledge-vault/concepts/` — especially
  `concept-credential-brute-counter-reset.md` (most complete example)
- `/home/unctad/projects/knowledge-vault/templates/template-concept.md` (generic vault template)
- `apps/conductor/constants.py` → `CONCEPT_ENGINE_MAP` (concept-to-engine binding)
- `apps/conductor/graph_resolver.py` → `_section_body()` (grows_from parsing rule)
- `apps/conductor/agent_state.py` → `_FACT_VOCAB`, `_ARTIFACT_BUCKETS` (legal fact/artifact names)

**Do NOT invent** ids, finding_types, fact names, or connection syntax. Conform exactly.

### Step 2 — Author the concept `.md`

**File location:** `/home/unctad/projects/knowledge-vault/concepts/concept-{slug}.md`

**Required frontmatter (from `concept-credential-brute-counter-reset.md` as the canonical form):**
```yaml
---
type: concept
id: CONCEPT-{SLUG}          # e.g. CONCEPT-TIMING-BLIND-ENUM
title: "<Concept Name>"
date: "YYYY-MM-DD"
last_updated: "YYYY-MM-DD"
category: web               # web | api | network | cloud | cryptography | active-directory
tags: [...]                 # technique tags (mitre-t1xxx, owasp-axxx, etc.)
keywords:
  finding_types: [<finding_type>]   # what finding triggers this concept
  engine_id: <engine_id>            # the engine that executes it
  artifact_types: [<artifact_type>]
  action_kinds: [<engine_id>]
finding_types: [<finding_type>]
artifact_types: [<artifact_type>]
related_engines: [<engine_id>]
state_changes:              # legal fact vocab — check _FACT_VOCAB in agent_state.py
  - <fact_name>
artifacts_captured:         # legal bucket names — check _ARTIFACT_BUCKETS in agent_state.py
  - <bucket>
unlocks:                    # concepts this one unlocks when it succeeds (frontmatter path)
  - concept: CONCEPT-XXX
    priority: N
rules_out: []
last_validated: YYYY
source_status: current      # current | outdated | lab-only
priority: N                 # 1–99; higher = earlier selection by planner
---
```

**Body:** encode the DURABLE PRINCIPLE (operator-judged). Cite source (PortSwigger/OWASP/WSTG/MITRE).
No hardcoded lab values (no usernames, no URLs, no lab-specific passwords). Parameterize all
target/credential references with config names.

**Required body section `## Relationships`** (parsed by `graph_resolver.py`):
```markdown
## Relationships

**Classification:** <tree branch | entry point | leaf>

**Grows from:**
- `<finding_type>` (<description>)

**Progression (this leads to):**
- [[concept-xxx]] — <why>

**Leaf classification:** <terminal | can_be_blocked>
**Leaf result:** <artifact_type>
```
The `**Grows from:**` format is parsed by `graph_resolver._section_body(rel_text, "Grows from")`.
Only `finding_type` identifiers recognized by the system (see `normalized_findings.finding_type`)
are valid. FUTURE/UNCERTAIN finding_types are logged as gaps — do not invent.

### Step 3 — Build/extend the engine (if new capability needed)

- New engine file: `apps/conductor/engines/<engine_id>_engine.py`
- Class `<EngineName>Engine(Engine)`; implement `run(target, config, session_store, output_channel)`
- All params from `config` (no hardcoded lab values)
- All exits must reach a terminal state: `succeeded` | `exhausted` | `failed`
- Reuse helpers from `apps/conductor/exploitation/` (payloads, detection, exhaustion, artifacts)
- `engine_id` must match the `id` field in `engine_registry` registration (see existing engines)

### Step 4 — Bind (CONCEPT_ENGINE_MAP + registry)

**`apps/conductor/constants.py`** — add to `CONCEPT_ENGINE_MAP`:
```python
"CONCEPT-{SLUG}": "<engine_id>",
```

**`apps/conductor/engines/__init__.py`** — register the engine in `engine_registry` so it is
visible to the execution orchestrator. Pattern: `engine_registry.register(EngineName())`.

### Step 5 — Link (no dangling edges)

Two connection mechanisms — BOTH must be wired:

| Mechanism | Location | Parsed by | Purpose |
|---|---|---|---|
| `grows_from` | Concept body `## Relationships` | `graph_resolver._section_body()` | Seeds `agent_state.pending` from findings |
| `unlocks` | Frontmatter YAML | `_apply_verdict_in_place()` in `agent_state.py` | Adds downstream concepts to `pending` after execution |

**Pre-link integrity check:**
- Every `grows_from` finding_type must be a type that the system actually produces (grep `normalized_findings`)
- Every `unlocks` target concept must already exist in `/concepts/` (no forward references to unwritten concepts)
- Every `[[concept-xxx]]` wiki-link in the body must resolve to an existing concept file
- Run: `grep -r "CONCEPT-{SLUG}" /home/unctad/projects/knowledge-vault/concepts/` to confirm nothing references a now-renamed id

### Step 6 — Embed (vault index rebuild)

```
POST /admin/vault/rebuild
```
This calls `vault_embedder.rebuild_index()` which:
- Scans all concept files in `/home/unctad/projects/knowledge-vault/concepts/`
- Uses frontmatter `id:` as the ChromaDB document ID (preserves `CONCEPT-` prefix)
- BM25 primary (concepts/ only) + ChromaDB+nomic-embed-text when indexed
- Confirms count in response: `{"indexed": N}`

Without this step the new concept is invisible to Qwen context injection and technique matching.

### Step 7 — Verify

Run each check; report honest blockers:

```
[ ] conventions conformance: frontmatter has all required fields; id/filename/priority match
[ ] grows_from integrity: every listed finding_type exists in normalized_findings (grep or DB query)
[ ] unlocks integrity: every target concept file exists in /concepts/
[ ] no dangling edges: no [[wiki-links]] to non-existent concept files
[ ] CONCEPT_ENGINE_MAP entry present (grep constants.py)
[ ] engine registered (grep __init__.py)
[ ] no hardcoded lab values: grep for usernames/passwords/lab URLs in the new engine file
[ ] all engine exits are terminal (grep for return EngineResult — each branch must reach one)
[ ] mock test for the technique (at minimum: engine returns succeeded/exhausted on valid/invalid input;
    concept seeded from expected finding_type; CONCEPT-{SLUG} dispatchable via planner)
[ ] vault rebuild completed (POST /admin/vault/rebuild → indexed count increased)
```

### Step 8 — Resolve the unknown

```
POST /api/v1/validation/workspace/unknowns/<id>/status
  status=resolved
  resolution="Added CONCEPT-{SLUG} → <engine_id>. Vault rebuilt. Mock tests pass."
```

Zone B count decrements; left-panel banner clears if no more pending unknowns.

---

## D. Invariants (must hold every time)

Every authored concept must satisfy ALL of these before the unknown is marked resolved:

1. **No hardcoded lab values** — no usernames, passwords, lab URLs, or PortSwigger lab IDs in engine code or concept files. All variable inputs come from `config` dict.
2. **No dangling edges** — no orphan concept (not linked from grows_from + missing from _CONCEPT_FINDING_TYPES); no unlocks target that doesn't exist; no wiki-link pointing to a non-existent file.
3. **Vocab matches** — fact names in `state_changes` match `_FACT_VOCAB`; artifact bucket names in `artifacts_captured` match `_ARTIFACT_BUCKETS` (both in `agent_state.py`).
4. **Both connection mechanisms wired** — `grows_from` in body AND `unlocks` in frontmatter. Neither alone is sufficient.
5. **Engine reaches terminal on all exits** — every code path in `run()` must call `emit_stage(branch_id, "succeeded"|"exhausted"|"failed")` before returning.
6. **Embedding rebuilt** — `POST /admin/vault/rebuild` called after concept file created/modified.
7. **Operator judgment recorded** — the `resolution` field on the unknown artifact contains the operator's judgment note (why this technique was generalized, or why it was marked one-off).
8. **`_CONCEPT_FINDING_TYPES` updated** in `apps/conductor/planner.py` — add the new concept's finding_type entry so `_find_finding_for_concept` can locate the correct DB row for dispatch.

---

## E. Worked Example — Counter-Reset Brute (real instance)

**Unknown that triggered this:** after running `credential_brute`, the engine exhausted without a match when IP-block was active. The evaluator got `match_kind="no_concept_match"` for the result shape.

**Operator judgment:** "IP-block + counter-reset is a real, generalizable bypass class. Counter-reset is in OWASP WSTG-ATHN-03 and the PortSwigger lab teaches it as a general defence mechanism. Encode the PRINCIPLE: if a success resets the IP failure counter, interleave self-logins."

**Step 1 (discover):** read `concept-credential-brute.md` for format reference.

**Step 2 (author):**
- File: `knowledge-vault/concepts/concept-credential-brute-counter-reset.md`
- `id: CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET`
- `grows_from: login_form_detected` (same trigger as plain brute)
- `unlocks: [CONCEPT-JS-SPIDER@70, CONCEPT-ACCESS-CONTROL@75]`
- `priority: 78` (lower than plain brute 85 — needs probe to elevate it to 95 on IP-block detection)
- No lab usernames/passwords — self_user/self_pass come from `config`

**Step 3 (build):**
- `apps/conductor/engines/credential_brute_counter_reset_engine.py`
- All credentials from `config.get("self_user")`, `config.get("self_pass")`, `config.get("target_user")`

**Step 4 (bind):**
- `constants.py`: `"CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET": "credential_brute_counter_reset"`
- `engines/__init__.py`: registered

**Step 5 (link):**
- `grows_from: login_form_detected` ✓ (finding type exists)
- `unlocks: CONCEPT-JS-SPIDER` ✓ (file `concept-js-spider.md` exists)
- `_CONCEPT_FINDING_TYPES` in `planner.py` updated ✓ (added in Workstream C, session 2026-06-03)

**Step 6 (embed):** `POST /admin/vault/rebuild` run after authoring.

**Step 7 (verify):**
- Seam test `tests/conductor/_patterns/test_seam_planner_authority.py` — C1/C2/C3 confirm concept dispatchable and self_pass guard fires correctly.
- No hardcoded usernames: `grep -r "wiener\|carlos\|peter" apps/conductor/engines/credential_brute_counter_reset_engine.py` → 0 matches.

**Step 8 (resolve):**
```
POST /unknowns/<id>/status?status=resolved&resolution=
  "Added CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET → credential_brute_counter_reset.
   Generalizable principle: IP-block counter-reset bypass via interleaved self-login.
   Source: OWASP WSTG-ATHN-03. Vault rebuilt. Seam tests C1–C3 pass."
```

---

## Quick Reference

| Action | Command / Path |
|---|---|
| List pending unknowns | `GET /api/v1/validation/workspace/unknowns?status=pending_review` |
| Read one unknown | `GET /api/v1/validation/workspace/unknowns?status=pending_review` + find by id |
| Resolve unknown | `POST /api/v1/validation/workspace/unknowns/<id>/status` |
| Vault concept location | `/home/unctad/projects/knowledge-vault/concepts/` |
| Engine location | `apps/conductor/engines/<engine_id>_engine.py` |
| CONCEPT_ENGINE_MAP | `apps/conductor/constants.py` |
| `_CONCEPT_FINDING_TYPES` | `apps/conductor/planner.py` |
| Vault rebuild | `POST /admin/vault/rebuild` |
| Template (generic) | `/home/unctad/projects/knowledge-vault/templates/template-concept.md` |
| Canon example | `knowledge-vault/concepts/concept-credential-brute-counter-reset.md` |
| grows_from parser | `apps/conductor/graph_resolver.py:_section_body()` |
| Fact vocab | `apps/conductor/agent_state.py:_FACT_VOCAB` |
| Artifact buckets | `apps/conductor/agent_state.py:_ARTIFACT_BUCKETS` |
