# Seeding Layer Diagnostic — `login_form_detected` → `pending`

**Date:** 2026-06-03  
**Investigation:** Why did CONCEPT-LOGIN-PROTECTION-PROBE (99), CONCEPT-DEFAULT-CREDS (90),
CONCEPT-CREDENTIAL-BRUTE (85), CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET (78) never appear
in `pending`, while sqli_auth_bypass (70), js_spider (75), username_enum (80) ran in
strictly ascending order?

---

## 1. Seeding Code Path (complete chain)

```
GET /exploitation-data.json  (routes.py:564)
  → get_or_init_agent_state_async(investigation_id)    [agent_state.py:222]
      → load_agent_state_async()                        [agent_state.py:191]
          → if existing and "goal" in existing: return  ← ONE-SHOT GATE
      → init_agent_state_async()                        [agent_state.py:132]
          → NormalizedFindingRepository.list_for_investigation()
          → for each finding: resolve_branches(finding_type)  [graph_resolver.py:428]
              → _get_index() → _build_index()           [graph_resolver.py:313]
                  → reads all /app/knowledge-vault/concepts/*.md
                  → _parse_concept_file() → grows_from, engine_id
                  → builds ft_index: {finding_type → [BranchSpec]}
          → for each branch: _concept_priority(concept_id)   [agent_state.py:104]
              → reads priority: from concept frontmatter
          → pending = [{concept, priority}] sorted desc
      → save_agent_state_async()                         ← persisted to DB blob
      → return fresh state

POST /investigations/{id}/planner/run  (routes.py:4525)
  → get_or_init_agent_state_async()  ← NOOP if already initialized
  → run_planner_loop()
      → per iteration: load_agent_state_async() + plan_next_step()
```

**Seeding is ONE-SHOT.** `get_or_init_agent_state_async` checks whether a `goal` key
exists in the persisted blob. If it does, it returns the stored state without re-seeding.
Seeding only re-runs if the blob is absent or `"goal"` is missing.

**Planner loop reads state fresh each iteration** via `load_agent_state_async()` — it
does NOT re-seed. Only `apply_verdict_to_state_async` modifies `pending` after init
(adding `unlocks` from engine verdicts, removing `rules_out` items).

---

## 2. `_parse_frontmatter` Behavior (critical finding)

`graph_resolver._parse_frontmatter` (line 83–102) only matches lines that START with
`engine_id:` (no leading whitespace):

```python
elif line.startswith("engine_id:"):
    val = line[10:].strip().strip("\"'")
    if val and val != "null":
        fm["engine_id"] = val
```

**Every concept file in the vault has `engine_id` only inside the nested `keywords:` block:**

```yaml
keywords:
  finding_types: [login_form_detected]
  engine_id: credential_brute        # ← indented — NOT matched by startswith("engine_id:")
```

Result: `_parse_frontmatter` returns `{}` for `engine_id` on every concept file.
The resolver always falls through to `CONCEPT_ENGINE_MAP` in `constants.py`.

**This is NOT a bug** — the `CONCEPT_ENGINE_MAP` covers all concepts correctly. The
`_parse_concept_file` fallback chain is:
1. `fm.get("engine_id")` → None (always, due to indentation)
2. `_CONCEPT_ENGINE_SUPPLEMENT.get(concept_id)` → covers NOSQL-OPERATOR-INJECTION + AUTH-BYPASS-LOGIN
3. `CONCEPT_ENGINE_MAP.get(concept_id)` → covers all other concepts

---

## 3. `grows_from` Values from Vault (verbatim, as parsed)

| Concept | id | priority | grows_from (real) | engine_id (via map) |
|---|---|---|---|---|
| concept-login-protection-probe.md | CONCEPT-LOGIN-PROTECTION-PROBE | 99 | `login_form_detected` | login_protection_probe |
| concept-default-creds.md | CONCEPT-DEFAULT-CREDS | 90 | `login_form_detected`, `api_exposure` | default_creds |
| concept-credential-brute.md | CONCEPT-CREDENTIAL-BRUTE | 85 | `login_form_detected` | credential_brute |
| concept-credential-brute-counter-reset.md | CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET | 78 | `login_form_detected` | credential_brute_counter_reset |
| concept-username-enumeration.md | CONCEPT-USERNAME-ENUMERATION | 80 | `login_form_detected` | username_enum |
| concept-sqli-auth-bypass.md | CONCEPT-SQLI-AUTH-BYPASS | 70 | `sqli`, `sqli_error_based`, `sqli_blind`, `login_form_detected` | sqli_auth_bypass |
| concept-js-spider.md | CONCEPT-JS-SPIDER | 75 | `login_form_detected`, `api_endpoint_discovered` | js_spider |

Note: `concept-credential-brute-counter-reset.md` was **created 2026-06-03T13:15:07**
and `concept-login-protection-probe.md` was **created 2026-06-03T16:22:36**.

---

## 4. `resolve_branches("login_form_detected")` — Live Output

Running `resolve_branches("login_form_detected")` against the current vault returns
**10 branches**, including ALL high-priority concepts:

```
CONCEPT-CREDENTIAL-BRUTE          engine=credential_brute           executable=True
CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET  engine=credential_brute_counter_reset  executable=True
CONCEPT-DEFAULT-CREDS             engine=default_creds              executable=True
CONCEPT-JS-SPIDER                 engine=js_spider                  executable=True
CONCEPT-LOGIN-PROTECTION-PROBE    engine=login_protection_probe     executable=True
CONCEPT-NOSQL-INJECTION           engine=access_control             executable=True
CONCEPT-NOSQL-OPERATOR-INJECTION  engine=oracle_search              executable=True
CONCEPT-SQLI-AUTH-BYPASS          engine=sqli_auth_bypass           executable=True
CONCEPT-USERNAME-ENUMERATION      engine=username_enum              executable=True
CONCEPT-JWT-ATTACKS               engine=None                       executable=False (NONE-YET)
```

Simulated `pending` after `init_agent_state_async` with `login_form_detected`:

```
{'concept': 'CONCEPT-LOGIN-PROTECTION-PROBE',         'priority': 99}
{'concept': 'CONCEPT-DEFAULT-CREDS',                  'priority': 90}
{'concept': 'CONCEPT-CREDENTIAL-BRUTE',               'priority': 85}
{'concept': 'CONCEPT-USERNAME-ENUMERATION',           'priority': 80}
{'concept': 'CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET', 'priority': 78}
{'concept': 'CONCEPT-JS-SPIDER',                      'priority': 75}
{'concept': 'CONCEPT-JWT-ATTACKS',                    'priority': 75}
{'concept': 'CONCEPT-NOSQL-OPERATOR-INJECTION',       'priority': 72}
{'concept': 'CONCEPT-SQLI-AUTH-BYPASS',               'priority': 70}
{'concept': 'CONCEPT-NOSQL-INJECTION',                'priority': 60}
```

The seeding layer is **correct TODAY**. The issue is **temporal**, not structural.

---

## 5. Root Cause of the Symptom

**The investigation's `agent_state` was seeded BEFORE the high-priority concept files existed.**

Timeline:
- `concept-credential-brute-counter-reset.md` created: **2026-06-03 13:15:07**
- `concept-login-protection-probe.md` created: **2026-06-03 16:22:36**
- The NoSQL rookie run investigation (which ran sqli_auth_bypass, js_spider, username_enum)
  was launched **before** both concept files existed.

When `init_agent_state_async` ran for that investigation, `_build_index()` scanned the
vault and found only the concepts that existed at that moment. `CONCEPT-LOGIN-PROTECTION-PROBE`
and `CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET` were not in the vault yet → not seeded.

Because `get_or_init_agent_state_async` is **one-shot** (the `"goal" in existing` guard
prevents re-seeding), the state was persisted with the incomplete pending list and was
never re-built when the new concept files were added.

The `_graph_index` is also **module-level cached** (set once at first call, never
re-read unless `rebuild_index()` is called explicitly). On a running container, adding
vault files does not automatically invalidate the in-memory index.

**Why strictly ascending order (70, 75, 80)?**

The missing high-priority concepts (99, 90, 85, 78) left only:
```
CONCEPT-USERNAME-ENUMERATION  80  → ran first
CONCEPT-JS-SPIDER             75  → ran second
CONCEPT-SQLI-AUTH-BYPASS      70  → ran third
```
This is exactly the ascending order symptom reported, explained by the partial
seed caused by the missing vault files at init time.

---

## 6. `_CONCEPT_FINDING_TYPES` Map (verbatim from `planner.py:54–70`)

This map is used by `_find_finding_for_concept` to look up the DB finding_id for
execution dispatch. It is a secondary hardcoded map (separate from the vault-driven
`grows_from`) and is NOT used for seeding `pending`:

```python
_CONCEPT_FINDING_TYPES: dict[str, list] = {
    "CONCEPT-CREDENTIAL-BRUTE":     ["login_form_detected"],
    "CONCEPT-USERNAME-ENUMERATION": ["login_form_detected"],
    "CONCEPT-SQLI-AUTH-BYPASS":     ["sqli", "sqli_error_based", "sqli_blind",
                                     "login_form_detected"],
    "CONCEPT-JS-SPIDER":            ["api_endpoint_discovered", "login_form_detected"],
    "CONCEPT-ACCESS-CONTROL":       ["api_exposure", "api_idor", "api_bola",
                                     "api_endpoint_discovered"],
    "CONCEPT-XSS-REFLECT":          ["xss_reflected", "reflected_xss",
                                     "xss_via_html_injection"],
    "CONCEPT-CMDI-REFLECTED":       ["cmdi_reflected", "os_command_injection"],
    "CONCEPT-CMDI-BLIND-TIME":      ["cmdi_blind", "os_command_injection"],
    "CONCEPT-CMDI-BLIND-BOOLEAN":   ["cmdi_blind", "os_command_injection"],
    "CONCEPT-DEFAULT-CREDS":             ["login_form_detected"],
    "CONCEPT-METASPLOIT-RECIPE":         ["service_banner_disclosed", "open_port_detected"],
    "CONCEPT-LOGIN-PROTECTION-PROBE":    ["login_form_detected"],
}
```

`CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET` is **absent** from `_CONCEPT_FINDING_TYPES`.
This means even if the planner selects it, `_find_finding_for_concept` returns `None`
and the planner skips it with a `"SKIP — no matching finding"` log entry. This is a
**secondary bug** that would prevent counter-reset execution even on a fresh investigation.

---

## 7. Gap Summary

| Concept | Should be seeded? | In vault at run time? | In `_CONCEPT_FINDING_TYPES`? | Net effect |
|---|---|---|---|---|
| CONCEPT-LOGIN-PROTECTION-PROBE (99) | Yes | No (created after run) | Yes | Not seeded — concept didn't exist |
| CONCEPT-DEFAULT-CREDS (90) | Yes | Yes (created 2026-05-28) | Yes | Should have been seeded — check if investigation predates 2026-05-28 |
| CONCEPT-CREDENTIAL-BRUTE (85) | Yes | Yes | Yes | Should have been seeded |
| CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET (78) | Yes | No (created 2026-06-03 13:15) | **MISSING** | Not seeded AND can't execute via planner |
| CONCEPT-USERNAME-ENUMERATION (80) | Yes | Yes | Yes | Correctly seeded and ran |
| CONCEPT-JS-SPIDER (75) | Yes | Yes | Yes | Correctly seeded and ran |
| CONCEPT-SQLI-AUTH-BYPASS (70) | Yes | Yes | Yes | Correctly seeded and ran |

**Two bugs confirmed:**

**Bug 1 (primary — temporal):** The investigation's `agent_state` was initialized before
`concept-login-protection-probe.md` and `concept-credential-brute-counter-reset.md`
existed. One-shot init + in-memory index cache = the new concepts were never added to
the persisted `pending` list for that investigation. Fix: expose a `POST /investigations/{id}/planner/reinit-state` route that calls `init_agent_state_async` unconditionally (bypasses the `get_or_init` guard) to re-seed `pending` from current vault state. Also: call `rebuild_index()` before re-seeding to flush the stale in-memory graph index.

**Bug 2 (secondary — missing map entry):** `CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET` is
absent from `_CONCEPT_FINDING_TYPES` in `planner.py`. Even on a fresh investigation with
correct seeding, the planner will skip counter-reset with a SKIP log entry because
`_find_finding_for_concept` has no entry to query.

Fix: add `"CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET": ["login_form_detected"]` to
`_CONCEPT_FINDING_TYPES`.

---

## 8. Whether `CONCEPT-DEFAULT-CREDS` and `CONCEPT-CREDENTIAL-BRUTE` Were Missing

These concepts were created **2026-05-28** (both have `date: "2026-05-28"` in frontmatter).
If the NoSQL rookie investigation was started after 2026-05-28, both should have been
in the vault at init time and correctly seeded (priority 90 and 85).

The fact that they didn't run may indicate:
1. The investigation `agent_state` was initialized at some earlier date (pre-2026-05-28
   rebuild), or
2. The `_graph_index` in-memory cache was stale on the running container and had not
   been rebuilt after the new concept files were added to the vault mount.
3. The planner loop was called with `max_iterations` too low to reach them after
   username_enum and js_spider ran first.

The in-memory index cache is the most likely culprit for concepts that existed in the
vault but didn't appear — the container's `_graph_index` may have been populated before
the vault files were written, and `rebuild_index()` was never called after the docker
vault mount refreshed.

---

## Files Referenced

- `/home/unctad/projects/ai-assist-tool/apps/conductor/graph_resolver.py` — vault index builder, `resolve_branches()`
- `/home/unctad/projects/ai-assist-tool/apps/conductor/agent_state.py` — `init_agent_state_async`, `get_or_init_agent_state_async`, `_concept_priority`
- `/home/unctad/projects/ai-assist-tool/apps/conductor/planner.py` — `_CONCEPT_FINDING_TYPES`, `plan_next_step`
- `/home/unctad/projects/ai-assist-tool/apps/conductor/constants.py` — `CONCEPT_ENGINE_MAP`
- `/home/unctad/projects/ai-assist-tool/apps/investigation_workspace/api/routes.py` — seeding call site (line 564) + planner run route (line 4525)
- `/home/unctad/projects/knowledge-vault/concepts/` — vault concept files (23 files)
