# Diagnosis Report — Latest Investigation Agent STATE

**Generated:** 2026-06-03
**Source:** `/home/unctad/projects/ai-assist-tool/data/validation.db` (host-accessible)
**Investigation ID:** `1cd56b91-da66-4ce8-b522-064d950a981c`
**Target:** `https://0a1b00b9037e3dc0807ea8bd00e3002b.web-security-academy.net/`
**Lab title (from sqli_auth_bypass exhaustion response):** "Broken brute-force protection, IP block"

---

## 1. Database Location

`validation.db` is accessible from the host at:

```
/home/unctad/projects/ai-assist-tool/data/validation.db
```

No Docker access required for this read.

---

## 2. `exploitation_branches` Schema

```sql
CREATE TABLE exploitation_branches (
    branch_id        TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    finding_id       TEXT NOT NULL,
    engine_id        TEXT NOT NULL,
    technique_class  TEXT NOT NULL,
    operator_params  TEXT NOT NULL DEFAULT '{}',
    state            TEXT NOT NULL DEFAULT 'pending',
    artifact         TEXT,
    exhaustion_record TEXT,
    stage_log        TEXT NOT NULL DEFAULT '[]',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    artifact_type    TEXT
);
```

---

## 3. Latest `state_*` Row (Verbatim)

```
branch_id:        state_1cd56b91-da66-4ce8-b522-064d950a981c
investigation_id: 1cd56b91-da66-4ce8-b522-064d950a981c
engine_id:        investigation_state
state:            succeeded
updated_at:       2026-06-03T09:38:54.466992+00:00
operator_params:  {}
exhaustion_record: (NULL)
stage_log:        []
```

---

## 4. Full STATE Blob (artifact column — verbatim)

```json
{
    "investigation_id": "1cd56b91-da66-4ce8-b522-064d950a981c",
    "target": "",
    "objective": null,
    "credentials": null,
    "session": null,
    "endpoints": [],
    "tokens": {},
    "attempt_tree": [],
    "parsed_objective": null,
    "ranked_lists": {},
    "pending_work_orders": {},
    "captured_session": null,
    "autonomous_stop_requested": false,
    "autonomous_status": "budget",
    "autonomous_run_log": [
        {
            "attempt": 1,
            "primitive_id": "sqli_auth_bypass",
            "engine_id": "sqli_auth_bypass",
            "rationale": "Operator selected: Test SQL injection auth bypass",
            "params": {},
            "result_state": "exhausted",
            "result_summary": "sqli_auth_bypass tried all payloads — no result found.",
            "solved": false,
            "parallel_batch": false,
            "source": "operator",
            "finding_id": "fnd_2faaffe1698b",
            "leaf_kind": "terminal",
            "leaf_reason": "concept 'CONCEPT-SQLI-AUTH-BYPASS' leaf_type=terminal — no stem warranted"
        },
        {
            "attempt": 2,
            "primitive_id": "js_spider",
            "engine_id": "js_spider",
            "rationale": "Operator selected: Spider JS for hidden endpoints",
            "params": {"concept_id": "CONCEPT-JS-SPIDER"},
            "result_state": "exhausted",
            "result_summary": "js_spider tried all payloads — no result found.",
            "solved": false,
            "parallel_batch": false,
            "source": "stem",
            "finding_id": "fnd_4d6ab70338fd",
            "leaf_kind": "terminal",
            "leaf_reason": "concept 'CONCEPT-JS-SPIDER' leaf_type=terminal — no stem warranted"
        },
        {
            "attempt": 3,
            "primitive_id": "username_enum",
            "engine_id": "username_enum",
            "rationale": "Operator selected: Enumerate username via response differential",
            "params": {"concept_id": "CONCEPT-USERNAME-ENUMERATION"},
            "result_state": "exhausted",
            "result_summary": "username_enum tried all payloads — no result found.",
            "solved": false,
            "parallel_batch": false,
            "source": "stem",
            "finding_id": "fnd_4d6ab70338fd",
            "leaf_kind": "terminal",
            "leaf_reason": "concept 'CONCEPT-USERNAME-ENUMERATION' leaf_type=terminal — no stem warranted"
        },
        {
            "attempt": 4,
            "primitive_id": "username_enum",
            "engine_id": "username_enum",
            "rationale": "Oracle progression: username_enum(message) exhausted (no_signal_found) — advancing to length",
            "params": {"oracle_strategy": "length"},
            "result_state": "exhausted",
            "result_summary": "username_enum tried all payloads — no result found.",
            "solved": false,
            "parallel_batch": false,
            "source": "stem",
            "finding_id": "fnd_4d6ab70338fd",
            "leaf_kind": "terminal",
            "leaf_reason": "concept 'CONCEPT-USERNAME-ENUMERATION' leaf_type=terminal — no stem warranted"
        }
    ],
    "agent_state": {
        "goal": {
            "objective": "obtain credentials / access",
            "success_conditions": ["valid_credentials_found"],
            "provided_self_user": null,
            "target_user": null
        },
        "facts": [
            "authentication_bypassed",
            "endpoints_discovered",
            "valid_username_known"
        ],
        "artifacts": {
            "credentials": [],
            "sessions": [],
            "tokens": [],
            "files": []
        },
        "pending": [
            {"concept": "CONCEPT-LOGIN-PROTECTION-PROBE", "priority": 99},
            {"concept": "CONCEPT-DEFAULT-CREDS",          "priority": 90},
            {"concept": "CONCEPT-CREDENTIAL-BRUTE",       "priority": 85},
            {"concept": "CONCEPT-ACCESS-CONTROL",         "priority": 80},
            {"concept": "CONCEPT-CREDENTIAL-BRUTE-COUNTER-RESET", "priority": 78},
            {"concept": "CONCEPT-JWT-ATTACKS",            "priority": 75},
            {"concept": "CONCEPT-NOSQL-OPERATOR-INJECTION","priority": 72},
            {"concept": "CONCEPT-XSS-REFLECT",            "priority": 70},
            {"concept": "CONCEPT-NOSQL-INJECTION",        "priority": 60}
        ],
        "ruled_out": [],
        "completed": [
            "CONCEPT-SQLI-AUTH-BYPASS",
            "CONCEPT-JS-SPIDER",
            "CONCEPT-USERNAME-ENUMERATION"
        ],
        "current_position": {
            "authentication": "none",
            "privilege": "none",
            "access_scope": [],
            "execution": "none"
        },
        "planner_log": []
    }
}
```

---

## 5. Ordered Planner Decision Sequence

**`planner_log` is empty (`[]`).**

The `run_planner_loop()` function in `autonomous_orchestrator.py` is the only writer to `planner_log`. It is only called from one route in `apps/investigation_workspace/api/routes.py` (line 4548/4598) — the explicit "run planner" endpoint. That route was never invoked for this investigation.

All 4 executions in this run were **operator-driven dispatches** through the normal autonomous loop (not `run_planner_loop`), as confirmed by `autonomous_run_log.source` values:
- Attempt 1: `source = "operator"` (direct operator selection)
- Attempts 2–4: `source = "stem"` (auto-dispatched stems from the first operator selection)

**No EXECUTE, SWEEP, or STUCK decisions were recorded via the planner.** The planner was never engaged.

---

## 6. What Actually Ran (Regular Branch Execution)

Three engine branches executed for investigation `1cd56b91-da66-4ce8-b522-064d950a981c`:

| branch_id | engine_id | state | key outcome |
|---|---|---|---|
| `exb_8a99ea361de5` | `sqli_auth_bypass` | `exhausted` | Single payload tried (`administrator'--`); lab responded "Invalid username"; exhausted immediately |
| `exb_jsspider_e420833cfd` | `js_spider` | `exhausted` | `reason: no_session`; 0 pages fetched; exhausted immediately |
| `exb_cdef9418fef0` | `username_enum` | `exhausted` | Phase 1 (message oracle): 99 candidates → "carlos" signal found but failed consistency gate; then Phase 1 (length oracle): 99 candidates → outliers "aix"/"ajax"/"ak" promoted; Phase 2 brute: 1155 passwords × user "aix" → password not found |

### username_enum notable events from stage_log:

- `09:24:29` — `user_exists_signal` for "carlos" (message strategy, probed=99)
- `09:24:31` — `consistency_discard` for "carlos" (signal rejected by consistency check)
- `09:25:08` — `length_outlier_detected` for "aix", "ajax", "ak" (length strategy, probed=99)
- `09:25:09` — Phase 2 brute begins: target_users=["aix"], password_candidates=1155
- `09:38:54` — exhausted: `password_not_found`, confirmed_users=["aix","ajax","ak"], passwords_tried=1155

### `agent_loop_unknowns` entry for this investigation:

```
context: exploitation, username_enum: Phase 1 confirmed user 'aix' but Phase 2 brute
         exhausted entirely (1155/1155 passwords tried, 0 succeeded)

raw_result: brute_attempts=1155, wordlist_size=1155, successes=0, confirmed_user=aix,
            oracle_strategy=length

expected_concept: credential_obtained (expected after confirmed enumeration)

evidence:
  phase1_oracle:             length
  phase1_confirmed_users:    ["aix", "ajax", "ak"]
  phase2_attempts:           1155
  phase2_wordlist_size:      1155
  classification:            possible false-positive enumeration OR password not in wordlist
  note: Phase 1 passed the consistency gate yet Phase 2 found nothing. Review: was the
        Phase 1 signal robust? Is the password wordlist exhaustive for this target?

status: pending_review
```

---

## 7. Stale Facts in `agent_state.facts`

The `facts` array contains:
```json
["authentication_bypassed", "endpoints_discovered", "valid_username_known"]
```

These are **inconsistent with the actual run outcomes**:
- `authentication_bypassed` — false. No auth bypass succeeded. sqli_auth_bypass exhausted.
- `endpoints_discovered` — plausible (js_spider ran but found nothing due to `no_session`).
- `valid_username_known` — false. username_enum found no confirmed username; the "aix" candidate was a false positive (Phase 2 brute found no password).

These facts appear to have been seeded at investigation initialization rather than derived from actual engine outcomes. The fact updater either was not called or was called with wrong assumptions.

---

## 8. `operator_params` — None Stored

The `operator_params` column in the state row is `{}` (empty). No operator parameters were stored in the state row. Individual branch rows also show `operator_params = {}`.

---

## 9. SWEEP Events

**No SWEEP events occurred.** `planner_log` is empty — `run_planner_loop` was never called. The autonomous loop `_seed_pending` path ran instead (operator-driven dispatches). There is no SWEEP event in any log for this investigation.

---

## 10. Summary Diagnosis

| Dimension | Finding |
|---|---|
| `planner_log` | Empty — `run_planner_loop` not invoked |
| SWEEP events | None |
| EXECUTE decisions | None (planner was not the dispatcher) |
| STUCK decisions | None |
| Dispatch mechanism | Operator-driven via autonomous loop `_seed_pending` path |
| `autonomous_status` | `"budget"` — loop terminated on attempt/wall-clock budget |
| Key failure | `username_enum` length-oracle false positive: "aix" confirmed but brute failed 1155/1155 |
| Root defect candidate | Stale `facts` seeded at init; length-oracle promoted weak outliers past consistency gate |
| Pending work unblocked | 9 concepts remain in `pending` (highest: CONCEPT-LOGIN-PROTECTION-PROBE, priority 99) — none were dispatched autonomously |
| Lab identity | "Broken brute-force protection, IP block" — this lab requires IP reset between attempts; wordlist may also be insufficient |
