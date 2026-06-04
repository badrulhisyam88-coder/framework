# Diagnosis Report: js_spider Dispatch and target_user Threading

Generated: read-only investigation (no files modified).

---

## PATH A — js_spider dispatched despite precondition (no session captured)

### Confirmed dispatch mechanism

**Auto-dispatch in execution.py, not the planner.** The planner is never involved.

The auto-dispatch hook is at:
- File: `apps/conductor/orchestrators/execution.py`
- Lines: 404–416

```python
# V2.9 Track A — auto-dispatch js_spider after credential_brute succeeds.
# Discovery-class engine; C6 operator-approval exemption applies.
if engine.engine_id == "credential_brute" and status == "success":
    try:
        logger.info(
            "execution: credential_brute succeeded — auto-dispatching js_spider"
        )
        await self.dispatch_engine(
            "js_spider",
            correlation_id=correlation_id,
        )
    except Exception as _exc:
        logger.debug("execution: js_spider auto-dispatch failed: %s", _exc)
```

This fires unconditionally inside `_run_engine()` immediately after `credential_brute` returns
`status == "success"`. The planner's precondition check is bypassed entirely.

### Where the precondition check lives

- File: `apps/conductor/planner.py`
- Lines: 37–90

```python
_CONCEPT_PRECONDITIONS: dict[str, dict] = {
    "CONCEPT-JS-SPIDER": {"authentication": frozenset({"authenticated", "admin"})},
}

def _precondition_met(concept_id: str, current_position: dict) -> bool:
    precond = _CONCEPT_PRECONDITIONS.get(concept_id)
    if not precond:
        return True
    for field_name, required_vals in precond.items():
        if current_position.get(field_name, "none") not in required_vals:
            return False
    return True
```

The check is correctly defined. It gates `CONCEPT-JS-SPIDER` on
`current_position.authentication in {authenticated, admin}`. However it is only
exercised by `plan_next_step()` (planner path). The auto-dispatch in execution.py
calls `dispatch_engine("js_spider", ...)` directly, which bypasses the planner
entirely and skips all precondition checking.

### Why this happened

CLAUDE.md says "auto-dispatches after `credential_brute` succeeds". The implementation
treats `credential_brute` status == "success" as equivalent to "session captured", but
`EngineResult.status == "success"` does NOT guarantee a session was stored. The engine
can return success with zero findings (e.g. found something, branch completed, but
`store_auth()` was not called or the session was empty). The precondition that matters
is `current_position.authentication != none`, which is only updated by
`apply_verdict_to_state_async` after the StateAgent processes the artifact — a fire-
and-forget call that may not have completed by the time the auto-dispatch fires.

### Conclusion for Path A

js_spider was dispatched by the **auto-dispatch hook** in
`apps/conductor/orchestrators/execution.py:406`, not by the planner. The planner's
`_precondition_met` check at `apps/conductor/planner.py:79–90` is **never reached** for
this code path. The precondition check is structurally sound but guards the wrong
dispatch path. The bug is that the auto-dispatch hook uses `status == "success"` as a
proxy for "session captured" without verifying `current_position.authentication`.

---

## PATH B — "get carlos password" → target_user threading

### Step 1: Chat message → operator_params boundary

When the operator types "get carlos password" in Zone C chat, the message hits one of
two routes:
- `POST /investigations/{id}/qwen/chat` (`routes.py:889`)
- `POST /investigations/{id}/qwen/chat/stream` (`routes.py:704`)

Both routes do the following with the message:
1. Pass it through `resolve_technique()` for deterministic routing (no target_user parse).
2. Build an Qwen context and call Ollama.
3. Parse the Ollama response for an ACTION block (engine_id, finding_type, reason).
4. **Save the raw message text as `InvestigationState.objective`** when `len(message) > 20`
   and `state.objective` is not already set (`routes.py:1056–1066`).

The message is saved verbatim as `objective = "get carlos password"`. It is **not** parsed
for `target_user`. No code extracts "carlos" from the chat message and writes it into
`goal.target_user` or into `operator_params` at this point.

The only place "carlos" would reach `goal.target_user` is via the
`POST /investigations/{id}/planner/run` endpoint with an explicit
`operator_params={"target_user": "carlos"}` in the request body. The chat handler does
not call `planner/run` — it returns an ACTION recommendation to the frontend. The
frontend then fires the Execute endpoint; that path does not thread `operator_params`.

### Step 2: operator_params → goal.target_user

The planner/run route at `routes.py:4525` does handle `target_user` correctly:

```python
_op = dict(operator_params or {})
_target_user = _op.get("target_user")
if _provided_self or _target_user:
    # writes _target_user → _f1_state["goal"]["target_user"]
```

And `_assemble_engine_params()` at `autonomous_orchestrator.py:1166–1168` reads it:

```python
if "target_user" not in params and goal.get("target_user"):
    params["target_user"] = goal["target_user"]
```

This wiring is correct. The problem is upstream: `planner/run` is never called with
`{"target_user": "carlos"}` because the chat route does not generate that call.

### Step 3: goal.target_user → username_enum_engine

`username_enum_engine.py` does **not** read `config["target_user"]` at all. Its `_run()`
method ignores any `target_user` in config. Phase 1 (enumeration) always iterates the
full `username_candidates.yaml` wordlist regardless of what the operator wants. Phase 2
(brute) uses `brute_target_user = confirmed_users[0]` — the first Phase 1 hit —
not the operator-specified target:

```python
# apps/conductor/engines/username_enum_engine.py:1247
brute_target_user = confirmed_users[0]
```

Even if `goal.target_user` were set to "carlos" and threaded via `_assemble_engine_params`
into params, `username_enum_engine` would ignore it because it never reads
`config.get("target_user")`. The engine is designed to discover usernames autonomously;
it has no "skip directly to this username" fast-path.

### Where "carlos" is dropped

The drop occurs at **two independent points**:

1. **Chat → operator_params boundary** (`routes.py:1056`): the message is stored as
   `objective = "get carlos password"` but "carlos" is never extracted into
   `goal.target_user` or any `operator_params` dict. No NLP/regex extraction of
   target_user runs in the chat handler.

2. **goal.target_user → engine** (`username_enum_engine.py:307–321`): even if
   `target_user` were correctly set in STATE, `username_enum_engine._run()` ignores it.
   The engine reads `config.get("candidate_usernames")` (a full list override) but not
   `config.get("target_user")` as a single-target shortcut.

`extract_target_account()` in `template_executor.py:605` does parse "carlos" out of
objective strings (pattern: "extract X's password", "password for the X user", etc.),
but it is only called by the `execute_variant` route (`routes.py:2934`) for
`oracle_search` engine parameterization — not by the username_enum or
credential_brute dispatch paths.

### Conclusion for Path B

| Boundary | Status | Detail |
|---|---|---|
| Chat message saved as objective | YES | `state.objective = "get carlos password"` (`routes.py:1060–1063`) |
| objective → goal.target_user extraction | **MISSING** | No code parses objective text into goal.target_user in the chat path |
| goal.target_user → planner params | Working (if set) | `_assemble_engine_params` at `autonomous_orchestrator.py:1167` |
| params.target_user → username_enum_engine | **MISSING** | Engine ignores `config["target_user"]`; always uses full wordlist + first Phase 1 hit |
| brute_target_user from Phase 1 | Uncontrolled | `confirmed_users[0]` — any outlier the oracle detects becomes the brute target |

"aix" (or any other confirmed-username outlier) appearing as the brute target is the
normal outcome: username_enum Phase 1 enumerates the full wordlist and picks the first
differential signal hit, which may or may not be "carlos".

---

## Summary of root causes

### Path A (js_spider dispatched without session)
- **Bug location**: `apps/conductor/orchestrators/execution.py:406`
- **Root cause**: auto-dispatch fires on `credential_brute status == "success"` without
  checking `current_position.authentication`. The planner's `_precondition_met` check
  in `apps/conductor/planner.py:79` is never reached for the auto-dispatch code path.
- **Fix direction**: Guard the auto-dispatch with a session-presence check before calling
  `dispatch_engine("js_spider")`. Either verify `channel._last_artifact` contains
  `artifact_type == "captured_session"`, or read `current_position.authentication` from
  STATE before firing.

### Path B ("carlos" never reaches goal or engine)
- **Bug 1 location**: `apps/investigation_workspace/api/routes.py` — both `qwen_chat`
  (line ~1060) and `qwen_chat_stream` (line ~957). The objective string is persisted but
  no extraction of target_user into `goal.target_user` is performed.
- **Bug 2 location**: `apps/conductor/engines/username_enum_engine.py:307–321`. The
  engine has no `config["target_user"]` fast-path; it always enumerates the full wordlist.
- **Fix direction (Bug 1)**: After saving objective, call `extract_target_account()` on
  it and write the result into `goal.target_user` via `save_agent_state_async`. Use the
  existing `_get_state_lock` to avoid concurrent writes.
- **Fix direction (Bug 2)**: Add a `target_user` config read at the top of
  `username_enum_engine._run()`. When set, skip Phase 1 enumeration entirely and proceed
  directly to Phase 2 brute for that username only.
