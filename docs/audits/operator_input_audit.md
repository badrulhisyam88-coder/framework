# Operator-Input Capability Audit
**Scope**: Action card system — can operator-supplied runtime parameters reach a probe?
**Date**: 2026-05-23
**Method**: Read-only. No code changed.

---

## Answer up front

**Yes — the system supports operator input today.**

The full pipeline is wired: template renders an input field, route collects the
value as a Form parameter, a ContextVar carries it into the probe runner task,
and the probe substitutes it into the request. The only probe that currently
uses it is `probe_api_idor_mutate` (mutating IDOR actions).

---

## 1 — How do existing action cards get their parameters?

### Fully pre-determined at probe time (all probes except one)

Every probe except `probe_api_idor_mutate` operates on parameters that are fixed
before the operator clicks anything:

| Probe | Where parameters come from |
|---|---|
| `probe_xss_reflected` | Hard-coded XSS payloads; target URL from `canonical_target` |
| `probe_sqli_auth_bypass` | Login endpoints from `FINDING_EVIDENCE_CTX` (recon hints) |
| `probe_brute_force_login` | Credential wordlist + form fields from `FINDING_EVIDENCE_CTX` |
| `probe_cmdi_reflected/blind_time/blind_boolean` | Hard-coded payloads + `canonical_target` |
| `probe_csp_*`, `probe_robots_check` | `canonical_target` only |
| `probe_api_exploit` | API doc path enumeration + default credential list |

None of these emit `has_input` cards. All their `next_actions` have `has_input=False`
(the default), so they render as plain Execute buttons.

### Operator-supplied at execute time (probe_api_idor_mutate)

`probe_api_exploit` Phase 2 emits one action card per mutating endpoint
(DELETE/PATCH/POST/PUT) discovered in the API spec. Each card carries:

```python
{
    "action_kind":       _make_mutate_ak(method, path_template),  # base64(method+path)
    "label":             f"{method} {path_template}",
    "reason":            "Non-GET request — type target username then click Execute",
    "has_input":         True,
    "input_name":        "target_user",
    "input_placeholder": "target username (e.g. carlos)",
}
```

The action_kind encodes only `(method, path_template)` — **not** a pre-baked
username. The operator types the target at execute time. The same card can be
executed multiple times with different usernames.

---

## 2 — Flow trace: input field → request fired

```
TEMPLATE  structured_evidence.html
          {% elif na.has_input %}
          <form hx-post="…/suggest/{action_kind}/execute?exploit_path_id=X&parent_run_id=Y"
                hx-swap="none" hx-on::after-request="…refresh…">
            <input type="text" name="{{ na.input_name }}"
                   placeholder="{{ na.input_placeholder }}" required>
            <button type="submit">Execute →</button>
          </form>
          ↓ HTMX serialises the form, sends POST with body target_user=carlos

ROUTE     execute_suggestion(
              investigation_id, finding_id, action_kind,  ← path params
              exploit_path_id="", parent_run_id="",        ← query params
              target_user: str = Form(default=""),         ← form body
          )
          → _TARGET_USER_CTX.set(target_user.strip())     ← publishes to context
          → parent_node_id = "exec-{parent_run_id}-r0"    ← anchors under IDOR result
               (or "disc-{finding_id}" if no parent_run_id)
          → kick_off(finding_id=finding_id, …)

RUNTIME   kick_off() creates ExecutionRun + asyncio.create_task(_runner_from_probe)
          asyncio task inherits current context → TARGET_USER_CTX value propagates

PROBE     probe_api_idor_mutate(canonical_target)
          → ACTION_ID_CTX.get() → "suggestion:api_idor_mutate_eyJ…"
          → _decode_mutate_ak(ak) → {"method": "DELETE", "path_template": "/user/{username}"}
          → TARGET_USER_CTX.get("").strip() → "carlos"
          → guard: if not target_user: yield note, return
          → filled = "/user/carlos"
          → _url_candidates(base_url, spec_base_path, filled) → [list of candidates]
          → client.request("DELETE", candidate, cookies=session_cookies,
                           headers=_browser_headers(base_url))
          → yield StageEvent + ResultEvent with HTTP response captured
```

### Where each piece lives

| Step | File | Key symbol |
|---|---|---|
| Input field render | `frontend/templates/partials/structured_evidence.html` L194–212 | `{% elif na.has_input %}` |
| Value collection | `apps/investigation_workspace/api/routes.py` L1027 | `target_user: str = Form(default="")` |
| ContextVar publication | `apps/investigation_workspace/api/routes.py` L1108–1110 | `_TARGET_USER_CTX.set(…)` |
| ContextVar definition | `apps/investigation_workspace/execution/runtime.py` L97–101 | `TARGET_USER_CTX` |
| Probe reads value | `apps/investigation_workspace/suggestions/probes.py` L4261 | `_TARGET_USER_CTX.get("").strip()` |
| Empty guard | `apps/investigation_workspace/suggestions/probes.py` L4263–4279 | early `return` with `ResultEvent(kind="note")` |

---

## 3 — Existing template patterns for input + execute

Before the current implementation, the template had only one pattern for next-action cards:
plain Execute button (`<button type="button" hx-post="…">`). No form or input field existed.

The current template now has two patterns in the `{% for na in next_actions %}` loop:

**Pattern A — Plain Execute button** (all catalog-backed actions, no input needed):
```html
<button type="button" hx-post="{{ _exec_url }}" hx-swap="none" …>
  Execute →
</button>
```

**Pattern B — Form with text input** (probe-emitted cards where `na.has_input` is True):
```html
<form hx-post="{{ _exec_url }}" hx-swap="none" hx-on::after-request="…refresh…"
      class="shrink-0 flex items-center gap-1">
  <input type="text" name="{{ na.input_name }}" placeholder="{{ na.input_placeholder }}"
         class="… w-36 …" required>
  <button type="submit" class="… bg-blue-600 …">Execute →</button>
</form>
```

The `_exec_url` Jinja variable is built once per card and includes `exploit_path_id`
and `parent_run_id` as query parameters when present.

No third pattern exists. Other templates (capture_bundle.html, context_panel.html)
have no comparable input + execute construct.

---

## 4 — Gaps between current state and "operator types, request fires"

**None for the implemented case (`probe_api_idor_mutate`).**

The pipeline is complete. To extend it to other probes, the gaps would be:

| Gap | What is missing |
|---|---|
| `SuggestionSpec` has no `has_input` | Catalog-registered probes can't declare input needs statically; `has_input` only reaches the template via probe-emitted `next_actions` payload, not via the catalog. Impact: only probe-emitted cards can be input cards today. Catalog entries that need input would require a probe to emit the card. |
| `TARGET_USER_CTX` is the only named input slot | The system has one ContextVar for operator input (`target_user`). A second parameter type (e.g., an IP, a port, a cookie value) would need a new ContextVar and a matching `Form()` param on the execute route. There is no generic named-input mechanism. |
| Dedup key doesn't cover target_user | `find_active_run` uses `(finding_id, action_kind, exploit_path_id)` as the dedup key. Two Execute clicks with different target_users on the same card return the same active run (if one is still running) because the action_kind is identical. This is acceptable for the IDOR case (only one run per card at a time) but would be a bug if the same card needed to fire concurrently against two different users. |
| No "executed for user X" display | The `executed` flag in `next_actions_view` uses `has_been_executed(investigation_id, finding_id, action_kind)`, which returns True if any run with that action_kind exists. After executing for "carlos", the card shows "✓ executed" even though the operator might want to also run it for "administrator". The card goes read-only on first successful execute. |

The last two gaps are low priority for the current single-user, one-card-at-a-time workflow.
