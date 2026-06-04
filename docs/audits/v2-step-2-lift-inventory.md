# V2.2 Pre-lift Engine Inventory

**Date:** 2026-05-26  
**Method:** 7 parallel subagents (one per probe) + sequential synthesis.  
**Sources:** `apps/investigation_workspace/suggestions/probes.py` (4,894 lines), `apps/conductor/exploitation/` utility modules, `apps/conductor/engines/xss_exploit_engine.py` (reference pattern), `apps/validation/services/metasploit.py`, `msf_recipes.py`, `msf_wordlists.py`.  
**Read-only. No code changes.**

---

## Quick-reference: cleanness ratings

| Engine | Probe(s) retired | Rating | Key reason |
|---|---|---|---|
| `CredentialBruteEngine` | `probe_brute_force_login` | **Coupled** | 3 lab couplings; CSRF regex hardcoded; wordlist split; auth injection conflict |
| `CmdiReflectedEngine` | `probe_cmdi_reflected` | **Coupled** | `authenticate_dvwa()` removal; `<pre>` parser DVWA-oriented |
| `CmdiBlindTimeEngine` | `probe_cmdi_blind_time` | **Risky** | Two-sample threshold model diverges from substrate; stale comment; 15s timeout critical |
| `CmdiBlindBooleanEngine` | `probe_cmdi_blind_boolean` | **Coupled** | Strategy-switch depends on `<pre>` heuristic; degrades to timing on non-DVWA |
| `SqliAuthBypassEngine` | `probe_sqli_auth_bypass` | **Decision required** | Post-exploit capture seam not wired; payload format mismatch; decision blocks PR |
| `DefaultCredsEngine` | `probe_api_default_creds_auth` | **Decision required** | `OutputChannel` lacks `store_auth()`; no trigger finding to anchor branch |
| `AccessControlEngine` | `probe_api_exploit` (+`probe_api_idor_mutate` — TBD) | **Coupled / Decision required** | Must strip self-auth; mutating-IDOR scope TBD; OpenAPI extraction decision |
| `BflaPriceManipulationEngine` | `probe_purchase_flow` | **Decision required** | Technique scope question; no trigger finding type; Juice Shop artifacts |
| `MetasploitRecipeEngine` | none (net-new) | **Coupled / Decision required** | `service_name→recipe` mapping absent; success detection unimplemented; input finding_type undecided |

---

## Per-probe sections

---

### 1. SqliAuthBypassEngine

**Probe:** `probe_sqli_auth_bypass` — `apps/investigation_workspace/suggestions/probes.py:635–1453` (818 lines)  
**Trigger finding type:** `sqli` (catalog.py:267–269)  
**Technique class:** `injection.sql`  
**Gate:** `sqli_auth_bypass` (new, default OFF)

#### 1.1 Current behavior

- **Endpoint discovery:** reads `detected_login_endpoints` from `FINDING_EVIDENCE_CTX` if set; otherwise calls `_sqli_find_login_endpoints()` against 6 candidate paths (probes.py:388–389; first entry `/rest/user/login` is Juice Shop-primary).
- **Payload loop:** 4 inline payloads in `_SQLI_PAYLOADS` (probes.py:394–399): `' OR 1=1--`, `admin@example.com' OR '1'='1`, `admin'--`, `' OR 1=1#`. Inner loop over payloads × endpoints; breaks on first bypass.
- **Bypass detection** (probes.py:786–812): HTTP 200 + token in body (`_sqli_extract_token`), or 3xx to non-login URL, or Set-Cookie present.
- **Post-exploit capture** (probes.py:831–1091): extracts `umail` via regex `r'"umail"\s*:\s*"([^"]+)"'` (probes.py:965–966); builds `bookmarklet_href` as `javascript:(function(){localStorage.setItem('token','…');location.reload();})()` (probes.py:998–1010); assembles `_pending_capture` including `_JUICE_SHOP_POST_EXPLOIT_ENDPOINTS` (probes.py:1012–1033); yields `ResultEvent(kind="detected")`.

#### 1.2 Lab couplings

| Coupling | Location | Lab | Lift action |
|---|---|---|---|
| `_JUICE_SHOP_POST_EXPLOIT_ENDPOINTS` — `/rest/user/whoami`, `/api/Users`, `/rest/basket`, `/api/BasketItems` | probes.py:416–421 | Juice Shop | Extract to `operator_params["post_exploit_endpoints"]`; default empty |
| Bookmarklet `localStorage.setItem('token',…)` | probes.py:994–1010 | Juice Shop SPA convention | **Drop**; bundler.py:177–178 auto-generates from `session_state` for any target |
| `umail` regex | probes.py:965–966 | Juice Shop response schema | Generalise: look for `email`, `umail`, `username` keys in parsed JSON |
| Juice Shop text in `_build_sqli_reproduction_markdown` | probes.py:531–633 | Juice Shop | Port as generic builder parameterised by `token_storage_convention` |
| `LOGIN_ENDPOINT_PATHS[0]` = `/rest/user/login` | probes.py:388; sqli_recon.py:33 | Juice Shop primary | Keep import from sqli_recon.py; Juice Shop path is first but not exclusive |
| Inline `_SQLI_PAYLOADS` vs `payload_registry.sqli_auth_bypass` | probes.py:394–399; payload_registry.py:42–47 | None | Use `load_payloads("sqli_auth_bypass")`; wrap each string as `{"email": s, "password": "x"}` |

#### 1.3 V2 substrate mapping

| Substrate module | Coverage |
|---|---|
| `exhaustion.py` | Direct fit. `technique_class="injection.sql"`, `detection_method="tautology_bypass"`. |
| `payload_registry.py` | `sqli_auth_bypass` registered (payload_registry.py:42–47). Minor format transform needed. |
| `target_adapters.http_post` | Covers the bypass POST. **Gap:** `http_post` injects existing session auth; bypass POST must be unauthenticated. Use raw httpx for the bypass loop. |
| `detection.py` | Not used. Bypass detection is application-layer (token presence, redirect target). Inline in engine. |
| `approval.py` / `branch_store.py` | Direct fit. |

**Post-exploit capture gap (critical):** The `_pending_capture` → runtime → `capture_post_exploit()` chain lives in `investigation_workspace/capture/bundler.py`. No V2 substrate equivalent. Three options (operator decision required — see §Operator decisions):

- **Option A:** Engine calls `capture_post_exploit()` directly (cross-layer dependency on workspace).
- **Option B:** Add `OutputChannel.create_capture_bundle()` — new seam, new pattern test (Pattern 15 candidate).
- **Option C:** Drop the endpoint sweep for this lift; emit session-token artifact only. Simplest; sweep can be added later.

#### 1.4 Pattern test candidates

- Pattern 12 (probe-to-engine atomicity): standard — retire `probe_sqli_auth_bypass` + catalog + route gate in same PR.
- **Pattern 15 candidate** (post-exploit capture seam): if Option A or B chosen — verify engine calls bundler with correct `investigation_id`, `endpoints`, `session_state`. If Option C, no new pattern needed beyond Pattern 12.

#### 1.5 Outcome preservation requirements

Must produce: `confirmed=True` bypass signal; severity `critical`/`high`/`info` per probes.py:475–485; evidence fields `payload_email`, `login_endpoint`, `token_captured`, `cookies_captured`, `response_status`, `indicators`; bookmarklet (via bundler auto-generate); `ExhaustionRecord` on all-payloads-failed.

#### 1.6 Rating: Decision required

Blocked by post-exploit capture decision. Everything else (exhaustion, branch lifecycle, session auth read, gate) maps cleanly to existing substrate.

---

### 2. CredentialBruteEngine

**Probe:** `probe_brute_force_login` — probes.py:2434–3066 (633 lines)  
**Trigger finding type:** `login_form_detected` (catalog.py:272–273)  
**Technique class:** `brute_force.credentials`  
**Gate:** `brute_force_login` (new, default OFF)

#### 2.1 Current behavior

- **Credential loading:** `auth_recon.load_default_credentials()` (auth_recon.py:421–444) prepends `_PRIORITY_CREDS = [("wiener", "peter")]`, then loads `probe/wordlists/default-passwords.csv` (2,875 SecLists pairs), falls back to 6-pair `_FALLBACK_CREDS`.
- **CSRF handling — per request:** if `csrf_field` is set, issues a fresh GET before every credential POST to extract `user_token` via `_USER_TOKEN_RE` regex (probes.py:2538; lab_auth.py:25–27). This is per-loop, not once at start.
- **Success detection:** `is_form_login_success()` (auth_recon.py:51–61) — HTTP 301/302 + `Location` does NOT contain login-failure keywords.
- **Session capture:** `dict(success_response.cookies)` stored in `_pending_capture` (probes.py:2613). Does NOT call `store_target_auth()` — captured session is NOT registered into `SessionOrchestrator`.
- **No-hints fallback** (probes.py:2471–2477): hardcodes DVWA form fields (`/login.php`, `user_token`, `{"Login": "Login"}`).

#### 2.2 Lab couplings

| Coupling | Location | Lab | Lift action |
|---|---|---|---|
| `_PRIORITY_CREDS = [("wiener", "peter")]` | auth_recon.py:416–418 | PortSwigger | Remove; use `payload_registry.load_payloads("brute_force_login")` only |
| `("wiener", "peter")` in `_FALLBACK_CREDS` | auth_recon.py:406–413 | PortSwigger | Remove from fallback |
| `_USER_TOKEN_RE` — hardcoded `name='user_token'` | lab_auth.py:25–27; imported at probes.py:2453–2455 | DVWA | Use `csrf_field` name from finding; build dynamic regex |
| DVWA form-field fallback | probes.py:2471–2477 | DVWA | **Drop entirely** — engine queries `normalized_findings` for `login_form_detected`; no fallback |
| Probe-local wordlist `probe/wordlists/default-passwords.csv` | auth_recon.py:400–403 | None (generic) | Decide: use payload_registry YAML (4 pairs) or port CSV to `data/payloads/` (2,875 pairs) — see operator decisions |

#### 2.3 V2 substrate mapping

- `is_form_login_success()` not in `detection.py` — must be ported inline.
- `target_adapters.http_post` injects existing session auth; brute force must NOT inject existing session — use raw httpx for credential POSTs.
- `payload_registry.py:49–55` has `brute_force_login` registered (YAML); file needs populating.
- `exhaustion.py` direct fit for all-creds-tried path.
- **Session write gap:** probe does not call `store_target_auth()`; engine should call `session_store.store_target_auth(base, {"cookies": ...})` after success to make session available downstream. Closes a probe behavioral gap (improvement over probe, not a breaking change).

#### 2.4 Pattern test candidates

**Pattern 15 candidate — CSRF token refresh invariant:**  
Contract: for every credential POST when `csrf_field` is non-None, a GET must immediately precede it. A mock server rotating tokens can verify `(GET, POST, GET, POST, …)` request sequence vs incorrect `(GET, POST, POST, POST, …)`. Silent failure mode: stale token → server rejects all attempts post-first → false exhaustion record. This is a new seam class (within-loop HTTP sequencing) not covered by Pattern 12.  
File: `tests/conductor/_patterns/test_seam_brute_force_csrf_refresh.py`.

#### 2.5 Outcome preservation requirements

Success: artifact `{username, form_action, attempt_number, session_cookies, http_status, location_header}`; `session_store.store_target_auth()` called; severity `"high"`. Exhaustion: `ExhaustionRecord(technique_class="brute_force.credentials", detection_method="redirect_heuristic", payloads_tried=[…], negative_evidence={attempts_made, last_status, last_location})`.

#### 2.6 Rating: Coupled

Three distinct lab couplings requiring modification to shared module `auth_recon.py`. Core logic (CSRF handling, success heuristic, brute iteration) is well-understood and generic. Wordlist source decision is the one remaining open question (see §Operator decisions).

---

### 3. CmdiReflectedEngine

**Probe:** `probe_cmdi_reflected` — probes.py:1454–1830 (377 lines)  
**Trigger finding type:** `command_injection`  
**Technique class:** `injection.cmdi`  
**Gate:** `cmdi_reflected_exploit` (new, default OFF)

#### 3.1 Current behavior

Preamble shared with blind variants: reads `FINDING_EVIDENCE_CTX` for recon hints; builds descriptor list `{path, param_name, form_action, needs_csrf}` via `_cmdi_candidate_targets()` (probes.py:1185–1224); calls `_cmdi_get_auth_state()` (probes.py:1162–1182) which calls `authenticate_dvwa(target)`.

Payload strategy: random 8-hex-char `marker` via `secrets.token_hex(4)` (probes.py:1541); `echo {marker}` via 5 POSIX separators + 2 variants = 7 payloads total. POSTs via `_cmdi_submit_payload()` (probes.py:1292–1316). Stops on first `marker in resp.text` hit (probes.py:1564). Follow-up: sends `whoami` and `id`, extracts output via `_cmdi_extract_pre_block()` (DVWA `<pre>…</pre>` parser, probes.py:1285–1289). Severity: `"critical"` if `"root"` in whoami, else `"high"` (probes.py:1700–1705).

#### 3.2 Lab couplings

| Coupling | Location | Lift action |
|---|---|---|
| `authenticate_dvwa()` call via `_cmdi_get_auth_state()` | probes.py:1176 (via 1488) | **Remove entirely**; read auth from `session_store.get_auth(investigation_id)` |
| DVWA credentials `admin/password` in `authenticate_dvwa` | lab_auth.py:22–23 | Not ported — lab_auth.py stays in probe layer |
| `_cmdi_extract_pre_block()` — DVWA `<pre>` output parser | probes.py:1285–1289 | Port inline as heuristic; document as DVWA-oriented |
| `COMMON_CMDI_PATHS[0,1]` — DVWA-specific paths | cmdi_recon.py:34–36 | Keep via import; DVWA paths are first but not exclusive |

#### 3.3 V2 substrate mapping

- `detection.reflection_check(payload, body)` (detection.py:15–21) covers marker-in-body check. Use it.
- `target_adapters.http_post` covers form-data POST; needs CSRF token pre-fetch layered on top (engine logic).
- `payload_registry.py:63–69` has `cmdi_reflected` registered → `data/payloads/cmdi_reflected.txt` (5 payloads). Note: probe uses inline builder (7 variants including commented forms). Use payload_registry at lift time; commented-separator variants can be added to the file.
- `exhaustion.py` direct fit.

#### 3.4 Rating: Coupled

`authenticate_dvwa()` removal is well-defined. `<pre>` parser must be ported inline as a heuristic. Correct CSRF handling per request must be preserved. Moderate complexity; no architectural surprises.

---

### 4. CmdiBlindTimeEngine

**Probe:** `probe_cmdi_blind_time` — probes.py:1831–2082 (252 lines)  
**Gate:** `cmdi_blind_time_exploit`

#### 4.1 Current behavior

3-sample baseline → skip candidate if `mean > 4s` → 2-sample probe confirmation; both samples must exceed `SLEEP_SECONDS * 0.9 = 4.5s` absolute threshold (probes.py:1924). **Note:** `exploitability_notes` string at probes.py:2067–2068 references the stale formula `"baseline + (3·σ) + 4.5s"` — actual logic is absolute threshold, not baseline-relative. No capture bundle (timing-only detection; `body_excerpt` = `"(time-based blind — no body to capture)"`).

#### 4.2 Key risks

- `detection.time_diff_significant()` uses a multiplier model; probe uses absolute threshold. **Mismatch.** Engine needs `time_exceeds_threshold(elapsed_ms, threshold_ms)` — add to `detection.py` or inline.
- 15s timeout per request (`3× SLEEP_SECONDS`) is critical — porting as 10s silently causes timeout before sleep completes.
- Two-sample confirmation (not one) is the anti-flake guard; collapsing to one sample silently degrades reliability.
- Stale comment must be corrected at lift time.

#### 4.3 Rating: Risky

Three correctness risks easy to miss in translation. Read probes.py:1899–1972 line-by-line before coding.

---

### 5. CmdiBlindBooleanEngine

**Probe:** `probe_cmdi_blind_boolean` — probes.py:2088–2367 (280 lines)  
**Gate:** `cmdi_blind_boolean_exploit`

#### 5.1 Current behavior

Per-separator strategy switch based on endpoint reflection detection (benign probe + `<pre>` block presence, probes.py:2168):
- **Strategy A (reflecting):** `[ 1 -eq 1 ] && echo OK` vs `[ 1 -eq 2 ] && echo OK`; differential = `has_ok` in `<pre>` block.
- **Strategy B (non-reflecting fallback):** `sleep 0` vs `sleep 5`; differential = timing (`<1500ms` / `>4500ms`).

Four requests per separator (2 true + 2 false). Both samples must confirm consistently.

#### 5.2 Known behavioral limitation

On non-DVWA targets without `<pre>` output rendering, `reflects=False` always → Strategy B always triggers → `CmdiBlindBooleanEngine` degenerates to timing, overlapping with `CmdiBlindTimeEngine`. This is a known behavioural limitation (not a bug); document in engine code.

#### 5.3 Rating: Coupled

Strategy-switch logic must be preserved exactly. Strategy B thresholds `<1500ms`/`>4500ms` should become named constants. `authenticate_dvwa()` removal required (same as Reflected). DVWA `<pre>` heuristic used for Strategy A discrimination.

---

### 6. One engine or three? — CmdiEngine decision

**Recommendation: three separate engines.** Grounds:

1. Detection methods are fundamentally different (marker-in-body, wall-clock sampling, paired TRUE/FALSE differential) — different HTTP loop structures, not dispatch modes.
2. Independent failure modes — operator arms each technique independently; three `exploitation_branches` rows per finding.
3. Code size — each engine ~300–450 lines; one combined engine would exceed the 800-line limit.
4. Gate granularity — operator can enable reflected without enabling blind variants.
5. Pattern 12 seam tests are simpler as three files than one combined file.
6. Probe comment at probes.py:1094–1107 explicitly states "Three genuinely-distinct techniques, NOT three modes of the same probe."

Each lift is a separate PR (one per engine, per the V2.2 bounded-PR rule).

---

### 7. DefaultCredsEngine

**Probe:** `probe_api_default_creds_auth` — probes.py:4271–4354 (84 lines)  
**Trigger finding types:** `api_exposure`, `api_idor`, `api_bola` (catalog.py:275–277 — surfaces alongside `probe_api_exploit`)  
**Technique class:** `brute_force.default_credentials`  
**Gate:** `api_default_creds_auth` (new, default OFF; no existing route-layer `?confirm=` gate to delete)

#### 7.1 Current behavior

Delegates to `auth_recon.load_default_credentials()` + `auth_recon.attempt_default_creds_login()`. The probe is 84 lines; all logic is in `auth_recon.py`. On success: writes `auth_result` to `_get_session_orch().store_target_auth(base, auth_result)` (probes.py:4302). Emits `ResultEvent(kind="detected"/"note")`. No `FindingEvent` with `finding_type` emitted — this is a utility/setup action, not a classified finding.

#### 7.2 Lab couplings

Same `_PRIORITY_CREDS = [("wiener", "peter")]` as CredentialBruteEngine (auth_recon.py:416–418). Same removal action. Payload registry has `default_creds_auth` registered (payload_registry.py:84–98); YAML has 5 generic pairs.

#### 7.3 V2 substrate gaps (blockers)

**Blocker A — `OutputChannel` lacks `store_auth()`:**  
The probe writes to `SessionOrchestrator._target_auth` (URL-keyed) via `store_target_auth()`. V2 engines read from `SessionOrchestrator._api_auth_store` (investigation-keyed) via `session_store.get_auth(investigation_id)`. These are two separate dicts (session.py:72–74). The engine must write to `_api_auth_store`; no engine-accessible path exists today. Resolution: add `OutputChannel.store_auth(investigation_id, auth)` method (delegates to `self._session_orch.store_auth()`). This is a substrate PR prerequisite.

**Blocker B — No trigger finding to anchor the branch:**  
`XssReflectedEngine` queries `normalized_findings` for `missing_csp_header` rows to get `(finding_id, target)` pairs. `DefaultCredsEngine` has no singular trigger — it fires on `api_exposure`/`api_idor`/`api_bola`. Options: (a) receive `parent_finding_id` in `config` dict; (b) query `normalized_findings` for the parent finding types at engine startup; (c) target-level branch (no per-finding anchor). Decision required before coding.

#### 7.4 Pattern test candidates

**New pattern candidate — Engine Auth Write Seam:**  
After `DefaultCredsEngine.run()` succeeds, `session_store.get_auth(investigation_id)` must return non-None. If `OutputChannel.store_auth()` is absent, downstream engines read `None` and run unauthenticated silently. Test: (a) `OutputChannel` exposes `store_auth()`, (b) mock-run with stubbed successful login → `get_auth()` non-None, (c) on login failure → `get_auth()` remains None, no exception.  
File: `tests/conductor/_patterns/test_seam_default_creds_auth_write.py`.

#### 7.5 Rating: Decision required

Two substrate blockers (Blocker A, Blocker B). Once resolved, the lift itself is mechanically straightforward — `_PRIORITY_CREDS` is the only lab coupling; core auth logic in `auth_recon.py` is generic.

---

### 8. AccessControlEngine

**Probes:** `probe_api_exploit` (probes.py:3067–3621, 555 lines) + `probe_api_idor_mutate` (probes.py:3623–4258, 636 lines)  
**Trigger finding types:** `api_exposure`, `api_idor`, `api_bola`  
**Technique class:** `access_control.api`  
**Gate:** `api_access_control` (new, default OFF)

#### 8.1 Current behavior

`probe_api_exploit`: (1) OpenAPI discovery against 14 candidate paths (probes.py:3091–3152); (2) spec parsing → `user_endpoints` extraction; (3) self-authentication via `attempt_default_creds_login()` (bypasses SessionOrchestrator); (4) cross-user GET enumeration with `_TARGET_USERS = ("carlos", "administrator", "admin")` (probes.py:2753–2757).

`probe_api_idor_mutate`: operator-triggered follow-on; re-runs phases 1–3, then dispatches either a single operator-selected mutation or all non-GET mutations against all target users.

#### 8.2 Lab couplings

| Coupling | Location | Lab | Action |
|---|---|---|---|
| `"carlos"` in `_TARGET_USERS` | probes.py:2754 | PortSwigger lab victim | Replace with operator-configurable list |
| HTML API doc table signals with `[param]` bracket syntax | probes.py:2939–2941; 2982 | PortSwigger bespoke API doc page | Retain detection; document as heuristic |
| `attempt_default_creds_login()` in Phase 3 | probes.py:3253–3284 | Architecture violation | **Delete Phase 3 entirely**; read from `session_store.get_auth()` |
| `/rest` in `_URL_PREFIXES` | probes.py:2888 | Juice Shop API prefix | Retain (harmless on non-Juice-Shop; `/rest` is a valid REST prefix) |

#### 8.3 V2 substrate gaps

- `target_adapters.py` has only `http_get` and `http_post`. Mutating IDOR requires DELETE/PATCH/PUT. **Add `http_request(method, url, …)` to `target_adapters.py`** if mutating IDOR is in scope. Small addition (~40 lines).
- OpenAPI discovery (phases 1–2) is 130+ lines shared between `probe_api_exploit` and `probe_api_idor_mutate` (which re-runs it independently). Decision: inline as `XssReflectedEngine` did with detection helpers, or extract to `apps/conductor/exploitation/api_discovery.py` for reuse across current and future API engines.
- `detection.py` has no access-control failure detector. IDOR positive = `200 <= status < 300` on cross-user GET. Inline in engine.
- `payload_registry.py:91–97` has `api_access_control` registered; `data/payloads/api_access_control.yaml` needs to be created.

#### 8.4 Decisions required before coding

1. **Scope:** IDOR-GET only (cleaner, `probe_api_exploit` retired), or IDOR-GET + mutating IDOR in one PR? Mutating IDOR requires `http_request()` addition and redesigning `ACTION_ID_CTX`/`OPERATOR_INPUTS_CTX` as `config` dict parameters.
2. **OpenAPI extraction:** inline helpers, or extract shared `api_discovery.py` module?
3. **`probe_api_idor_mutate` fate:** lift as second engine in same PR, separate PR, or defer?
4. **`_TARGET_USERS` replacement:** operator `config["target_users"]` param or payload registry YAML?

#### 8.5 Rating: Coupled / Decision required

Auth stripping (Phase 3 deletion) is mandatory and well-defined. Lab coupling (`"carlos"`) is straightforward to make configurable. Scope decision (IDOR-GET only vs. mutating IDOR) is the primary gating question.

---

### 9. BflaPriceManipulationEngine

**Probe:** `probe_purchase_flow` — probes.py:4806–4894 + `apps/investigation_workspace/probe/purchase_flow.py` (484 lines core)  
**Trigger finding types:** `api_exposure`, `api_idor`, `api_bola` (same as AccessControlEngine)  
**CRITICAL_KINDS:** yes — already in `_EXPLOITATION_ACTIONS` (routes.py:1360)

#### 9.1 Current behavior

5-step exploitation chain: (0) PATCH price endpoint to zero; (1) add to cart; (2) extract CSRF; (3) checkout; (4) detect success via 10 keywords. Orchestrates across 5 candidate price paths, 5 PATCH body shapes, 5 add-to-cart endpoint patterns, 6 checkout endpoint patterns. Full chain completes in one probe run.

#### 9.2 Lab couplings — quantified

All core endpoint templates and field names are lab-shaped:
- Price paths (`/api/products/{pid}/price`, `/api/items/{pid}/price`, `/api/product/{pid}/price`) — Juice Shop + PortSwigger shaped (purchase_flow.py:128–133)
- PATCH body shapes including `{"price":0}`, `{"amount":0}`, `{"cost":0}` — specific lab schemas (purchase_flow.py:25–31)
- Cart endpoint `POST /api/basket` with field `productId` — Juice Shop verbatim (purchase_flow.py:44)
- `"redir": "CART"` in cart POST body — PortSwigger shaped (purchase_flow.py:40)
- `"is-solved"` in success keywords — PortSwigger challenge-solved banner; **false positive risk on real targets** (purchase_flow.py:67)
- Internal re-authentication via `attempt_default_creds_login()` — architecture violation

#### 9.3 Operator decision surface

1. **Technique scope:** Does BFLA price manipulation qualify as a distinct V2.2 engine? The ~8-engine bound requires explicit operator approval for engine #9+. The technique is application-domain-specific (requires a shopping cart + checkout flow); it does not generalize to the reference scenario (telnet + HTTP login chain); `probe_api_exploit` already covers BFLA at the authorization-check level.

2. **Config requirements:** Minimum viable config to run generically: `price_endpoint_path`, `price_field_name`, `price_http_method`, `cart_endpoint_path` + `cart_body_schema`, `checkout_endpoint_path`. 5–6 required config fields makes this a heavily operator-guided technique — closer to a guided action than an automated engine.

3. **`"is-solved"` keyword:** Must be removed or gated before any lift — it is a PortSwigger lab artifact that is a false-positive risk in production detection.

4. **No trigger finding type:** No FilterOrchestrator rule produces a `bfla_price_manipulation` or `writable_price_endpoint` finding. A lift requires either wiring a new finding type + rule, or triggering on `api_idor`/`api_bola` with broad discovery inline (imprecise for an engine).

5. **`target_adapters.py` gap:** No `http_patch()`. Required for price manipulation. Small addition; could be shared with AccessControlEngine.

**Recommendation for operator:** Defer to V2.3+ or later. The technique is not applicable to the reference scenario; `probe_api_exploit` already provides access-control coverage at the authorization-check level; and the required infrastructure (new finding type, new FilterOrchestrator rule, `http_patch`, 5–6 operator config fields) adds scope that outweighs the V2.2 marginal value.

#### 9.4 Rating: Decision required

Primary question: is this in scope for V2.2 at all?

---

### 10. MetasploitRecipeEngine

**Source:** `apps/validation/services/metasploit.py` (MsfClient), `msf_recipes.py` (RECIPES), `msf_wordlists.py` (WORDLISTS), `apps/validation/api/metasploit.py` (live routes)  
**Trigger finding type:** TBD — no existing probe to retire (net-new capability)  
**Technique class:** `metasploit.module_execution`

#### 10.1 Current behavior

**MsfClient** (metasploit.py:41–360): Process-wide singleton, lazy connect via `pymetasploit3`. All blocking calls go through `asyncio.to_thread`. Public interface: `status()`, `search()`, `module_info()`, `run_via_console(module_type, module_path, options, mode, timeout_s=300)`. `run_via_console` is synchronous-then-return — polls msfconsole `console.read()` in a loop until no new data for 1.5s with total timeout (`timeout_s + 30` seconds). Returns full console output as a single string. No streaming.

**RECIPES** (msf_recipes.py:34–516): 11 service keys (`telnet`, `ssh`, `ftp`, `smb`, `http`, `https`, `rdp`, `mysql`, `mssql`, `snmp`, `vnc`). Each entry has a `modules` list with `{type, path, intent, what_it_does, required, success, failure}`. The reference scenario (telnet port 23) maps to `RECIPES["telnet"]`. No lab-specific modules; all paths are standard Metasploit framework modules.

**Live routes** (api/metasploit.py): Isolated from the Conductor pipeline (api/metasploit.py:6–7). `POST /metasploit/run` writes `MsfRun` rows to `msf_runs` table — independent of `exploitation_branches`. No conflict with engine path.

#### 10.2 Lab couplings

None. RECIPES are fully generic. WORDLISTS are hardcoded to `/usr/src/metasploit-framework/data/wordlists/…` — msfrpcd's own container filesystem paths; not lab-specific.

#### 10.3 V2 substrate gaps

- **`service_name → recipe_key` mapping absent.** RECIPES are keyed by UI service string; `service_detected` findings carry `evidence["service_name"]` as produced by nmap (e.g., `"telnetd"`, `"ssh"`, `"microsoft-ds"`). A normalization lookup table (e.g., `"telnetd" → "telnet"`, `"microsoft-ds" → "smb"`) must be designed and tested.
- **No streaming to `emit_stage()`:** `run_via_console` returns only after completion. Engine can emit `"running"` before the call, `"succeeded"`/`"exhausted"` after. Mid-execution streaming requires refactoring `_drain()` (not blocking for V2.2).
- **Success/failure detection unimplemented:** RECIPES `success`/`failure` strings are documentation-only, not regex patterns. Engine author must write detection logic from scratch. Key signals: `[+]`/`[-]`/`[!]` prefixes, `"session N opened"`, `"LOGIN SUCCESSFUL:"`.
- **Input finding type undecided:** Engine consumes `service_detected` findings (most coherent — maps to RECIPES service keys). Must be confirmed to drive the DB query pattern (analogous to `_query_csp_findings` in xss_exploit_engine.py:150–165).

#### 10.4 Pattern test candidates

**New pattern — Recipe lookup seam (Pattern 15 or 16 candidate):**  
Contract: every `service_detected` finding with a known `service_name` must map to a RECIPES entry; unknown `service_name` must produce an ExhaustionRecord, not a silent no-op. Analogous to Pattern 5 (dangling reference) but for the recipe lookup domain. Test: (a) known service name → correct recipe selected, (b) unknown service name → ExhaustionRecord with reason, (c) `None`/empty `service_name` → fail-closed.  
File: `tests/conductor/_patterns/test_seam_msf_recipe_lookup.py`.

#### 10.5 Rating: Coupled / Decision required

Primary decision: what `finding_type` does the engine consume? `service_detected` is the correct answer; confirm before writing the DB query. `service_name → recipe_key` mapping must be designed (new seam). Success detection must be written from scratch. MsfClient itself is stable and wrappable.

---

## Synthesis

---

### Recommended lift order

| Priority | Engine | Rationale |
|---|---|---|
| 1 | **CredentialBruteEngine** | Coupled (manageable). Highest operator verification value — fires on `login_form_detected` which the current reference target produces. Pattern 15 CSRF-refresh seam test is well-defined. Clear lab couplings with known resolutions. Lift this first. |
| 2 | **CmdiReflectedEngine** | Coupled. Proves the three-engine split pattern. Reflected is the most operator-verifiable (captured whoami/id output). `authenticate_dvwa()` removal is well-defined. Defer blind variants until Reflected lifts cleanly. |
| 3 | **CmdiBlindTimeEngine** | Risky. Lift after Reflected only. Read probes.py:1899–1972 in full before coding. Two-sample threshold logic and 15s timeout are the correctness risks. |
| 4 | **CmdiBlindBooleanEngine** | Coupled. Lift after BlindTime. Strategy-switch must be preserved; document behavioral limitation. |
| 5 | **SqliAuthBypassEngine** | Decision required, then Coupled. Block until post-exploit capture decision made (Option A/B/C). Core bypass logic maps cleanly to substrate once decision is recorded. |
| 6 | **DefaultCredsEngine** | Decision required. Requires **substrate PR first**: add `OutputChannel.store_auth()` + resolve trigger finding anchor. Once substrate PR merges, lift is mechanically straightforward. |
| 7 | **AccessControlEngine** | Coupled / Decision required. Scope decision (IDOR-GET-only vs. mutating IDOR) must be made first. IDOR-GET-only is the Coupled-rated path; mutating IDOR adds `http_request()` substrate work and redesign of `ACTION_ID_CTX` as config params. |
| 8 | **MetasploitRecipeEngine** | Decision required. Confirm input `finding_type` = `service_detected`. Design `service_name → recipe_key` mapping. Net-new, no probe to retire — can be parallelised with any lift that doesn't share substrate work. |
| Deferred | **BflaPriceManipulationEngine** | Decision required. Not applicable to reference scenario; technique is domain-specific; ~8-engine bound needs explicit approval for engine #9+. Recommended for V2.3+ or permanently deferred. |

---

### Substrate extensions needed (cross-engine concerns)

These affect multiple lifts and must be resolved — either as a prerequisite substrate PR or as part of the first affected engine lift.

| Extension | Affects | Blocking? | Recommended action |
|---|---|---|---|
| **`OutputChannel.store_auth(investigation_id, auth)`** | DefaultCredsEngine | Blocks lift #6 | Prerequisite substrate PR before DefaultCredsEngine lift. Small addition (~15 lines in `OutputChannel`). Also add Pattern test for engine-auth-write seam. |
| **`target_adapters.http_patch()`** | AccessControlEngine (mutating path), BflaPriceManipulationEngine | Blocks mutating IDOR scope | Add in AccessControlEngine lift PR if mutating IDOR is in scope. Else defer. |
| **`detection.time_exceeds_threshold(elapsed_ms, threshold_ms)`** | CmdiBlindTimeEngine | Inline alternative available | Either add to `detection.py` in same PR (1 function, ~10 lines) or implement inline in CmdiBlindTimeEngine. |
| **`payload_registry` YAML population** | CredentialBruteEngine (`brute_force_login.yaml`), SqliAuthBypassEngine (format transform) | Decision required for brute force | Populate `data/payloads/brute_force_login.yaml` with SecLists CSV content (2,875 pairs) in lift PR or as separate prerequisite. |
| **`data/payloads/api_access_control.yaml` creation** | AccessControlEngine | Lift-PR scope | Create in AccessControlEngine lift PR. |

**No substrate extensions block lifts #1–4 (CredentialBrute, CmdiReflected, CmdiBlindTime, CmdiBlindBoolean).** Those can begin immediately after operator decisions are recorded.

---

### Cross-engine concerns

1. **`authenticate_dvwa()` appears in all three cmdi probes and `probe_purchase_flow`** — all share the same call site via `_cmdi_get_auth_state()`. Removing it in CmdiReflectedEngine lift PR will remove it from the probe layer; the engine never imports `lab_auth.py`. Confirm `lab_auth.py` is not deleted in any cmdi PR (it is still referenced by `probe_brute_force_login` via `_USER_TOKEN_RE` import at probes.py:2453–2455 and by the probe-layer CSRF handling).

2. **`_PRIORITY_CREDS = [("wiener", "peter")]` in `auth_recon.py`** is shared between `probe_api_default_creds_auth` (probes.py:4291) and `probe_brute_force_login` (probes.py:2502). Removing it from `auth_recon.py` in CredentialBruteEngine PR will affect both probes simultaneously — confirm this is the right time or separate the removal.

3. **`probe_api_idor_mutate` fate must be decided before AccessControlEngine PR is drafted.** If it is not lifted in the same PR as `probe_api_exploit`, it remains as an ACTIVE-LEGACY probe after `probe_api_exploit` is retired. The mutating-endpoint next-action cards generated by `probe_api_exploit` will then surface a probe that still runs through the legacy route layer. This is a partial retirement — acceptable only if explicitly documented as planned (Pattern 12 invariant requires the catalog entry absence check, not the follow-on card behavior).

4. **OpenAPI discovery logic duplication.** Both `probe_api_exploit` and `probe_api_idor_mutate` re-run OpenAPI discovery independently (probes.py:3091–3152, 3647–3690). If both are lifted in the same PR, this is the right time to extract a shared `api_discovery.py` helper in `apps/conductor/exploitation/`. If only `probe_api_exploit` is lifted, inline as `XssReflectedEngine` precedent.

5. **No Pattern 12 atomicity obligation for MetasploitRecipeEngine** — there is no existing probe to retire. The engine is purely additive. This simplifies the lift substantially; the only retirement obligation is ensuring no duplicate execution path exists (there is none).

---

### Operator decisions surfaced

These questions have no proposed answers — each requires explicit operator decision before the affected PR is drafted.

**D1 — SqliAuthBypassEngine post-exploit capture:**  
Option A: engine calls `investigation_workspace/capture/bundler.py` directly (cross-layer dependency).  
Option B: add `OutputChannel.create_capture_bundle()` — new seam, Pattern 15 test obligation.  
Option C: drop endpoint sweep; emit session-token artifact only for initial lift.  
*Which option?*

**D2 — CredentialBruteEngine wordlist source:**  
Probe-local `probe/wordlists/default-passwords.csv` has 2,875 SecLists pairs. Registry YAML `data/payloads/brute_force_login.yaml` has 4 generic pairs. The engine should load from one source.  
*Populate the YAML from SecLists CSV (2,875 pairs) as the authoritative source, or implement a two-source loader?*

**D3 — DefaultCredsEngine trigger finding anchor:**  
Option A: receive `parent_finding_id` in `config` dict (explicit, requires callsite to supply it).  
Option B: query `normalized_findings` for `api_exposure`/`api_idor`/`api_bola` at engine startup.  
Option C: target-level engine — one branch per investigation, no per-finding anchor.  
*Which option?*

**D4 — AccessControlEngine scope:**  
Option A: IDOR-GET only (retire `probe_api_exploit`; leave `probe_api_idor_mutate` as ACTIVE-LEGACY with explicit deferral note).  
Option B: IDOR-GET + mutating IDOR in one PR (requires `http_request()` addition, redesign of operator-input wiring).  
*IDOR-GET-only is the cleaner first lift; which is preferred?*  
**D4 RESOLVED — Step 11 + consolidated cleanup: Option A chosen; D4 REVISED in Step 11 consolidated cleanup: `probe_api_idor_mutate` dropped entirely (not ACTIVE-LEGACY). Mutating IDOR deferred to operator-driven Burp/curl. Architecture violation (Phase 3 self-auth bypass), lab coupling (`_TARGET_USERS`), and cleaner V2 state drove the revision.**

**D5 — AccessControlEngine OpenAPI discovery:**  
Option A: inline helpers in engine (XssReflectedEngine precedent — probes.py helper functions ported inline).  
Option B: extract to shared `apps/conductor/exploitation/api_discovery.py` for reuse across future API engines.  
*Extract to shared module recommended if AccessControlEngine + future API engines will all need it; inline if AccessControlEngine is the only consumer in V2.2.*

**D6 — BflaPriceManipulationEngine scope:**  
As documented in §9.3: the technique is domain-specific, not applicable to the reference scenario, requires ~6 operator config fields, and would be engine #9+ (beyond the ~8-engine bound). `probe_api_exploit` covers BFLA at the authorization-check level.  
*Confirm: defer to V2.3+ or permanently deferred?*

**D7 — MetasploitRecipeEngine input finding type:**  
`service_detected` findings (carrying `evidence["service_name"]`) are the most coherent trigger — they map to RECIPES service keys and are produced by `NmapEngine` when the `nmap_external_scan` gate is ON.  
*Confirm `service_detected` as the input finding type for MetasploitRecipeEngine.*

---

## Files audited

| File | Lines | Role |
|---|---|---|
| `apps/investigation_workspace/suggestions/probes.py` | 4,894 | All probe functions |
| `apps/investigation_workspace/suggestions/catalog.py` | ~350 | SuggestionSpec registry |
| `apps/investigation_workspace/probe/purchase_flow.py` | 484 | BflaPriceManipulation core |
| `apps/investigation_workspace/probe/lab_auth.py` | ~150 | DVWA auth + `_USER_TOKEN_RE` |
| `apps/investigation_workspace/probe/auth_recon.py` | ~450 | `_PRIORITY_CREDS`, `load_default_credentials`, `is_form_login_success`, `attempt_default_creds_login` |
| `apps/conductor/engines/xss_exploit_engine.py` | 425 | V2.2 Step 1 reference pattern |
| `apps/conductor/exploitation/approval.py` | 100 | Arm state machine |
| `apps/conductor/exploitation/detection.py` | 94 | Response analysis helpers |
| `apps/conductor/exploitation/exhaustion.py` | 88 | ExhaustionRecord emitter |
| `apps/conductor/exploitation/payload_registry.py` | 162 | Payload/wordlist registry |
| `apps/conductor/exploitation/target_adapters.py` | 198 | HTTP request helpers |
| `apps/conductor/exploitation/branch_store.py` | 186 | exploitation_branches DB writer |
| `apps/validation/services/metasploit.py` | ~360 | MsfClient |
| `apps/validation/services/msf_recipes.py` | ~520 | RECIPES catalog |
| `apps/validation/services/msf_wordlists.py` | ~130 | WORDLISTS catalog |
| `apps/validation/api/metasploit.py` | ~200 | Live Metasploit routes |
