# V2 Design Audit

**Date:** 2026-05-26  
**Scope:** Read-only inventory of scan data, probe/template code, and exploitation UI — inputs for V2 exploitation template design.  
**Sources:** DB queries (validation.db, orchestration.db), grep/file reads of all referenced directories, UI route trace.  
**Method:** Three parallel subagents (A: DB, B: code catalog, C: UI trace) + sequential synthesis.

---

## Part 1 — What the System Produced (DB State)

### Most Recent Investigation

- **Target:** `https://0a9900fa0370fae780a90dee00220046.web-security-academy.net/` (PortSwigger lab)
- **Run:** 2026-05-26 01:57:35 UTC, investigation `d0b271a0`, status `active`/`detection` in validation.db
- **16 normalized_findings** total

### Finding Type Breakdown

| finding_type | Count | Source | Phase | validation_status |
|---|---|---|---|---|
| `vulnerability_assessed` | 7 | nuclei | enumeration | 4 dropped, 3 pending |
| `missing_*_header` | 5 | passive_probe | recon | all dropped |
| `api_exposure` | 1 | api_recon | enumeration | **validated** |
| `http_service_detected` | 1 | passive_probe | recon | dropped |
| `login_form_detected` | 1 | auth_recon | enumeration | **incomplete** (csrf_token_needed gap) |
| `sqli` | 1 | sqli_recon | enumeration | **validated** |

### Validation Status

| Status | Count | Notes |
|---|---|---|
| dropped | 10 | FilterOrchestrator ran correctly |
| pending | 3 | vulnerability_assessed (wildcard-dns-detect x2, secrets-patterns-pii x1) — no matching rule |
| validated | 2 | api_exposure + sqli — passed to exploitation phase |
| incomplete | 1 | login_form_detected — CSRF gap surfaced |

No `exploitable` boolean column exists. `validated` is the system's equivalent of "worth exploiting." Two validated findings; one incomplete (exploitable with CSRF workaround).

### Absent Finding Types (Expected, Gate-Blocked)

- `service_detected` from nmap — `nmap_external_scan` gate is OFF (default); without it, the plugin chain (TelnetEngine, SshEngine, etc.) cannot fire for external targets.
- `zap_endpoint_discovered`, `zap_alert` — ZAP gates OFF.
- `cmdi_recon` — CmdiReconEngine requires service_detected chain trigger; not fired.

### Key DB Anomaly

The investigation ID in validation.db (`d0b271a0`) does not match the one in orchestration.db (`5461956e`) for the same target+timestamp. `engine_runs` table in orchestration.db has 0 rows — per-engine execution detail is not queryable. Root cause unclear; may be a separate execution path writing to each DB independently.

---

## Part 2 — Exploitation Code Inventory

### 2A — Conductor Engines (all LIVE)

| Engine | Technique Class | Reusability | Tests |
|---|---|---|---|
| SqliReconEngine | SQLi — login endpoint discovery (presence only, no payloads) | Generic; candidate-path override | Yes |
| AuthReconEngine | HTML login form detection; field mapping (CSRF, username, password) | Generic; candidate-path override | Yes |
| CmdiReconEngine | Cmdi endpoint discovery; form structure + auth-required detection | Mostly generic; DVWA-shaped path list | Yes |
| SshEngine | SSH default-credential brute force (paramiko); banner fallback | Fully generic; wordlist configurable | Yes |
| TelnetEngine | Telnet cleartext-credential exposure proof; proves cleartext, no brute | Fully generic; protocol-level | Partial |
| SmbEngine | SMB null-session enumeration (impacket); TCP banner fallback | Fully generic | Partial |
| WordpressEngine | WP-specific: SQLi exposure, user enum, XML-RPC, config backup | Generic within WordPress | Partial |
| DrupalEngine | Drupal-specific: Drupalgeddon2, admin exposure, JSON API, SQLi <7.32 | Generic within Drupal | Partial |
| ApacheEngine | Apache misconfig: version disclosure, server-status, TRACE, directory listing | Generic Apache | Partial |
| NginxEngine | Nginx misconfig: version, .git/HEAD, .env, status page | Generic Nginx | Partial |

### 2B — Suggestion Probes (LIVE via `/suggest/{action_kind}/execute`, bypass Conductor)

| Probe (action_kind) | Technique Class | Reusability | Lab Coupling | Tests |
|---|---|---|---|---|
| `sqli_auth_bypass` | SQLi auth bypass; boolean tautology payloads against login forms | Core logic generic | Post-exploit: Juice Shop (`/rest/user/whoami`, `localStorage.token`, `umail`) | None |
| `brute_force_login` | Default credential brute force; HTML form with CSRF token handling | Mostly generic | Priority creds: `wiener/peter` (PortSwigger account) | None |
| `cmdi_reflected` | Reflected cmdi; 7 POSIX separator variants; `whoami`/`id` capture | Technique generic | `authenticate_dvwa()` fallback hardcodes DVWA paths+`admin/password` | None |
| `cmdi_blind_time` | Time-based blind cmdi; sleep payload; delay detection | Fully generic technique | Same DVWA fallback | None |
| `cmdi_blind_boolean` | Boolean blind cmdi; true/false condition differential | Fully generic technique | Same DVWA fallback | None |
| `csp_xss_reflected` | Reflected XSS; marker payload; sanitization context detection | Fully generic | None detected | None |
| `api_default_creds_auth` | Default credential auth; form-urlencoded + JSON; caches to `_API_AUTH_STORE` | Mostly generic | Priority creds: `wiener/peter` | None |
| `api_full_discovery` | API endpoint enum (SecLists wordlist + 401/403 confirm) | Generic | None detected | None |
| `api_authed_recon` | Authenticated page scraping (BeautifulSoup) | Generic | None detected | None |
| `api_endpoint_enum` | HTTP method enumeration per endpoint | Generic | None detected | None |
| `api_browser_recon` | Playwright headless browser traffic interception | Generic | None detected | None |
| `api_exploit` | API IDOR/BOLA; cross-user GET; mutating actions; OpenAPI discovery | Mostly generic | OpenAPI path patterns Juice Shop-shaped | None |
| `purchase_flow` | Full BFLA price manipulation → cart → checkout | Core logic partially generic | Endpoint path templates + success keywords Juice Shop/PortSwigger-shaped | None |

### 2C — Guided Actions (ACTIVE-LEGACY, live via `investigation_core_router`)

| Action Group | Technique Class | Reusability |
|---|---|---|
| SQLI_ACTIONS (4 steps) | Manual-guided SQLi: injection detection → boolean confirmation → UNION extraction → auth bypass | Fully generic (manual; operator executes) |
| AUTH_ACTIONS (2 steps) | Manual-guided: default creds testing, session token analysis | Fully generic |
| XSS_ACTIONS (2 steps) | Manual-guided: XSS reflection probe, execution confirmation | Fully generic |

These go through an approval state machine. Evidence is manually attached. No automated probe runner. Live routes but low operator exposure (no UI surface to access them in the main workspace).

### 2D — Metasploit Stack (all LIVE, operator-driven)

| Component | Technique Class | Reusability |
|---|---|---|
| MsfClient (`metasploit.py`) | Full Metasploit RPC wrapper; any module | Fully generic |
| RECIPES (`msf_recipes.py`) | Static curated module recipes for 9 services; recon→enum→creds→vuln→exploit | Fully generic, offline |
| WORDLISTS (`msf_wordlists.py`) | 40+ MSF wordlist file catalog; 10+ credential categories | Fully generic |

---

## Part 3 — Exploitation UI Card Driver Trace

### Card Architecture

The Exploitation tab is driven exclusively by the `suggestions/` layer:

1. `exploitation_paths/next_actions.py` → `NEXT_ACTIONS_BY_PATH` catalog → ghost action nodes in the React Flow mind tree
2. React Flow (`exploit-tree.js`) classifies nodes as CRITICAL_KINDS (arm-gate) vs non-critical (direct execute)
3. Click routes to `POST /suggest/{action_kind}/execute` → `execute_suggestion()` in `routes.py`
4. `suggestions/catalog.py` `find_spec(action_kind)` resolves the `SuggestionSpec`
5. `spec.probe_runner` (async generator in `suggestions/probes.py`) runs the actual probe
6. Results live in in-memory `ExecutionRun` objects only — NOT written to validation.db

### "Execute →" (blue) vs "Arm exploit →" (orange→red)

Both use the same backend route and same probe runner. The only difference is a two-step client-side guard:

- **Execute →**: single click; no `?confirm=` param required
- **Arm exploit →**: click 1 arms (5-second window); click 2 appends `?confirm=<action_kind>`; server returns HTTP 409 without it

CRITICAL_KINDS / `_EXPLOITATION_ACTIONS` (9 kinds): `sqli_auth_bypass`, `brute_force_login`, `cmdi_reflected`, `cmdi_blind_time`, `cmdi_blind_boolean`, `purchase_flow`, `api_exploit`, `csp_xss_reflected`, `api_full_discovery`. These sets are in sync between JS and Python.

### Current Exploitation UI State

**Working end-to-end:** All 17 action_kinds with a registered `probe_runner` in `catalog.py`.

**Ghost-node dead ends (render but 404 on click):** Several `next_actions.py` entries have no matching `SuggestionSpec`:
- `xss_stored_persistence_check`, `xss_stored_context_probe`
- `auth_default_creds_check`, `auth_rate_limit_probe`
- `srf_token_check`, `csrf_samesite_cookie_check`
- `svc_fingerprint_deep`

**Not surfaced in context panel (no `SUGGESTIONS` dict entry):** `api_bola`, `auth_bypass`, `auth_session_hijack` finding types — these finding types have no entry in `catalog.py`; ghost nodes may appear in the mind tree but no context-panel buttons render.

**Legacy evidence shape:** 9 `ResultEvent` calls in `probes.py` still use the pre-Phase-54 evidence shape; these render as "Legacy evidence" in the structured panel.

**Critical architectural note:** The `suggestions/` probe execution path bypasses Conductor, StorageBridge, and FilterOrchestrator entirely. Probe results are session-scoped in-memory objects. A process restart loses all execution history. Exploitation actions do not write to validation.db.

---

## Part 4 — Synthesis

### 4A — Coverage Matrix

| Technique Class (from scan data) | Finding Type(s) | Probe/Template Exists? | State | Gap? |
|---|---|---|---|---|
| SQL injection payload delivery | `sqli` (validated) | `probe_sqli_auth_bypass` | LIVE, partial lab coupling | Partial — core logic usable; post-exploit capture Juice Shop-specific |
| API access control bypass (IDOR/BOLA) | `api_exposure` (validated) | `probe_api_exploit`, `probe_api_full_discovery`, `probe_api_authed_recon` | LIVE | Covered |
| Credential attack with CSRF handling | `login_form_detected` (incomplete) | `probe_brute_force_login` | LIVE, lab coupling in priority creds | Partial — CSRF handling present; priority creds `wiener/peter` need operator config |
| Subdomain takeover recon | `vulnerability_assessed` (wildcard-dns, pending) | None | — | **GAP — no exploitation path wired** |
| Static secret extraction | `vulnerability_assessed` (secrets-pii, pending) | None | — | **GAP — no exploitation path wired** |
| XSS payload delivery | `missing_csp_header` (dropped — no injection point) | `probe_csp_xss_reflected` | LIVE, generic | Available but source finding is dropped; no co-located injection finding |
| SSH brute force | No `service_detected` (gate-blocked) | `SshEngine` | LIVE, fully generic | Gate-blocked — needs `nmap_external_scan` ON to trigger for this target type |
| Telnet cleartext capture | No `service_detected` | `TelnetEngine` | LIVE, fully generic | Gate-blocked |
| SMB null-session | No `service_detected` | `SmbEngine` | LIVE, fully generic | Gate-blocked |
| Command injection | No `command_injection` finding in this run | `probe_cmdi_*` (3 variants) | LIVE, partial DVWA coupling | Gate-blocked (cmdi_recon requires service_detected chain) |
| Full Metasploit module execution | Any confirmed vulnerability | `MsfClient` | LIVE | Fully covered; operator-driven |

### 4B — V2 Design Inputs

#### Real V2 Template Candidates (reusable, contract-compatible)

1. **`probe_sqli_auth_bypass` core logic** — the boolean tautology payload loop and bypass detection are generic. Strip out `_JUICE_SHOP_POST_EXPLOIT_ENDPOINTS`, `umail` regex, and the bookmarklet. Replace with a configurable post-exploit capture spec. This is the strongest V2 template candidate.

2. **`probe_brute_force_login`** — CSRF token handling per request is implemented and solid. Only fix needed: replace `_PRIORITY_CREDS = [("wiener", "peter")]` with operator-configurable priority list. The SecLists wordlist fallback is generic.

3. **`probe_xss_reflected` / `probe_cmdi_*`** — technique logic is genuinely generic. DVWA fallback in cmdi probes is the main coupling. Strip `authenticate_dvwa()` fallback; require operator-supplied auth state instead.

4. **`SshEngine`, `SmbEngine`, `TelnetEngine`** — fully generic and production-quality (paramiko, impacket). Can be activated for internal targets by toggling gates. No changes needed for V2.

5. **`MsfClient` + RECIPES + WORDLISTS** — the Metasploit stack is the universal exploit template in an indirect sense: operator selects a module, sets options, runs it. V2 could expose a structured "suggest Metasploit module" path based on validated finding type → recipe lookup in `msf_recipes.py`. The `RECIPES` dict already has the recon→exploit progression for 9 service classes.

6. **`exploitation_paths/taxonomy.py`** (14 attack class IDs) — clean, extensible. V2 should add any new technique classes here before wiring them.

#### Code That Is Bloat / Not Worth Carrying Forward

1. **`authenticate_dvwa()` in `probe/lab_auth.py`** — hardcodes DVWA paths + `admin/password`. Host gate removed in Phase 60 (now attempts on every target, which is wasteful and wrong). V2 should use operator-supplied auth state from `_API_AUTH_STORE`. `lab_auth.py` should be classified DORMANT or removed in Legacy Workspace Deprecation Sprint.

2. **`probe_purchase_flow` / `purchase_flow.py`** — Juice Shop + PortSwigger lab-shaped endpoint patterns, cart/checkout path templates, and success keywords do not generalize. The underlying BFLA technique (PATCH price → cart → checkout) is valid; the implementation is lab-specific. Not a V2 template candidate as-is.

3. **`_JUICE_SHOP_POST_EXPLOIT_ENDPOINTS`** in `probe_sqli_auth_bypass` — specific to Juice Shop API paths; the bookmarklet uses `localStorage.token` (Juice Shop convention). Removable without affecting bypass detection.

4. **`_PRIORITY_CREDS = [("wiener", "peter")]`** — PortSwigger Burp Academy test account. Must be operator-configurable for V2; should not be hardcoded.

5. **Several ghost-node dead ends in `next_actions.py`** — entries with no registered `SuggestionSpec` render as clickable nodes that return 404. These should either get a spec wired or be removed from the ghost-node catalog.

#### Technique Classes With No Coverage

1. **Subdomain takeover** — wildcard-dns-detect finding is `pending` (no rule) and has no downstream exploitation path. Not a V2 priority but the gap exists.
2. **Static secret extraction** — secrets-patterns-pii finding is `pending` with no exploitation path. V2 may want a rule to classify this finding and a spec to guide extraction.
3. **Stored XSS** — `xss_stored_persistence_check` and `xss_stored_context_probe` are ghost nodes in `next_actions.py` with no backing spec. Reflected XSS is covered; stored is not.
4. **CSRF exploitation** — `csrf_token_check` and `csrf_samesite_cookie_check` are ghost nodes. No exploitation probe for CSRF.

#### Where the Dormant Subsystems Stand

**`suggestions/` — Activate and extend** (it already IS activated). This is the live execution path for all exploitation cards. The DORMANT_V2 label in the directory is misleading — these probes run in production. V2 exploit templates should be added here as new `SuggestionSpec` entries in `catalog.py` + new async generators in `probes.py`, following the existing pattern.

**`guided_actions/` (ACTIVE-LEGACY) — Partial reuse, low priority.** The three guided action groups (SQLI, AUTH, XSS) are live but have no UI surface in the operator-facing workspace. They implement the same technique classes as the automated suggestion probes but require manual operator execution. For V2, the automated probe path in `suggestions/` supersedes these for any technique that can be automated. The guided actions may be useful as a fallback for techniques that cannot be automated (e.g., where operator judgment is required). Not a V2 blocking dependency.

#### Seams V2 Will Need

1. **Exploitation phase write path** — `suggestions/` probes do not write to validation.db. V2 needs a persistence seam: exploitation results must be written somewhere durable (validation.db `exploitation_results` table or similar). Currently, a process restart loses all exploitation history.

2. **Auth state handoff (Conductor → suggestions)** — Two separate `_API_AUTH_STORE` objects exist: one in `suggestions/probes.py:54` (investigation_workspace layer), one owned by `SessionOrchestrator` in the Conductor layer. They are not connected. V2 session inheritance ("session inheritance from `_API_AUTH_STORE` non-negotiable" per CLAUDE.md) requires a seam that lets the suggestions probes read the Conductor's session store. This is the most critical seam gap.

3. **Exploitation phase trigger** — `PhaseOrchestrator` has an `EXPLOITATION` phase in `_PHASE_SEQUENCE` but it is not wired. V2 needs to wire this so the Conductor can dispatch exploitation engines after FilterOrchestrator produces validated findings.

4. **Re-invocation into exploitation** — existing re-invocation rules (PR I pattern) dispatch enumeration engines. V2 will need analogous rules to dispatch exploitation engines for validated findings, following the same `REINVOCATION_RULES` + `engine_invocation_emitter` pattern.

---

## Part 5 — Risk Flags

### Contradictions with V2 Design Direction

1. **Auth store split** — CLAUDE.md states "Session inheritance from `_API_AUTH_STORE` non-negotiable." The `_API_AUTH_STORE` in `suggestions/probes.py:54` and the one in `SessionOrchestrator` are separate. V2 cannot inherit session state without bridging these. This is not just a seam — it is a semantic conflict about which auth store is canonical.

2. **Suggestions bypass the Conductor pipeline** — The existing exploitation layer (suggestions/) runs outside Conductor/FilterOrchestrator. V2's stated architecture is three-level orchestration (Conductor L3 → orchestrators L2 → engines L1). If V2 exploit templates run through `suggestions/`, they continue to bypass this architecture. If they run through the Conductor (as a new ExploitationEngine), they need the full seam set above. The design must pick a lane.

3. **No `exploitable` flag in schema** — The DB has no exploitable boolean. FilterOrchestrator produces `validated` status. If V2 needs to distinguish "validated as a finding" from "confirmed exploitable post-execution," that requires a schema addition to normalized_findings or a separate exploitation_results table.

### Hidden Couplings V2 Will Trip On

1. **`authenticate_dvwa()` fires on every target** — Phase 60 removed the host gate. Every cmdi probe call will attempt DVWA auth first. For non-DVWA targets it fails silently (ok=False), but it adds unnecessary HTTP requests. If V2 adds many cmdi exploitation paths, this silent overhead scales badly.

2. **`_JUICE_SHOP_POST_EXPLOIT_ENDPOINTS` in the SQL bypass** — if V2 reuses `probe_sqli_auth_bypass` without stripping these, post-exploit capture will hit Juice Shop API paths on every target. On non-Juice-Shop targets these 404 silently; the probe still reports `confirmed=True` from the bypass step. Operator sees confirmed; post-exploit artifacts are empty or misleading.

3. **`next_actions.py` / `catalog.py` sync gap** — ghost nodes appear for unregistered action kinds. Adding a V2 template to `next_actions.py` without a matching `catalog.py` entry produces a clickable node that 404s. There is no startup validation that checks this sync, unlike the gate registry which fails closed on unknown gate_id.

4. **Legacy evidence shape in 9 probes** — ResultEvent calls using pre-Phase-54 shape render as "Legacy evidence." If V2 builds on these probes without migrating to the structured payload, operator UI will show degraded cards for those technique classes.

### Known Bug Pattern Matches

- **Silent auth-store split** matches Pattern 4 (FilterOrchestrator DB writer target bug: closure captures wrong state). The same issue — a singleton that looks global but is actually scoped — is live in the auth store.
- **Ghost-node dead ends with no startup validation** matches Pattern 5 (default values silently disable behavior). The `next_actions.py`→`catalog.py` sync gap silently produces dead UI elements; there is no fail-closed check equivalent to the gate registry's startup validation.
- Neither of these is exactly a new pattern, but the auth-store split is worth noting as a seam candidate for `tests/conductor/_patterns/` if V2 introduces the handoff seam.

---

## Summary

**Most important finding:** The exploitation layer (`suggestions/`) is already live and functional end-to-end, but it runs entirely outside the Conductor architecture. V2 must make an explicit architectural choice: either promote exploitation into the Conductor pipeline (with new seams and a wired exploitation phase), or formalize `suggestions/` as a legitimate second execution path with its own persistence and session-inheritance model. The current split — where Conductor handles recon/enumeration and `suggestions/` handles exploitation, with no handoff between them — is the biggest design risk V2 faces.

**V2 template candidates ready to extend:** `probe_sqli_auth_bypass` (strip lab coupling), `probe_brute_force_login` (operator-configurable creds), `probe_xss_reflected` (no changes needed), `MsfClient` (wire finding_type → recipe suggestion), `probe_cmdi_*` (strip DVWA auth fallback).

**Blockers encountered:**
- Investigation ID mismatch between validation.db and orchestration.db — root cause unknown; no engine-level execution data available in orchestration.db.
- Three `vulnerability_assessed` findings are `pending` indefinitely; no rule covers `wildcard-dns-detect` or `secrets-patterns-pii` templates. Not a V2 blocker but a FilterOrchestrator gap.

**New bug pattern candidates:**
- `next_actions.py`/`catalog.py` sync gap (ghost nodes that 404) — consider adding startup validation equivalent to gate registry's unknown-gate_id check. Not yet in the seam catalog; if V2 ships the exploitation-phase seam, this should be Pattern 9.
- Auth store split (two disconnected `_API_AUTH_STORE` singletons) — if V2 introduces the session-inheritance seam, add a seam test analogous to the DB-writer target bug test (Pattern 4) to catch closure-captures-wrong-store.
